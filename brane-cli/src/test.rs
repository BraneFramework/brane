//  TEST.rs
//    by Lut99
//
//  Created:
//    21 Sep 2022, 16:23:37
//  Last edited:
//    25 May 2023, 20:12:59
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains functions for testing package functions.
//

use std::fs;
use std::path::PathBuf;

use brane_ast::ast::Snippet;
use brane_ast::{ParserOptions, Workflow};
use brane_exe::FullValue;
use brane_tsk::docker::DockerOptions;
use brane_tsk::input::prompt_for_input;
use console::style;
use specifications::data::DataIndex;
use specifications::package::PackageInfo;
use specifications::version::Version;

use crate::errors::TestError;
use crate::run::{self, OfflineVmState, initialize_offline_vm, run_offline_vm};
use crate::utils::{ensure_datasets_dir, ensure_package_dir};


/***** HELPER FUNCTIONS *****/
/// Writes the given FullValue to a string in such a way that it's valid BraneScript.
///
/// # Arguments
/// - `value`: The FullValue to write.
///
/// # Returns
/// The string that may be written to, say, phony workflow files.
fn write_value(value: FullValue) -> String {
    match value {
        FullValue::Array(values) => {
            // Write them all in an array
            format!("[ {} ]", values.into_iter().map(write_value).collect::<Vec<String>>().join(", "))
        },
        FullValue::Instance(name, props) => {
            // Write them all in an instance expression
            format!("new {}{{ {} }}", name, props.into_iter().map(|(n, v)| format!("{n} := {v}")).collect::<Vec<String>>().join(", "))
        },
        FullValue::Data(name) => {
            // Write it as a new Data declaration
            format!("new Data{{ name := \"{name}\" }}")
        },
        FullValue::IntermediateResult(name) => {
            // Also write it as a new Data declaration
            format!("new Data{{ name := \"{name}\" }}")
        },

        FullValue::Boolean(value) => {
            if value {
                "true".into()
            } else {
                "false".into()
            }
        },
        FullValue::Integer(value) => format!("{value}"),
        FullValue::Real(value) => format!("{value}"),
        FullValue::String(value) => format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\"")),

        FullValue::Void => String::new(),
    }
}





/***** LIBRARY *****/
/// Handles the `brane test`-command.
///
/// # Arguments
/// - `name`: The name of the package to test.
/// - `version`: The version of the package to test.
/// - `show_result`: Whether or not to `cat` the resulting file if any.
/// - `docker_opts`: The options we use to connect to the local Docker daemon.
/// - `keep_containers`: Whether to keep containers after execution or not.
///
/// # Returns
/// Nothing, but does do a whole dance of querying the user and executing a package based on that.
///
/// # Errors
/// This function errors if any part of that dance failed.
pub async fn handle(
    name: impl Into<String>,
    version: Version,
    show_result: Option<PathBuf>,
    docker_opts: DockerOptions,
    keep_containers: bool,
) -> Result<(), TestError> {
    let name: String = name.into();

    // Read the package info of the given package
    let package_dir = match ensure_package_dir(&name, Some(&version), false) {
        Ok(dir) => dir,
        Err(err) => {
            return Err(TestError::PackageDirError { name, version, err });
        },
    };
    let package_info = match PackageInfo::from_path(package_dir.join("package.yml")) {
        Ok(info) => info,
        Err(err) => {
            return Err(TestError::PackageInfoError { name, version, err });
        },
    };

    // Run the test for this info
    let output: FullValue = test_generic(package_info, show_result, docker_opts, keep_containers).await?;

    // Print it, done
    println!("Result: {} [{}]", style(format!("{output}")).bold().cyan(), style(format!("{}", output.data_type())).bold());
    Ok(())
}



/// Tests the package in the given PackageInfo.
///
/// # Arguments
/// - `info`: The PackageInfo that describes the package to test.
/// - `show_result`: Whether or not to `cat` the resulting file if any.
/// - `docker_opts`: The options we use to connect to the local Docker daemon.
/// - `keep_containers`: Whether to keep containers after execution or not.
///
/// # Returns
/// The value of the chosen function in that package (which may be Void this time).
pub async fn test_generic(
    info: PackageInfo,
    show_result: Option<PathBuf>,
    docker_opts: DockerOptions,
    keep_containers: bool,
) -> Result<FullValue, TestError> {
    // Get the local datasets directory
    let datasets_dir: PathBuf = match ensure_datasets_dir(true) {
        Ok(dir) => dir,
        Err(err) => {
            return Err(TestError::DatasetsDirError { err });
        },
    };

    // Collect the local data index
    let data_index: DataIndex = match brane_tsk::local::get_data_index(datasets_dir) {
        Ok(index) => index,
        Err(err) => {
            return Err(TestError::DataIndexError { err });
        },
    };

    // Query the user what they'd like to do (we quickly convert the common Type to a ClassDef)
    let (function, mut args) = match prompt_for_input(&data_index, &info) {
        Ok(res) => res,
        Err(err) => {
            return Err(TestError::InputError { err });
        },
    };

    // Build a phony workflow with that
    let workflow_content: String = format!(
        "import {}[{}]; return {}({});",
        info.name,
        info.version,
        function,
        // We iterate over the function arguments to resolve them in the args
        info.functions
            .get(&function)
            .unwrap()
            .parameters
            .iter()
            .map(|p| { write_value(args.remove(&p.name).unwrap()) })
            .collect::<Vec<String>>()
            .join(", "),
    );

    // We run it by spinning up an offline VM
    let mut state: OfflineVmState = match initialize_offline_vm(ParserOptions::bscript(), docker_opts, keep_containers) {
        Ok(state) => state,
        Err(err) => {
            return Err(TestError::InitializeError { err });
        },
    };

    // Compile the workflow
    let workflow = Workflow::from_source(
        &mut state.state,
        &mut state.source,
        &state.pindex,
        &state.dindex,
        None,
        &state.options,
        "<test task>",
        workflow_content.clone(),
    )
    .map_err(|err| TestError::RunError { err: run::Error::CompileError(err) })?;

    let snippet = Snippet { lines: workflow_content.lines().count(), snippet: workflow };

    let result: FullValue = match run_offline_vm(&mut state, snippet).await {
        Ok(result) => result,
        Err(err) => {
            return Err(TestError::RunError { err });
        },
    };

    // Write the intermediate result if told to do so
    if let Some(file) = show_result {
        if let FullValue::IntermediateResult(name) = &result {
            let name: String = name.into();

            // Write the result
            println!();
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("Contents of intermediate result '{name}':");
            let path: PathBuf = state.results_dir.path().join(name).join(file);
            let contents: String = match fs::read_to_string(&path) {
                Ok(contents) => contents,
                Err(err) => {
                    return Err(TestError::IntermediateResultFileReadError { path, err });
                },
            };
            if !contents.is_empty() {
                println!("{contents}");
            }
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!();
        }
    }

    // Return the result
    Ok(result)
}
