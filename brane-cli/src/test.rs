//  TEST.rs
//    by Lut99
// 
//  Created:
//    21 Sep 2022, 16:23:37
//  Last edited:
//    01 Mar 2023, 11:23:04
//  Auto updated?
//    Yes
// 
//  Description:
//!   Contains functions for testing package functions.
// 

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use console::{style, Term};
use dialoguer::theme::ColorfulTheme;
use dialoguer::Confirm;
use dialoguer::{Input as Prompt, Select};

use brane_ast::{DataType, ParserOptions};
use brane_ast::spec::BuiltinClasses;
use brane_ast::ast::{ClassDef, VarDef};
use brane_exe::FullValue;
use specifications::common::Function;
use specifications::data::DataIndex;
use specifications::package::PackageInfo;
use specifications::version::Version;

use crate::errors::TestError;
use crate::utils::{ensure_datasets_dir, ensure_package_dir};
use crate::run::{initialize_offline_vm, run_offline_vm, OfflineVmState};


/***** CUSTOM TYPES *****/
type Map<T> = std::collections::HashMap<String, T>;





/***** HELPER FUNCTIONS *****/
/// Prompts the user for input before testing the package.
/// 
/// Basically asks their shirt off their body in what function they want to execute and which values to execute it with.
/// 
/// # Arguments
/// - `name`: The name of the package (used for debugging).
/// - `version`: The version of the package (used for debugging).
/// - `function`: The list of functions that may be tested (and are thus defined in the package).
/// - `types`: The list of types defined in the package such that we may resolve them. Missing builtins will be injected.
/// 
/// # Returns
/// The name of the chosen function and a map of values for the function to run with.
/// 
/// # Errors
/// This function errors if querying the user failed. Additionally, if their package re-exports builtins, that's considered a grave grime and they will be shot too.
fn prompt_for_input(name: impl AsRef<str>, version: &Version, functions: &Map<Function>, types: HashMap<String, ClassDef>) -> Result<(String, Map<FullValue>), TestError> {
    // We get a list of functions, sorted alphabetically (but dumb)
    let mut function_list: Vec<String> = functions.keys().map(|k| k.to_string()).collect();
    function_list.sort();

    // Insert missing builtins in the map
    let mut types: HashMap<String, ClassDef> = types;
    for builtin in &[ BuiltinClasses::Data ] {
        if let Some(old) = types.insert(builtin.name().into(), ClassDef{
            name    : builtin.name().into(),
            package : None,
            version : None,

            props   : builtin.props().into_iter().map(|p| p.into()).collect(),
            // We don't care for methods anyway
            methods : vec![],
        }) {
            return Err(TestError::PackageDefinesBuiltin{ name: name.as_ref().into(), version: *version, duplicate: old.name });
        }
    }

    // Query the user about which of the functions they'd like
    let index = match Select::with_theme(&ColorfulTheme::default())
        .with_prompt("The function the execute")
        .default(0)
        .items(&function_list[..])
        .interact()
    {
        Ok(index) => index,
        Err(err)  => { return Err(TestError::FunctionQueryError { err }); }
    };
    let function_name = &function_list[index];
    let function = &functions[function_name];

    // Now, with the chosen function, we will collect all of the function's arguments
    let mut args: Map<FullValue> = Map::new();
    if !function.parameters.is_empty() {
        println!("\nPlease provide input for the chosen function:\n");
        for p in &function.parameters {
            // Prompt for that data type
            let value: FullValue = prompt_for_param(format!("{} [{}]", p.name, p.data_type), &p.name, DataType::from(&p.data_type), p.optional.unwrap_or(false), None, &types)?;
            args.insert(p.name.clone(), value);
        }
    }
    debug!("Arguments: {:#?}", args);

    // Print a newline after all the prompts, and then we return
    println!();
    Ok((function_name.clone(), args))
}

/// Prompts the user to enter the value for a single function argument.
/// 
/// # Arguments
/// - `what`: The prompt to present the user with.
/// - `name`: The name of the parameter to query for.
/// - `data_type`: The DataType to query for.
/// - `optional`: Whether this parameter is optional or not.
/// - `default`: If any, the default value to provide the user with.
/// - `types`: The list of ClassDefs that we use to resolve custom typenames.
/// 
/// # Returns
/// The queried-for value.
/// 
/// # Errors
/// This function errors if querying the user failed.
fn prompt_for_param(what: impl AsRef<str>, name: impl AsRef<str>, data_type: DataType, optional: bool, default: Option<FullValue>, types: &HashMap<String, ClassDef>) -> Result<FullValue, TestError> {
    let what: &str = what.as_ref();
    let name: &str = name.as_ref();

    // Switch on the expected type to determine which questions to ask
    use DataType::*;
    let value: FullValue = match data_type {
        Boolean => {
            // Fetch the default value as a bool
            let default: Option<bool> = default.map(|d| d.bool());
            // The prompt is what we need
            FullValue::Boolean(prompt(what, optional, default)?)
        },
        Integer => {
            // Fetch the default value as an int
            let default: Option<i64> = default.map(|d| d.int());
            // The prompt is what we need
            FullValue::Integer(prompt(what, optional, default)?)
        },
        Real => {
            // Fetch the default value as a real
            let default: Option<f64> = default.map(|d| d.real());
            // The prompt is what we need
            FullValue::Real(prompt(what, optional, default)?)
        },
        String => {
            // Fetch the default value as a string
            let default: Option<std::string::String> = default.map(|d| d.string());
            // The prompt is what we need
            FullValue::String(prompt(what, optional, default)?)
        },

        Array{ elem_type } => {
            // If there is a default, we are forced to ask it beforehand.
            if let Some(default) = default {
                // Ensure the default has the correct value
                if default.data_type() != (DataType::Array{ elem_type: elem_type.clone() }) { panic!("{} cannot have a value of type {} as default value", DataType::Array{ elem_type }, default.data_type()); }

                // Prompt the user to use it
                if match Confirm::new()
                    .with_prompt(format!("{} has a default value: {}; would you like to use that?", style(name).bold().cyan(), style(format!("{default}")).bold()))
                    .interact() {
                    Ok(use_default) => use_default,
                    Err(err)        => { return Err(TestError::YesNoQueryError{ err }); },
                } {
                    return Ok(default);
                }
            }

            // Add as many elements as the user likes
            let mut values: Vec<FullValue> = Vec::with_capacity(16);
            loop {
                // Query the user
                let res = prompt_for_param(format!("{} [{}] <element {}>", name, elem_type, values.len()), name, *elem_type.clone(), false, None, types)?;
                values.push(res);

                // Ask if they want to ask more
                if !match Confirm::new()
                    .with_prompt("Add more elements?")
                    .interact() {
                    Ok(cont) => cont,
                    Err(err) => { return Err(TestError::YesNoQueryError{ err }); },
                } {
                    break;
                }
            }

            // Done
            FullValue::Array(values)
        },
        Class{ name: c_name } => {
            // If there is a default, we are forced to ask it beforehand.
            if let Some(default) = default {
                // Ensure the default has the correct value
                if default.data_type() != (DataType::Class{ name: c_name.clone() }) { panic!("{} cannot have a value of type {} as default value", DataType::Class{ name: c_name }, default.data_type()); }

                // Prompt the user to use it
                if match Confirm::new()
                    .with_prompt(format!("{} has a default value: {}; would you like to use that?", style(name).bold().cyan(), style(format!("{default}")).bold()))
                    .interact() {
                    Ok(use_default) => use_default,
                    Err(err)        => { return Err(TestError::YesNoQueryError{ err }); },
                } {
                    return Ok(default);
                }
            }

            // Resolve the class
            let def: &ClassDef = match types.get(&c_name) {
                Some(def) => def,
                None      => {  return Err(TestError::UndefinedClass{ name: c_name }); },
            };

            // Sort the properties of said class alphabetically
            let mut props: Vec<&VarDef> = def.props.iter().collect();
            props.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

            // Query for them in-order
            let mut values: HashMap<std::string::String, FullValue> = HashMap::with_capacity(props.len());
            for p in props {
                let res = prompt_for_param(format!("{} [{}] <field {}::{}>", name, p.data_type, c_name, p.name), name, p.data_type.clone(), false, None, types)?;
                values.insert(p.name.clone(), res);
            }

            // Done
            FullValue::Instance(c_name, values)
        },
        Data | IntermediateResult => {
            // Get the directory with the datasets
            let datasets_dir = match ensure_datasets_dir(false) {
                Ok(dir)  => dir,
                Err(err) => { return Err(TestError::DatasetsDirError{ err }); }
            };

            // Collect the local data index
            let dindex: DataIndex = match brane_tsk::local::get_data_index(datasets_dir) {
                Ok(dindex) => dindex,
                Err(err)   => { return Err(TestError::DataIndexError { err }); },
            };
            let mut items: Vec<std::string::String> = dindex.into_iter().map(|info| info.name).collect();
            items.sort();

            // Prepare the prompt with beautiful themes and such
            let colorful = ColorfulTheme::default();
            let mut prompt = Select::with_theme(&colorful);
            prompt
                .items(&items)
                .with_prompt(what)
                .default(0usize);

            // Done
            let res: std::string::String = match prompt.interact_on_opt(&Term::stderr()) {
                Ok(res)  => res.map(|i| items[i].clone()).unwrap_or_else(|| items[0].clone()),
                Err(err) => { return Err(TestError::ValueQueryError{ res_type: std::any::type_name::<std::string::String>(), err }); },
            };

            // The prompt is what we need
            FullValue::Data(res.into())
        },

        Void => FullValue::Void,

        // The rest we don't do
        _ => { panic!("Cannot query values for parameter '{}' of type {}", name, data_type); }
    };

    // Done
    Ok(value)
}

/// Prompts the user for a value of the given type.
/// 
/// # Generic arguments
/// - `T`: The general type to query for.
/// 
/// # Arguments
/// - `what`: The prompt to present the user with.
/// - `optional`: Whether this parameter is optional or not.
/// - `default`: If any, the default value to provide the user with.
/// 
/// # Returns
/// The queried-for result.
/// 
/// # Errors
/// This function errors if we could not query for the given prompt.
fn prompt<T>(what: impl AsRef<str>, optional: bool, default: Option<T>) -> Result<T, TestError>
where
    T: Clone + FromStr + Display,
    T::Err: Display + Debug,
{
    // Prepare the prompt with beautiful themes and such
    let colorful = ColorfulTheme::default();
    let mut prompt = Prompt::with_theme(&colorful);
    prompt
        .with_prompt(what.as_ref())
        .allow_empty(optional);

    // Also add a default if that's given
    if let Some(default) = default {
        prompt.default(default);
    }

    // Alright hit it
    match prompt.interact() {
        Ok(res)  => Ok(res),
        Err(err) => Err(TestError::ValueQueryError{ res_type: std::any::type_name::<T>(), err }),
    }
}



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

        FullValue::Boolean(value) => if value { "true".into() } else { "false".into() },
        FullValue::Integer(value) => format!("{value}"),
        FullValue::Real(value)    => format!("{value}"),
        FullValue::String(value)  => format!("\"{}\"", value.replace('\\', "\\\\").replace('\"', "\\\"")),

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
/// 
/// # Returns
/// Nothing, but does do a whole dance of querying the user and executing a package based on that.
/// 
/// # Errors
/// This function errors if any part of that dance failed.
pub async fn handle(name: impl Into<String>, version: Version, show_result: Option<PathBuf>) -> Result<(), TestError> {
    let name: String = name.into();

    // Read the package info of the given package
    let package_dir = match ensure_package_dir(&name, Some(&version), false) {
        Ok(dir)  => dir,
        Err(err) => { return Err(TestError::PackageDirError{ name, version, err }); }
    };
    let package_info = match PackageInfo::from_path(package_dir.join("package.yml")) {
        Ok(info) => info,
        Err(err) => { return Err(TestError::PackageInfoError{ name, version, err }); }
    };

    // Run the test for this info
    let output: FullValue = test_generic(package_info, show_result).await?;

    // Print it, done
    println!("Result: {} [{}]", style(format!("{output}")).bold().cyan(), style(format!("{}", output.data_type())).bold());
    Ok(())
}



/// Tests the package in the given PackageInfo.
/// 
/// # Arguments
/// - `info`: The PackageInfo that describes the package to test.
/// - `show_result`: Whether or not to `cat` the resulting file if any.
/// 
/// # Returns
/// The value of the chosen function in that package (which may be Void this time).
pub async fn test_generic(info: PackageInfo, show_result: Option<PathBuf>) -> Result<FullValue, TestError> {
    // Query the user what they'd like to do (we quickly convert the common Type to a ClassDef)
    let (function, mut args) = prompt_for_input(&info.name, &info.version, &info.functions, info.types.iter().map(|(n, t)| (n.clone(), ClassDef {
        name    : t.name.clone(),
        package : Some(info.name.clone()),
        version : Some(info.version),

        props   : t.properties.iter().map(|p| VarDef {
            name      : p.name.clone(),
            data_type : DataType::from(&p.data_type),
        }).collect(),
        methods : vec![],
    })).collect())?;

    // Build a phony workflow with that
    let workflow: String = format!("import {}[{}]; return {}({});",
        info.name, info.version,
        function,
        // We iterate over the function arguments to resolve them in the args
        info.functions.get(&function).unwrap().parameters.iter().map(|p| {
            write_value(args.remove(&p.name).unwrap())
        }).collect::<Vec<String>>().join(", "),
    );

    // We run it by spinning up an offline VM
    let mut state: OfflineVmState = match initialize_offline_vm(ParserOptions::bscript()) {
        Ok(state) => state,
        Err(err)  => { return Err(TestError::InitializeError{ err }); },
    };
    let result: FullValue = match run_offline_vm(&mut state, "<test task>", workflow).await {
        Ok(result) => result,
        Err(err)   => { return Err(TestError::RunError{ err }); },
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
                Err(err)     => { return Err(TestError::IntermediateResultFileReadError{ path, err }); },
            };
            if !contents.is_empty() { println!("{contents}"); }
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!();
        }
    }

    // Return the result
    Ok(result)
}
