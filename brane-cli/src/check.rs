//  CHECK.rs
//    by Lut99
//
//  Created:
//    02 Feb 2024, 11:08:20
//  Last edited:
//    08 Feb 2024, 17:18:29
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the `brane check`-subcommand, which attempts to validate
//!   a workflow against remote policy.
//

use std::io::Read;
use std::sync::Arc;
use std::{fs, io};

use brane_ast::{CompileResult, Workflow};
use brane_dsl::{Language, ParserOptions};
use console::style;
use error_trace::trace;
use specifications::data::DataIndex;
use specifications::driving::{CheckReply, CheckRequest, DriverServiceClient};
use specifications::package::PackageIndex;
use specifications::profiling::{self};
use tracing::{debug, info};

pub use crate::errors::CheckError as Error;
use crate::instance::InstanceInfo;


/***** HELPER FUNCTIONS *****/
/// Compiles the given source text for the given remote instance.
///
/// # Arguments
/// - `instance`: The [`InstanceInfo`] describing the instance for which we will compile.
/// - `input`: Some description of where the input comes from (used for debugging).
/// - `source`: The raw source text.
/// - `language`: The [`Language`] as which to parse the `source` text.
/// - `user`: An override to set the end user of the workflow result instead of hte instance one.
///
/// # Returns
/// A compiled [`Workflow`].
///
/// Note that this already printed any warnings or errors.
///
/// # Errors
/// This function errors if we failed to get remote packages/datasets, or if the input was not valid BraneScript/Bakery.
async fn compile(instance: &InstanceInfo, input: &str, source: String, language: Language, user: Option<String>) -> Result<Workflow, Error> {
    // Read the package index from the remote first
    let url: String = format!("{}/graphql", instance.api);
    debug!("Retrieving package index from '{url}'");
    let pindex: PackageIndex = brane_tsk::api::get_package_index(&url).await.map_err(|source| Error::PackageIndexRetrieve { url, source })?;

    // Next up, the data index
    let url: String = format!("{}/data/info", instance.api);
    debug!("Retrieving data index from '{url}'");
    let dindex: DataIndex = brane_tsk::api::get_data_index(&url).await.map_err(|source| Error::DataIndexRetrieve { url, source })?;

    // Hit the Brane compiler
    match brane_ast::compile_program(source.as_bytes(), &pindex, &dindex, &ParserOptions::new(language)) {
        CompileResult::Workflow(mut wf, warns) => {
            // Emit the warnings before continuing
            for warn in warns {
                warn.prettyprint(input, &source);
            }

            // Inject a user
            wf.user = Arc::new(Some(user.unwrap_or_else(|| instance.user.clone())));

            // OK
            Ok(wf)
        },
        CompileResult::Err(errs) => {
            // Print 'em
            for err in errs {
                err.prettyprint(input, &source);
            }
            Err(Error::AstCompile { input: input.into() })
        },
        CompileResult::Eof(err) => {
            err.prettyprint(input, source);
            Err(Error::AstCompile { input: input.into() })
        },

        // The rest does not occur for this variation of the function
        CompileResult::Program(_, _) | CompileResult::Unresolved(_, _) => unreachable!(),
    }
}





/***** LIBRARY *****/
/// Handles the `brane check`-subcommand, which attempts to validate a workflow against remote policy.
///
/// # Arguments
/// - `file`: The path to the file to load as input. `-` means stdin.
/// - `language`: The [`Language`] of the input file.
/// - `user`: An override for the user in the instance file, if any.
/// - `profile`: If true, show profile timings of the request if available.
///
/// # Errors
/// This function errors if we failed to perform the check.
pub async fn handle(file: String, language: Language, user: Option<String>, profile: bool) -> Result<(), Error> {
    info!("Handling 'brane check {}'", if file == "-" { "<stdin>" } else { file.as_str() });


    /***** PREPARATION *****/
    let prof: profiling::ProfileScope = profiling::ProfileScope::new("Local preparation");

    // Resolve the input file to a source string
    debug!("Loading input from '{file}'...");
    let load = prof.time("Input loading");
    let (input, source): (String, String) = if file == "-" {
        // Read from stdin
        let mut source: String = String::new();
        io::stdin().read_to_string(&mut source).map_err(|source| Error::InputStdinRead { source })?;
        ("<stdin>".into(), source)
    } else {
        // Read from a file
        match fs::read_to_string(&file) {
            Ok(source) => (file, source),
            Err(err) => return Err(Error::InputFileRead { path: file.into(), source: err }),
        }
    };
    load.stop();

    // Get the current instance
    debug!("Retrieving active instance info...");
    let instance: InstanceInfo =
        prof.time_func("Instance resolution", InstanceInfo::from_active_path).map_err(|source| Error::ActiveInstanceInfoLoad { source })?;

    // Attempt to compile the input
    debug!("Compiling source text to Brane WIR...");
    let workflow: Workflow = prof
        .time_fut("Workflow compilation", compile(&instance, &input, source, language, user))
        .await
        .map_err(|source| Error::WorkflowCompile { input: input.clone(), source: Box::new(source) })?;

    let sworkflow: String =
        prof.time_func("Workflow serialization", || serde_json::to_string(&workflow)).map_err(|source| Error::WorkflowSerialize { input, source })?;

    // Connect to the driver
    debug!("Connecting to driver '{}'...", instance.drv);
    let rem = prof.time("Driver time");
    let mut client: DriverServiceClient = DriverServiceClient::connect(instance.drv.to_string())
        .await
        .map_err(|source| Error::DriverConnect { address: instance.drv.clone(), source })?;

    // Send the request
    debug!("Sending check request to driver '{}' and awaiting response...", instance.drv);
    let res: CheckReply = match client.check(CheckRequest { workflow: sworkflow }).await {
        Ok(res) => res.into_inner(),
        Err(source) => return Err(Error::DriverCheck { address: instance.drv, source }),
    };
    rem.stop();

    // FIRST: Print profile information if available
    if profile {
        println!();
        println!("{}", (0..80).map(|_| '-').collect::<String>());
        println!("LOCAL PROFILE RESULTS:");
        println!("{}", prof.display());
        if let Some(prof) = res.profile {
            // Attempt to parse it
            match serde_json::from_str::<profiling::ProfileScope>(&prof) {
                Ok(prof) => {
                    // Print
                    println!();
                    println!("REMOTE PROFILE RESULTS:");
                    println!("{}", prof.display());
                },
                Err(err) => warn!("{}", trace!(("Failed to deserialize profile information in CheckReply"), err)),
            }
        }
        println!("{}", (0..80).map(|_| '-').collect::<String>());
        println!();

        // Drop both of them to avoid writing them again
        std::mem::forget(prof);
    }

    // Consider the verdict
    if res.verdict {
        println!("Workflow {} was {} by all domains", style(&workflow.id).bold().cyan(), style("accepted").bold().green());
    } else {
        println!("Workflow {} was {} by at least one domain", style("").bold().cyan(), style("rejected").bold().red());

        if let Some(who) = res.who {
            println!(" > Checker of domain {} rejected workflow", style(who).bold().cyan());
            if !res.reasons.is_empty() {
                println!("   Reasons for denial:");
                for reason in res.reasons {
                    println!("    - {}", style(reason).bold());
                }
            }
        }
    }
    println!();

    // Either way, the request itself was a success
    Ok(())
}
