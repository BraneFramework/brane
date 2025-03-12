//  MAIN.rs
//    by Lut99
//
//  Created:
//    20 Sep 2022, 13:53:43
//  Last edited:
//    02 Oct 2023, 17:13:16
//  Auto updated?
//    Yes
//
//  Description:
//!   Entrypoint to the in-container delegate executable that organises
//!   things around there.
//

use std::path::PathBuf;
use std::process;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use brane_let::common::PackageResult;
use brane_let::errors::LetError;
use brane_let::{exec_ecu, exec_nop};
use clap::Parser;
use dotenvy::dotenv;
use log::{LevelFilter, debug, warn};
use serde::de::DeserializeOwned;


/***** CONSTANTS *****/
/// Defines the name of the output prefix environment variable.
const OUTPUT_PREFIX_NAME: &str = "ENABLE_STDOUT_PREFIX";
/// The thing we prefix to the output stdout so the Kubernetes engine can recognize valid output when it sees it.
const OUTPUT_PREFIX: &str = "[OUTPUT] ";





/***** ARGUMENTS *****/
#[derive(Parser)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Opts {
    #[clap(short, long, env = "BRANE_APPLICATION_ID")]
    application_id: String,
    #[clap(short, long, env = "BRANE_LOCATION_ID")]
    location_id: String,
    #[clap(short, long, env = "BRANE_JOB_ID")]
    job_id: String,
    #[clap(short, long, env = "BRANE_CALLBACK_TO")]
    callback_to: Option<String>,
    #[clap(short, long, env = "BRANE_PROXY_ADDRESS")]
    proxy_address: Option<String>,
    #[clap(short, long, env = "BRANE_MOUNT_DFS")]
    mount_dfs: Option<String>,
    /// Prints debug info
    #[clap(short, long, action, env = "DEBUG")]
    debug: bool,
    #[clap(subcommand)]
    sub_command: SubCommand,
}

#[derive(Parser, Clone)]
enum SubCommand {
    /// Execute arbitrary source code and return output
    #[clap(name = "ecu")]
    Code {
        /// Function to execute
        function:    String,
        /// Input arguments (encoded, as Base64'ed JSON)
        arguments:   String,
        #[clap(short, long, env = "BRANE_WORKDIR", default_value = "/opt/wd")]
        working_dir: PathBuf,
    },
    /// Don't perform any operation and return nothing
    #[clap(name = "no-op")]
    NoOp,
}





/***** ENTRYPOINT *****/
#[tokio::main]
async fn main() {
    // Parse the arguments
    dotenv().ok();
    let Opts { proxy_address, debug, sub_command, .. } = Opts::parse();

    // Configure logger.
    let mut logger = env_logger::builder();
    logger.format_module_path(false);
    if debug {
        logger.filter_level(LevelFilter::Debug).init();
    } else {
        logger.filter_level(LevelFilter::Info).init();
    }
    debug!("BRANELET v{}", env!("CARGO_PKG_VERSION"));
    debug!("Initializing...");

    // // Mount DFS via JuiceFS.
    // if let Some(ref mount_dfs) = opts.mount_dfs {
    //     debug!("Initializing JuiceFS...");
    //     // Try to run the command
    //     let mut command = Command::new("/juicefs");
    //     command.args(vec!["mount", "-d", mount_dfs, "/data"]);
    //     command.stdout(Stdio::piped());
    //     command.stderr(Stdio::piped());
    //     debug!(" > Running '{:?}'", &command);
    //     let output = match command.output() {
    //         Ok(output) => output,
    //         Err(err)   => { log::error!("{}", LetError::JuiceFSLaunchError{ command: format!("{:?}", command), err }); std::process::exit(-1); }
    //     };

    //     // Make sure we completed OK
    //     debug!(" > Return status: {}", output.status);
    //     if !output.status.success() {
    //         log::error!("{}", LetError::JuiceFSError{ command: format!("{:?}", command), code: output.status.code().unwrap_or(-1), stdout: String::from_utf8_lossy(&output.stdout).to_string(), stderr: String::from_utf8_lossy(&output.stderr).to_string() });
    //         std::process::exit(-1);
    //     }
    // }

    // Start redirector in the background, if proxy address is set.
    if proxy_address.is_some() {
        warn!("Proxy is not implemented anymore");
    }

    // // Callbacks may be called at any time of the execution.
    // debug!("Initializing callback...");
    // let callback: Option<Callback> = match callback_to {
    //     Some(callback_to) => match Callback::new(application_id, location_id, job_id, callback_to).await {
    //         Ok(callback) => Some(callback),
    //         Err(err)     => { log::error!("Could not setup callback connection: {}", err); std::process::exit(-1); }
    //     },
    //     None => None,
    // };

    // Wrap actual execution, so we can always log errors.
    match run(sub_command).await {
        Ok(code) => process::exit(code),
        Err(err) => {
            log::error!("{}", err);
            process::exit(-1);
        },
    }
}

/// **Edited: instantiating callback earlier, updated callback policy (new callback interface + new events). Also returning LetErrors.**
///
/// Runs the job that this branelet is in charge of.
///
/// **Arguments**
///  * `sub_command`: The subcommand to execute (is it code, oas or nop?)
///  * `callback`: The Callback future that asynchronously constructs a Callback instance.
///
/// **Returns**  
/// The exit code of the nested application on success, or a LetError otherwise.
async fn run(
    sub_command: SubCommand,
    // callback: Option<Callback>,
) -> Result<i32, LetError> {
    // // We've initialized!
    // if let Some(ref mut callback) = callback {
    //     if let Err(err) = callback.ready().await { log::error!("Could not update driver on Ready: {}", err); }
    // }

    // Switch on the sub_command to do the actual work
    let output = match sub_command {
        SubCommand::Code { function, arguments, working_dir } => exec_ecu::handle(function, decode_b64(arguments)?, working_dir).await,
        SubCommand::NoOp => exec_nop::handle().await,
    };

    // Perform final FINISHED callback.
    match output {
        Ok(PackageResult::Finished { result }) => {
            // Convert the output to a string
            let output: String = match serde_json::to_string(&result) {
                Ok(output) => output,
                Err(err) => {
                    let err = LetError::ResultJSONError { value: format!("{result:?}"), err };
                    // if let Some(ref mut callback) = callback {
                    //     if let Err(err) = callback.decode_failed(format!("{}", err)).await { log::error!("Could not update driver on DecodeFailed: {}", err); }
                    // }
                    return Err(err);
                },
            };

            // If that went successfull, output the result in some way
            // if let Some(ref mut callback) = callback {
            //     // Use the callback to report it
            //     if let Err(err) = callback.finished(output).await { log::error!("Could not update driver on Finished: {}", err); }
            // } else {
            // Print to stdout as (base64-encoded) JSON
            if std::env::vars().any(|(name, value)| name == OUTPUT_PREFIX_NAME && value == "1") {
                debug!("Writing output prefix enabled");
                println!("{}{}", OUTPUT_PREFIX, BASE64_STANDARD.encode(output));
            } else {
                println!("{}", BASE64_STANDARD.encode(output));
            }
            // }

            Ok(0)
        },

        Ok(PackageResult::Failed { code, stdout, stderr }) => {
            // Back it up to the user
            // if let Some(ref mut callback) = callback {
            //     // Use the callback to report it
            //     if let Err(err) = callback.failed(code, stdout, stderr).await { log::error!("Could not update driver on Failed: {}", err); }
            // } else {
            // Gnerate the line divider
            let lines = (0..80).map(|_| '-').collect::<String>();
            // Print to stderr
            log::error!(
                "Internal package call return non-zero exit code {}\n\nstdout:\n{}\n{}\n{}\n\nstderr:\n{}\n{}\n{}\n\n",
                code,
                &lines,
                stdout,
                &lines,
                &lines,
                stderr,
                &lines
            );
            // }

            Ok(code)
        },

        Ok(PackageResult::Stopped { signal }) => {
            // Back it up to the user
            // if let Some(ref mut callback) = callback {
            //     // Use the callback to report it
            //     if let Err(err) = callback.stopped(signal).await { log::error!("Could not update driver on Stopped: {}", err); }
            // } else {
            // Print to stderr
            log::error!("Internal package call was forcefully stopped with signal {}", signal);
            // }

            Ok(-1)
        },

        Err(err) => {
            // Just pass the error
            Err(err)
        },
    }
}

/// **Edited: now returning LetErrors.**
///
/// Decodes the given base64 string as JSON to the desired output type.
///
/// **Arguments**
///  * `input`: The input to decode/parse.
///
/// **Returns**  
/// The parsed data as the appropriate type, or a LetError otherwise.
fn decode_b64<T>(input: String) -> Result<T, LetError>
where
    T: DeserializeOwned,
{
    // Decode the Base64
    let input = match BASE64_STANDARD.decode(input) {
        Ok(input) => input,
        Err(err) => {
            return Err(LetError::ArgumentsBase64Error { err });
        },
    };

    // Decode the raw bytes to UTF-8
    let input = match String::from_utf8(input[..].to_vec()) {
        Ok(input) => input,
        Err(err) => {
            return Err(LetError::ArgumentsUTF8Error { err });
        },
    };

    // Decode the string to JSON
    // println!("Received input: {}", input);
    match serde_json::from_str(&input) {
        Ok(result) => Ok(result),
        Err(err) => Err(LetError::ArgumentsJSONError { err }),
    }
}
