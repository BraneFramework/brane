use crate::callback::Callback;
use anyhow::{Context, Result};
use specifications::common::{Parameter, Type, Value, Typed};
use specifications::container::{ActionCommand, ContainerInfo};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use subprocess::{Exec, Redirection};
use yaml_rust::{Yaml, YamlLoader};

type Map<T> = std::collections::HashMap<String, T>;

///
///
///
pub async fn handle(
    function: String,
    arguments: Map<Value>,
    working_dir: PathBuf,
    callback: &mut Option<&mut Callback>,
) -> Result<Value> {
    debug!("Executing '{}' (code) using arguments:\n{:#?}", function, arguments);

    let container_info = ContainerInfo::from_path(working_dir.join("container.yml"))?;
    let functions = container_info.actions;
    let function = functions
        .get(&function)
        .unwrap_or_else(|| panic!("Function '{}' not found", function));

    let function_input = function.input.clone().unwrap_or_default();
    let function_output = function.output.clone().unwrap_or_default();

    assert_input(&function_input, &arguments)?;

    // Perform initialization.
    initialize(&working_dir)?;
    if let Some(callback) = callback {
        callback.initialized(None).await?;
    }

    // Determine entrypoint and, optionally, command and arguments
    let entrypoint = &container_info.entrypoint.exec;
    let command = function.command.clone().unwrap_or_else(|| ActionCommand {
        args: Default::default(),
        capture: None,
    });

    if let Some(callback) = callback {
        callback.started(None).await?;
    }

    // Output variables are captured from the stdout
    let stdout = execute(entrypoint, &command.args, &arguments, &working_dir)?;
    let output = capture_output(stdout, &function_output, &command.capture, &container_info.types)?;

    if let Some(parameter) = function_output.first() {
        let value = output
            .get(&parameter.name)
            .with_context(|| format!("Output '{}' not found.", parameter.name))?;

        Ok(value.clone())
    } else {
        Ok(Value::Unit)
    }
}

///
///
///
fn assert_input(
    parameters: &[Parameter],
    arguments: &Map<Value>,
) -> Result<()> {
    debug!("Asserting input arguments");

    for p in parameters {
        let expected_type = p.data_type.as_str();
        if expected_type.starts_with("mount") {
            continue;
        }

        let argument = arguments.get(&p.name);
        ensure!(argument.is_some(), "Argument not provided: {}", p.name);

        let argument = argument.unwrap();
        let actual_type = argument.data_type();

        if expected_type != actual_type {
            bail!(
                "Type check for '{}' failed: '{}' is not '{}' or subtype thereof",
                p.name,
                expected_type,
                actual_type
            );
        }
    }

    Ok(())
}

///
///
///
fn initialize(working_dir: &Path) -> Result<()> {
    debug!("Initializing working directory");

    let init_sh = working_dir.join("init.sh");
    if !init_sh.exists() {
        return Ok(());
    }

    let result = Command::new(init_sh).output().expect("Couldn't execute init.sh");

    ensure!(result.status.success(), "Non-zero exit status for init.sh");

    Ok(())
}

///
///
///
fn execute(
    entrypoint: &str,
    command_args: &[String],
    arguments: &Map<Value>,
    working_dir: &Path,
) -> Result<Vec<String>> {
    let entrypoint_path = working_dir.join(entrypoint).canonicalize()?;
    let command = if entrypoint_path.is_file() {
        Exec::cmd(entrypoint_path)
    } else {
        let segments = entrypoint.split_whitespace().collect::<Vec<&str>>();
        let entrypoint_path = working_dir.join(&segments[0]).canonicalize()?;

        Exec::cmd(entrypoint_path).args(&segments[1..])
    };

    let envs = construct_envs(arguments)?;
    debug!("Using environment variables:\n{:#?}", envs);
    let envs: Vec<_> = envs.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    let process = command
        .args(command_args)
        .env_extend(&envs)
        .stderr(Redirection::Merge)
        .stdout(Redirection::Pipe)
        .stream_stdout()
        .expect("Couldn't start subprocess.");

    let br = BufReader::new(process);
    let mut lines = Vec::new();

    for line in br.lines().flatten() {
        println!("{}", &line);
        lines.push(line);
    }

    // TODO: is this possible with subprocess crate?
    // ensure!(result.exit_status == ExitStatus::Exited(0), "Non-zero exit status for action");

    Ok(lines)
}

///
///
///
fn construct_envs(variables: &Map<Value>) -> Result<Map<String>> {
    let mut envs = Map::<String>::new();

    for (name, variable) in variables.iter() {
        let name = name.to_ascii_uppercase();

        match variable {
            Value::Array { entries, .. } => {
                envs.insert(name.clone(), entries.len().to_string());

                for (index, entry) in entries.iter().enumerate() {
                    if let Value::Array { .. } = entry {
                        unimplemented!()
                    } else if let Value::Struct { properties, .. } = entry {
                        construct_struct_envs(&name, Some(index), properties, &mut envs);
                    } else {
                        let value = match entry {
                            Value::Boolean(value) => value.to_string(),
                            Value::Integer(value) => value.to_string(),
                            Value::Real(value) => value.to_string(),
                            Value::Unicode(value) => value.to_string(),
                            _ => unreachable!(),
                        };

                        envs.insert(format!("{}_{}", &name, index), value);
                    }
                }
            }
            Value::Boolean(value) => {
                envs.insert(name, value.to_string());
            }
            Value::Integer(value) => {
                envs.insert(name, value.to_string());
            }
            Value::Pointer { .. } => unreachable!(),
            Value::Real(value) => {
                envs.insert(name, value.to_string());
            }
            Value::Struct { properties, .. } => {
                construct_struct_envs(&name, None, properties, &mut envs);
            }
            Value::Unicode(value) => {
                envs.insert(name, value.to_string());
            }
            Value::Unit => unreachable!(),
            _ => todo!(),
        }
    }

    debug!("envs: {:?}", envs);
    Ok(envs)
}

///
///
///
fn construct_struct_envs(
    name: &str,
    index: Option<usize>,
    properties: &Map<Value>,
    envs: &mut Map<String>,
) {
    for (key, entry) in properties.iter() {
        let value = match entry {
            Value::Array { entries: _, .. } => unimplemented!(),
            Value::Boolean(value) => value.to_string(),
            Value::Integer(value) => value.to_string(),
            Value::Real(value) => value.to_string(),
            Value::Unicode(value) => value.to_string(),
            Value::Struct { data_type, properties } => match data_type.as_str() {
                "Directory" | "File" => {
                    let value = properties.get("url").expect("Missing `url` property.").to_string();
                    envs.insert(format!("{}_{}_URL", &name, key.to_ascii_uppercase()), value);
                    continue;
                }
                _ => unimplemented!(),
            },
            _ => unreachable!(),
        };

        if let Some(index) = index {
            envs.insert(format!("{}_{}_{}", &name, index, key.to_ascii_uppercase()), value);
        } else {
            envs.insert(format!("{}_{}", &name, key.to_ascii_uppercase()), value);
        }
    }
}

///
///
///
fn capture_output(
    stdout: Vec<String>,
    parameters: &[Parameter],
    mode: &Option<String>,
    c_types: &Option<Map<Type>>,
) -> Result<Map<Value>> {
    debug!("Capture output using mode: {:?}", mode);

    let stdout = preprocess_stdout(stdout, mode)?;
    let docs = YamlLoader::load_from_str(&stdout)?;

    let c_types = c_types.clone().unwrap_or_default();
    let output = unwrap_yaml_hash(&docs[0], parameters, &c_types)?;

    Ok(output)
}

///
///
///
fn unwrap_yaml_hash(
    value: &Yaml,
    parameters: &[Parameter],
    types: &Map<Type>,
) -> Result<Map<Value>> {
    let map = value.as_hash().unwrap();

    let mut output = Map::<Value>::new();
    for p in parameters {
        let key = Yaml::from_str(p.name.as_str());
        let value = &map[&key];

        let value = match value {
            Yaml::Array(elements) => {
                let n = p.data_type.find('[').unwrap(); // Number of array dimensions
                let value_type: String = p.data_type.chars().take(n).collect();

                let mut entries = vec![];
                for element in elements.iter() {
                    let variable = unwrap_yaml_value(element, &value_type)?;
                    entries.push(variable);
                }

                let data_type = p.data_type.to_string();
                Value::Array { data_type, entries }
            }
            Yaml::Hash(_) => unwrap_yaml_struct(value, &p.data_type, types)?,
            _ => unwrap_yaml_value(&map[&key], &p.data_type)?,
        };

        output.insert(p.name.clone(), value);
    }

    Ok(output)
}

fn unwrap_yaml_struct(
    value: &Yaml,
    data_type: &str,
    types: &Map<Type>,
) -> Result<Value> {
    let arch_type = types
        .get(data_type)
        .unwrap_or_else(|| panic!("Missing type `{}`", data_type));
    let mut properties = Map::<Value>::new();

    for p in &arch_type.properties {
        let prop_value = value[p.name.as_str()].clone();
        let prop = unwrap_yaml_value(&prop_value, &p.data_type)?;

        properties.insert(p.name.to_string(), prop);
    }

    Ok(Value::Struct {
        data_type: data_type.to_string(),
        properties,
    })
}

///
///
///
fn unwrap_yaml_value(
    value: &Yaml,
    data_type: &str,
) -> Result<Value> {
    debug!("Unwrapping as {}: {:?} ", data_type, value);

    let value = match data_type {
        "boolean" => {
            let value = value.as_bool().unwrap();
            Value::Boolean(value)
        }
        "File[]" => {
            if let Yaml::Array(elements) = value {
                let mut entries = vec![];
                for element in elements.iter() {
                    let variable = unwrap_yaml_value(element, "File")?;
                    entries.push(variable);
                }

                Value::Array {
                    data_type: data_type.to_string(),
                    entries,
                }
            } else {
                bail!("Expected an array, but it was not.");
            }
        }
        "Directory" | "File" => {
            let value = String::from(value.as_str().unwrap());
            let url = Value::Unicode(value);

            let mut properties: Map<Value> = Default::default();
            properties.insert(String::from("url"), url);

            Value::Struct {
                data_type: String::from(data_type),
                properties,
            }
        }
        "integer" => {
            let value = value.as_i64().unwrap();
            Value::Integer(value)
        }
        "real" => {
            let value = value.as_f64().unwrap();
            Value::Real(value)
        }
        _ => {
            let value = String::from(value.as_str().unwrap());
            Value::Unicode(value)
        }
    };

    Ok(value)
}

const MARK_START: &str = "--> START CAPTURE";
const MARK_END: &str = "--> END CAPTURE";
const PREFIX: &str = "~~>";

///
///
///
fn preprocess_stdout(
    stdout: Vec<String>,
    mode: &Option<String>,
) -> Result<String> {
    let mode = mode.clone().unwrap_or_else(|| String::from("complete"));

    let mut captured = Vec::new();
    match mode.as_str() {
        "complete" => return Ok(stdout.join("\n")),
        "marked" => {
            let mut capture = false;

            for line in stdout {
                if line.trim_start().starts_with(MARK_START) {
                    capture = true;
                    continue;
                }

                // Stop capturing after observing MARK_END after MARK_START
                if capture && line.trim_start().starts_with(MARK_END) {
                    break;
                }

                if capture {
                    debug!("captured: {}", line);
                    captured.push(line);
                }
            }
        }
        "prefixed" => {
            for line in stdout {
                if line.starts_with(PREFIX) {
                    let trimmed = line.trim_start_matches(PREFIX);
                    debug!("captured: {}", trimmed);
                    captured.push(trimmed.to_string());
                }
            }
        }
        _ => unreachable!(),
    }

    Ok(captured.join("\n"))
}
