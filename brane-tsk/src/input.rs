//  INPUT.rs
//    by Lut99
//
//  Created:
//    22 May 2023, 13:13:51
//  Last edited:
//    08 Feb 2024, 15:16:20
//  Auto updated?
//    Yes
//
//  Description:
//!   Queries functions that are useful for value inputs.
//

use std::collections::HashMap;
use std::error;
use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::str::FromStr;

use brane_ast::DataType;
use brane_ast::ast::{ClassDef, VarDef};
use brane_ast::spec::BuiltinClasses;
use brane_exe::FullValue;
use console::{Term, style};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input as Prompt, Select};
use specifications::data::DataIndex;
use specifications::package::PackageInfo;
use specifications::version::Version;
use tracing::debug;


/***** ERRORS *****/
/// Defines errors that can occur when prompting for input.
#[derive(Debug)]
pub enum Error {
    /// A package attempts to define a builtin function.
    PackageDefinesBuiltin { name: String, version: Version, builtin: String },
    /// The package uses an undefined class.
    UndefinedClass { name: String, version: Version, class: String },

    /// Failed to query the user for the function they like to run.
    FunctionQueryError { err: dialoguer::Error },
    /// Failed to ask the user a yes/no R U sure question.
    YesNoQueryError { err: dialoguer::Error },
    /// Failed to query a value of the given type.
    ValueQueryError { res_type: &'static str, err: dialoguer::Error },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            PackageDefinesBuiltin { name, version, builtin } => write!(f, "Package {name}:{version} overwrites builtin class '{builtin}'"),
            UndefinedClass { name, version, class } => write!(f, "Package {name}:{version} references undefined class '{class}'"),

            FunctionQueryError { .. } => write!(f, "Failed to query for package function"),
            YesNoQueryError { .. } => write!(f, "Failed to query for confirmaiton"),
            ValueQueryError { res_type, .. } => write!(f, "Failed to query for {res_type} value"),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            PackageDefinesBuiltin { .. } => None,
            UndefinedClass { .. } => None,

            FunctionQueryError { err } => Some(err),
            YesNoQueryError { err } => Some(err),
            ValueQueryError { err, .. } => Some(err),
        }
    }
}





/***** LIBRARY *****/
/// Prompts the user for input before testing the package.
///
/// Basically asks their shirt off their body in what function they want to execute and which values to execute it with.
///
/// # Arguments
/// - `dindex`: The [`DataIndex`] that represents possible datasets to choose from if the given function requires any.
/// - `package`: The [`PackageInfo`] file that contains the package information of the package we are querying for.
///
/// # Returns
/// The name of the chosen function and a map of values for the function to run with.
///
/// # Errors
/// This function errors if querying the user failed. Additionally, if their package re-exports builtins, that's considered a grave grime and they will be shot too.
pub fn prompt_for_input(data_index: &DataIndex, package: &PackageInfo) -> Result<(String, HashMap<String, FullValue>), Error> {
    // We get a list of functions, sorted alphabetically (but dumb)
    let mut function_list: Vec<String> = package.functions.keys().map(|k| k.to_string()).collect();
    function_list.sort();

    // Insert missing builtins in the map
    let mut types: HashMap<String, ClassDef> = package
        .types
        .iter()
        .map(|t| {
            (t.0.clone(), ClassDef {
                name:    t.1.name.clone(),
                package: Some(package.name.clone()),
                version: Some(package.version),

                props:   t.1.properties.iter().map(|p| VarDef { name: p.name.clone(), data_type: DataType::from(&p.data_type) }).collect(),
                methods: vec![],
            })
        })
        .collect();
    for builtin in &[BuiltinClasses::Data] {
        if let Some(old) = types.insert(builtin.name().into(), ClassDef {
            name:    builtin.name().into(),
            package: None,
            version: None,

            props:   builtin.props().into_iter().map(|p| p.into()).collect(),
            // We don't care for methods anyway
            methods: vec![],
        }) {
            return Err(Error::PackageDefinesBuiltin { name: package.name.clone(), version: package.version, builtin: old.name });
        }
    }

    // Query the user about which of the functions they'd like
    let index =
        match Select::with_theme(&ColorfulTheme::default()).with_prompt("The function the execute").default(0).items(&function_list[..]).interact() {
            Ok(index) => index,
            Err(err) => {
                return Err(Error::FunctionQueryError { err });
            },
        };
    let function_name = &function_list[index];
    let function = &package.functions[function_name];

    // Now, with the chosen function, we will collect all of the function's arguments
    let mut args: HashMap<String, FullValue> = HashMap::new();
    if !function.parameters.is_empty() {
        println!("\nPlease provide input for the chosen function:\n");
        for p in &function.parameters {
            // Prompt for that data type
            let value: FullValue = prompt_for_param(
                data_index,
                package,
                format!("{} [{}]", p.name, p.data_type),
                &p.name,
                DataType::from(&p.data_type),
                p.optional.unwrap_or(false),
                None,
                &types,
            )?;
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
/// - `dindex`: The [`DataIndex`] that represents possible datasets to choose from.
/// - `package`: A [`PackageInfo`] that represents the package we are querying for.
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
#[allow(clippy::too_many_arguments)]
fn prompt_for_param(
    data_index: &DataIndex,
    package: &PackageInfo,
    what: impl AsRef<str>,
    name: impl AsRef<str>,
    data_type: DataType,
    optional: bool,
    default: Option<FullValue>,
    types: &HashMap<String, ClassDef>,
) -> Result<FullValue, Error> {
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

        Array { elem_type } => {
            // If there is a default, we are forced to ask it beforehand.
            if let Some(default) = default {
                // Ensure the default has the correct value
                if default.data_type() != (DataType::Array { elem_type: elem_type.clone() }) {
                    panic!("{} cannot have a value of type {} as default value", DataType::Array { elem_type }, default.data_type());
                }

                // Prompt the user to use it
                if match Confirm::new()
                    .with_prompt(format!(
                        "{} has a default value: {}; would you like to use that?",
                        style(name).bold().cyan(),
                        style(format!("{default}")).bold()
                    ))
                    .interact()
                {
                    Ok(use_default) => use_default,
                    Err(err) => {
                        return Err(Error::YesNoQueryError { err });
                    },
                } {
                    return Ok(default);
                }
            }

            // Add as many elements as the user likes
            let mut values: Vec<FullValue> = Vec::with_capacity(16);
            loop {
                // Query the user
                let res = prompt_for_param(
                    data_index,
                    package,
                    format!("{} [{}] <element {}>", name, elem_type, values.len()),
                    name,
                    *elem_type.clone(),
                    false,
                    None,
                    types,
                )?;
                values.push(res);

                // Ask if they want to ask more
                if !match Confirm::new().with_prompt("Add more elements?").interact() {
                    Ok(cont) => cont,
                    Err(err) => {
                        return Err(Error::YesNoQueryError { err });
                    },
                } {
                    break;
                }
            }

            // Done
            FullValue::Array(values)
        },
        Class { name: c_name } => {
            // If there is a default, we are forced to ask it beforehand.
            if let Some(default) = default {
                // Ensure the default has the correct value
                if default.data_type() != (DataType::Class { name: c_name.clone() }) {
                    panic!("{} cannot have a value of type {} as default value", DataType::Class { name: c_name }, default.data_type());
                }

                // Prompt the user to use it
                if match Confirm::new()
                    .with_prompt(format!(
                        "{} has a default value: {}; would you like to use that?",
                        style(name).bold().cyan(),
                        style(format!("{default}")).bold()
                    ))
                    .interact()
                {
                    Ok(use_default) => use_default,
                    Err(err) => {
                        return Err(Error::YesNoQueryError { err });
                    },
                } {
                    return Ok(default);
                }
            }

            // Resolve the class
            let def: &ClassDef = match types.get(&c_name) {
                Some(def) => def,
                None => {
                    return Err(Error::UndefinedClass { name: package.name.clone(), version: package.version, class: c_name });
                },
            };

            // Sort the properties of said class alphabetically
            let mut props: Vec<&VarDef> = def.props.iter().collect();
            props.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

            // Query for them in-order
            let mut values: HashMap<std::string::String, FullValue> = HashMap::with_capacity(props.len());
            for p in props {
                let res = prompt_for_param(
                    data_index,
                    package,
                    format!("{} [{}] <field {}::{}>", name, p.data_type, c_name, p.name),
                    name,
                    p.data_type.clone(),
                    false,
                    None,
                    types,
                )?;
                values.insert(p.name.clone(), res);
            }

            // Done
            FullValue::Instance(c_name, values)
        },
        Data | IntermediateResult => {
            // Collect the given datasets
            let mut items: Vec<&str> = data_index.iter().map(|info| info.name.as_str()).collect();
            items.sort();

            // Prepare the prompt with beautiful themes and such
            let colorful = ColorfulTheme::default();
            let prompt = Select::with_theme(&colorful).items(&items).with_prompt(what).default(0usize);

            // Done
            let res: std::string::String = match prompt.interact_on_opt(&Term::stderr()) {
                Ok(res) => res.map(|i| items[i].to_string()).unwrap_or_else(|| items[0].to_string()),
                Err(err) => {
                    return Err(Error::ValueQueryError { res_type: std::any::type_name::<std::string::String>(), err });
                },
            };

            // The prompt is what we need
            FullValue::Data(res.into())
        },

        Void => FullValue::Void,

        // The rest we don't do
        _ => {
            panic!("Cannot query values for parameter '{}' of type {}", name, data_type);
        },
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
fn prompt<T>(what: impl AsRef<str>, optional: bool, default: Option<T>) -> Result<T, Error>
where
    T: Clone + FromStr + Display,
    T::Err: Display + Debug,
{
    // Prepare the prompt with beautiful themes and such
    let colorful = ColorfulTheme::default();
    let mut prompt = Prompt::with_theme(&colorful).with_prompt(what.as_ref()).allow_empty(optional);

    // Also add a default if that's given
    if let Some(default) = default {
        prompt = prompt.default(default);
    }

    // Alright hit it
    match prompt.interact() {
        Ok(res) => Ok(res),
        Err(err) => Err(Error::ValueQueryError { res_type: std::any::type_name::<T>(), err }),
    }
}
