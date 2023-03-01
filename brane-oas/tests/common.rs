use anyhow::Result;
use brane_oas::{build, parse_oas_file, resolver};
use specifications::common::{Function, Type};

type Map<T> = std::collections::HashMap<String, T>;
type FunctionAndTypes = (Function, Map<Type>);

#[allow(dead_code)]
pub fn build_oas_function_body(
    path: &str,
    operation_id: &str,
) -> Result<FunctionAndTypes> {
    build_oas_function(path, operation_id, "body.yml")
}

#[allow(dead_code)]
pub fn build_oas_function_param(
    path: &str,
    operation_id: &str,
) -> Result<FunctionAndTypes> {
    build_oas_function(path, operation_id, "param.yml")
}

#[allow(dead_code)]
pub fn build_oas_function_resp(
    path: &str,
    operation_id: &str,
) -> Result<FunctionAndTypes> {
    build_oas_function(path, operation_id, "resp.yml")
}

///
///
///
pub fn build_oas_function(
    path: &str,
    operation_id: &str,
    file: &str,
) -> Result<FunctionAndTypes> {
    let oas = parse_oas_file(format!("tests/resources/{file}"))?;
    let path_item = resolver::resolve_path_item(oas.paths.get(path).unwrap())?;
    let server_known = !oas.servers.is_empty() || !path_item.servers.is_empty();
    let (functions, types) = build::build_oas_function(
        operation_id.to_string(),
        &path_item.get.unwrap(),
        &oas.components,
        server_known,
    )?;

    // Unwrap first (and only) function.
    let function = functions.iter().next().unwrap().1.clone();

    Ok((function, types))
}
