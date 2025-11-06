//  API.rs
//    by Lut99
//
//  Created:
//    26 Sep 2022, 12:15:06
//  Last edited:
//    01 Mar 2023, 10:58:29
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements functions that we use to connect to the Brane API.
//!   Concretely, it is used to retrieve package/data indices.
//

use std::collections::HashMap;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use graphql_client::{GraphQLQuery, Response};
use reqwest::Client;
use specifications::common::{Function, Type};
use specifications::data::{DataIndex, DataInfo};
use specifications::package::{PackageIndex, PackageInfo, PackageKind};
use specifications::version::ConcreteFunctionVersion;
use uuid::Uuid;

pub use crate::errors::ApiError as Error;


/***** CUSTOM TYPES *****/
/// Defines the DateTime in UTC-type that the GraphQLQuery needs (apparently).
pub type DateTimeUtc = DateTime<Utc>;





/***** LIBRARY *****/
/// Downloads the current package index from the Brane API service.
///
/// # Arguments
/// - `endpoint`: The endpoint to send the request to.
///
/// # Returns
/// The PackageIndex that represents the packages currently known to the instance at the time of the call.
///
/// # Errors
/// This function errors for many reasons, chief of which may be that the endpoint is unavailable or its response was ill-formed.
pub async fn get_package_index(endpoint: impl AsRef<str>) -> Result<PackageIndex, Error> {
    // Load up the query
    #[derive(GraphQLQuery)]
    #[graphql(schema_path = "graphql/api_schema.json", query_path = "graphql/get_packages.graphql", response_derives = "Debug")]
    pub struct GetPackages;

    // Resolve &str-like to &str
    let endpoint: &str = endpoint.as_ref();

    // Start preparing the client to send the GraphQL request
    let client = Client::new();
    let variables = get_packages::Variables {};
    let graphql_query = GetPackages::build_query(variables);

    // Request/response for GraphQL query.
    let graphql_response: reqwest::Response =
        client.post(endpoint).json(&graphql_query).send().await.map_err(|source| Error::RequestError { address: endpoint.into(), source })?;
    let body: String = graphql_response.text().await.map_err(|source| Error::ResponseBodyError { address: endpoint.into(), source })?;
    let graphql_response: Response<get_packages::ResponseData> =
        serde_json::from_str(&body).map_err(|source| Error::ResponseJsonParseError { address: endpoint.into(), raw: body, source })?;

    // Analyse the response as a list of PackageInfos
    let packages: Vec<get_packages::GetPackagesPackages> = match graphql_response.data {
        Some(packages) => packages.packages,
        None => {
            return Err(Error::NoResponse { address: endpoint.into() });
        },
    };

    // Parse it as PackageInfos
    let mut infos: Vec<PackageInfo> = Vec::with_capacity(packages.len());
    for (i, p) in packages.into_iter().enumerate() {
        // Parse some elements of the PackageInfo
        let functions: HashMap<String, Function> = p.functions_as_json.map(|f| serde_json::from_str(&f).unwrap()).unwrap_or_default();
        let types: HashMap<String, Type> = p.types_as_json.map(|t| serde_json::from_str(&t).unwrap()).unwrap_or_default();
        let kind: PackageKind = PackageKind::from_str(&p.kind).map_err(|source| Error::PackageKindParseError {
            address: endpoint.into(),
            index: i,
            raw: p.kind,
            source,
        })?;
        let version: ConcreteFunctionVersion = ConcreteFunctionVersion::from_str(&p.version).map_err(|source| Error::VersionParseError {
            address: endpoint.into(),
            index: i,
            raw: p.version,
            source,
        })?;

        // Throw it in a PackageInfo
        infos.push(PackageInfo {
            created: p.created,
            id: p.id,
            digest: p.digest,

            name: p.name,
            version,
            kind,
            owners: p.owners,
            description: p.description.unwrap_or_default(),

            detached: p.detached,
            functions,
            types,
        });
    }

    // Now parse it to an index
    PackageIndex::from_packages(infos).map_err(|source| Error::PackageIndexError { address: endpoint.into(), source })
}



/// Downloads the current data index from the Brane API service.
///
/// # Arguments
/// - `endpoint`: The endpoint to send the request to.
///
/// # Returns
/// The DataIndex that represents the packages currently known to the instance at the time of the call.
///
/// # Errors
/// This function errors for many reasons, chief of which may be that the endpoint is unavailable or its response was ill-formed.
pub async fn get_data_index(endpoint: impl AsRef<str>) -> Result<DataIndex, Error> {
    let endpoint: &str = endpoint.as_ref();

    // Send the reqwest
    let res: reqwest::Response = reqwest::get(endpoint).await.map_err(|source| Error::RequestError { address: endpoint.into(), source })?;

    // Fetch the body
    let body: String = res.text().await.map_err(|source| Error::ResponseBodyError { address: endpoint.into(), source })?;
    let datasets: HashMap<String, DataInfo> =
        serde_json::from_str(&body).map_err(|source| Error::ResponseJsonParseError { address: endpoint.into(), raw: body, source })?;

    // Re-interpret the map as a vector, then wrap it in an index
    let datasets: Vec<DataInfo> = datasets.into_values().collect();
    DataIndex::from_infos(datasets).map_err(|source| Error::DataIndexError { address: endpoint.into(), source })
}
