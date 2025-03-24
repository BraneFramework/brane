//  SCHEMA.rs
//    by Lut99
//
//  Created:
//    17 Oct 2022, 15:17:39
//  Last edited:
//    08 Oct 2024, 15:20:52
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines things that we need when accessing the API with GraphQL.
//

use std::path::PathBuf;
use std::str::FromStr;

use chrono::{DateTime, TimeZone, Utc};
use juniper::{EmptySubscription, FieldResult, GraphQLObject, RootNode, graphql_object};
use scylla::IntoTypedRows;
use specifications::version::Version;
use tracing::{debug, info};

use crate::packages::PackageUdt;
use crate::spec::Context;

pub type Schema = RootNode<'static, Query, Mutations, EmptySubscription<Context>>;
impl juniper::Context for Context {}

#[derive(Clone, Debug, GraphQLObject)]
pub struct Package {
    pub created: DateTime<Utc>,
    pub description: Option<String>,
    pub detached: bool,
    pub digest: String,
    pub owners: Vec<String>,
    pub id: String,
    pub kind: String,
    pub name: String,
    pub version: String,
    pub functions_as_json: Option<String>,
    pub types_as_json: Option<String>,
}

impl From<PackageUdt> for Package {
    fn from(row: PackageUdt) -> Self {
        let created = Utc.timestamp_millis_opt(row.created).unwrap();

        Package {
            created,
            description: Some(row.description),
            detached: row.detached,
            digest: row.digest,
            owners: row.owners,
            id: row.id.to_string(),
            kind: row.kind,
            name: row.name,
            version: row.version,
            functions_as_json: Some(row.functions_as_json),
            types_as_json: Some(row.types_as_json),
        }
    }
}

pub struct Query;

#[graphql_object(context = Context)]
impl Query {
    #[allow(non_snake_case)]
    async fn apiVersion() -> &'static str {
        info!("Handling GRAPHQL on '/graphql' (i.e., get API version)");
        env!("CARGO_PKG_VERSION")
    }

    async fn packages(name: Option<String>, version: Option<String>, term: Option<String>, context: &Context) -> FieldResult<Vec<Package>> {
        info!("Handling GRAPHQL on '/graphql' (i.e., get packages list)");
        let scylla = context.scylla.clone();

        let like = format!("%{}%", term.unwrap_or_default());
        let query = "SELECT package FROM brane.packages WHERE name LIKE ? ALLOW FILTERING";

        debug!("Querying Scylla database...");
        let mut packages: Vec<Package> = vec![];
        if let Some(rows) = scylla.query(query, &(like,)).await?.rows {
            // Search for all matches of this package
            for row in rows.into_typed::<(PackageUdt,)>() {
                let (package,) = row?;

                if let Some(name) = &name {
                    if name != &package.name {
                        continue;
                    }
                }

                packages.push(package.into());
            }

            // Now find the target version if relevant
            if let Some(version) = version {
                let target_version: Version = Version::from_str(&version)?;
                let mut package: Option<Package> = None;
                let mut version: Option<Version> = None;
                if target_version.is_latest() {
                    for p in packages {
                        // Find the one with the highest version

                        // Parse it as a version
                        let pversion: Version = match Version::from_str(&p.version) {
                            Ok(version) => version,
                            Err(_) => {
                                continue;
                            },
                        };

                        // Compare
                        if package.is_none() || &pversion > version.as_ref().unwrap() {
                            package = Some(p);
                            version = Some(pversion);
                        }
                    }
                } else {
                    for p in packages {
                        // Find the first matching one

                        // Parse it as a version
                        let pversion: Version = match Version::from_str(&p.version) {
                            Ok(version) => version,
                            Err(_) => {
                                continue;
                            },
                        };

                        // Compare
                        if target_version == pversion {
                            package = Some(p);
                        }
                    }
                }

                // Overwrite the list
                packages = if let Some(package) = package { vec![package] } else { vec![] };
            }
        }

        debug!("Returning {} packages", packages.len());
        Ok(packages)
    }
}

pub struct Mutations;

#[graphql_object(context = Context)]
impl Mutations {
    async fn login(_username: String, _password: String, _context: &Context) -> FieldResult<String> {
        info!("Handling GRAPHQL on '/graphql' (i.e., login)");
        todo!();
    }

    async fn unpublish_package(name: String, version: String, context: &Context) -> FieldResult<&str> {
        info!("Handling GRAPHQL on '/graphql' (i.e., unpublish package)");
        let scylla = context.scylla.clone();

        // Get the image file first, tho
        debug!("Querying file path from Scylla database...");
        let query = "SELECT file FROM brane.packages WHERE name = ? AND version = ?";
        let file = scylla.query(query, &(&name, &version)).await?;
        if let Some(rows) = file.rows {
            if rows.is_empty() {
                return Ok("OK!");
            }
            let file: PathBuf = PathBuf::from(rows[0].columns[0].as_ref().unwrap().as_text().unwrap());

            // Delete the thing from the database
            debug!("Deleting package from Scylla database...");
            let query = "DELETE FROM brane.packages WHERE name = ? AND version = ?";
            scylla.query(query, &(&name, &version)).await?;

            // Delete the file
            debug!("Deleting container file '{}'...", file.display());
            tokio::fs::remove_file(&file).await?;
        }

        Ok("OK!")
    }
}
