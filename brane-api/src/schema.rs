//  SCHEMA.rs
//    by Lut99
// 
//  Created:
//    17 Oct 2022, 15:17:39
//  Last edited:
//    17 Oct 2022, 15:18:15
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines things that we need when accessing the API with GraphQL.
// 

use chrono::{DateTime, TimeZone, Utc};
use juniper::{graphql_object, EmptySubscription, FieldResult, GraphQLObject, RootNode};
use scylla::IntoTypedRows;
use uuid::Uuid;

use crate::spec::Context;
use crate::packages::PackageUdt;

pub type Schema = RootNode<'static, Query, Mutations, EmptySubscription<Context>>;
impl juniper::Context for Context {}

#[derive(Clone, Debug, GraphQLObject)]
pub struct Package {
    pub created: DateTime<Utc>,
    pub description: Option<String>,
    pub detached: bool,
    pub digest: String,
    pub owners: Vec<String>,
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub version: String,
    pub functions_as_json: Option<String>,
    pub types_as_json: Option<String>,
}

impl From<PackageUdt> for Package {
    fn from(row: PackageUdt) -> Self {
        let created = Utc.timestamp_millis(row.created);

        Package {
            created,
            description: Some(row.description),
            detached: row.detached,
            digest: row.digest,
            owners: row.owners,
            id: row.id,
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
    ///
    ///
    ///
    async fn apiVersion() -> &str {
        env!("CARGO_PKG_VERSION")
    }

    ///
    ///
    ///
    async fn packages(
        name: Option<String>,
        version: Option<String>,
        term: Option<String>,
        context: &Context,
    ) -> FieldResult<Vec<Package>> {
        let scylla = context.scylla.clone();

        let like = format!("%{}%", term.unwrap_or_default());
        let query = "SELECT package FROM brane.packages WHERE name LIKE ? ALLOW FILTERING";

        let mut packages = vec![];
        if let Some(rows) = scylla.query(query, &(like,)).await?.rows {
            for row in rows.into_typed::<(PackageUdt,)>() {
                let (package,) = row?;

                if let Some(name) = &name {
                    if name != &package.name {
                        continue;
                    }
                }

                if let Some(version) = &version {
                    if version != &package.version {
                        continue;
                    }
                }

                packages.push(package.into());
            }
        }

        Ok(packages)
    }
}

pub struct Mutations;

#[graphql_object(context = Context)]
impl Mutations {
    ///
    ///
    ///
    async fn login(
        _username: String,
        _password: String,
        _context: &Context,
    ) -> FieldResult<String> {
        todo!();
    }

    ///
    ///
    ///
    async fn unpublish_package(
        name: String,
        version: String,
        context: &Context,
    ) -> FieldResult<&str> {
        let scylla = context.scylla.clone();

        let query = "DELETE FROM brane.packages WHERE name = ? AND version = ?";
        scylla.query(query, &(&name, &version)).await?;

        Ok("OK!")
    }
}
