#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;
#[macro_use]
extern crate juniper;

pub mod schema;

pub struct Context {
    pub name: String,
}

pub use schema::Schema;
