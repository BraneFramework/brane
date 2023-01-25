//  LIB.rs
//    by Lut99
// 
//  Created:
//    18 Aug 2022, 09:49:38
//  Last edited:
//    17 Jan 2023, 14:36:31
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines a library that converts BraneScript _or_ Bakery to a
//!   temporary AST. This AST may then be further analysed / compiled in
//!   the `brane-ast` crate.
// 

// Define private modules
mod scanner;
mod parser;

// Define public modules
pub mod errors;
pub mod spec;
pub mod data_type;
pub mod location;
pub mod symbol_table;
pub mod compiler;


// Bring some stuff into the crate namespace
pub use errors::ParseError as Error;
pub use spec::{Language, TextPos, TextRange};
pub use data_type::DataType;
pub use location::Location;
pub use symbol_table::SymbolTable;
pub use parser::ast;
pub use compiler::{parse, ParserOptions};
