//  MOD.rs
//    by Lut99
// 
//  Created:
//    25 Aug 2022, 11:01:39
//  Last edited:
//    17 Jan 2023, 14:55:05
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines the module that implements the scanner part of the parser.
// 

// Declare the modules
pub mod tokens;
pub mod comments;
pub mod literal;
pub mod scanning;

// Bring some stuff into this namespace
pub use tokens::{Token, Tokens};
pub use scanning::scan_tokens;


// Define some useful types for this module
/// Shortcut for a LocatedSpan that carries a &str and no additional data.
pub type Span<'a> = nom_locate::LocatedSpan<&'a str>;
