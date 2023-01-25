//  MOD.rs
//    by Lut99
// 
//  Created:
//    18 Aug 2022, 09:48:12
//  Last edited:
//    17 Jan 2023, 14:55:18
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines nom-functions that parse token streams to a temporary AST
//!   that is suited for analysing in `brane-ast`.
// 

// Declare private modules
mod expression;
mod identifier;
mod instance;
mod literal;
mod operator;
// mod pattern;

// Declare public modules
pub mod ast;
pub mod bakery;
pub mod bscript;


// Declare macros
/// Defines a macro that parses the given token from the given stream of tokens.
#[macro_export]
macro_rules! tag_token (
    (Token::$variant:ident) => (
        move |i: Tokens<'a>| {
            use nom::{Err, error_position, Needed, try_parse, take};
            use nom::error::ErrorKind;

            if i.tok.is_empty() {
                match stringify!($variant) {
                    "Dot" => Err(Err::Error(E::from_char(i, '.'))),
                    "Colon" => Err(Err::Error(E::from_char(i, ':'))),
                    "Comma" => Err(Err::Error(E::from_char(i, ','))),
                    "LeftBrace" => Err(Err::Error(E::from_char(i, '{'))),
                    "LeftBracket" => Err(Err::Error(E::from_char(i, '['))),
                    "LeftParen" => Err(Err::Error(E::from_char(i, '('))),
                    "RightBrace" => Err(Err::Error(E::from_char(i, '}'))),
                    "RightBracket" => Err(Err::Error(E::from_char(i, ']'))),
                    "RightParen" => Err(Err::Error(E::from_char(i, ')'))),
                    "Semicolon" => Err(Err::Error(E::from_char(i, ';'))),
                    _ => {
                        Err(Err::Error(error_position!(i, ErrorKind::Eof)))
                    }
                }
            } else {
                let (i1, t1) = try_parse!(i, take!(1));

                if t1.tok.is_empty() {
                    Err(Err::Incomplete(Needed::Size(NonZeroUsize::new(1).unwrap())))
                } else {
                    if let Token::$variant(_) = t1.tok[0] {
                        Ok((i1, t1))
                    } else {
                        match stringify!($variant) {
                            "Dot" => Err(Err::Error(E::from_char(i, '.'))),
                            "Colon" => Err(Err::Error(E::from_char(i, ':'))),
                            "Comma" => Err(Err::Error(E::from_char(i, ','))),
                            "LeftBrace" => Err(Err::Error(E::from_char(i, '{'))),
                            "LeftBracket" => Err(Err::Error(E::from_char(i, '['))),
                            "LeftParen" => Err(Err::Error(E::from_char(i, '('))),
                            "RightBrace" => Err(Err::Error(E::from_char(i, '}'))),
                            "RightBracket" => Err(Err::Error(E::from_char(i, ']'))),
                            "RightParen" => Err(Err::Error(E::from_char(i, ')'))),
                            "Semicolon" => Err(Err::Error(E::from_char(i, ';'))),
                            _ => {
                                Err(Err::Error(error_position!(i, ErrorKind::Tag)))
                            }
                        }
                    }
                }
            }
        }
    );
);
