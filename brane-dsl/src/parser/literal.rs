//  LITERAL.rs
//    by Lut99
//
//  Created:
//    10 Aug 2022, 15:39:44
//  Last edited:
//    31 Oct 2023, 10:45:42
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains nom function(s) that parse literal tokens.
//

use std::num::NonZeroUsize;

use nom::error::{ContextError, ParseError};
use nom::{IResult, Parser, branch, combinator as comb};
use tracing::trace;

use super::ast::Literal;
use crate::scanner::{Token, Tokens};
use crate::spec::TextRange;
use crate::tag_token;


/***** HELPER FUNCTIONS *****/
/// Resolves escape strings in a string by, well, resolving them.
///
/// # Arguments
/// - `raw`: The string to resolve.
///
/// # Returns
/// The to-be-resolved string.
fn resolve_escape(raw: String) -> String {
    // Loop to add
    let mut res: String = String::with_capacity(raw.len());
    let mut escaped: bool = false;
    for c in raw.chars() {
        // Check if escaped
        if escaped {
            // We are; match a specific set of characters
            if c == '\\' || c == '"' || c == '\'' {
                res.push(c);
            } else if c == 'n' {
                res.push('\n');
            } else if c == 'r' {
                res.push('\r');
            } else if c == 't' {
                res.push('\t');
            } else {
                panic!("Encountered unknown escape character '{}'", c);
            }
            escaped = false;
        } else if c == '\\' {
            // Going into escape mode
            escaped = true;
        } else {
            res.push(c);
        }
    }

    // Done
    res
}





/***** LIBRARY *****/
/// Parses a literal Token to a Literal node in the AST.
///
/// # Arguments
/// - `input`: The list of tokens to parse from.
///
/// # Returns
/// The remaining list of tokens and the parsed Literal if there was anything to parse. Otherwise, a `nom::Error` is returned (which may be a real error or simply 'could not parse').
pub fn parse<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Literal, E> {
    trace!("Attempting to parse literal expression");
    branch::alt((
        comb::map(tag_token!(Token::Null), |t| Literal::Null { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(tag_token!(Token::Boolean), |t| Literal::Boolean {
            value: t.tok[0].as_bool(),

            range: TextRange::from(t.tok[0].inner()),
        }),
        comb::map(tag_token!(Token::Integer), |t| Literal::Integer {
            value: t.tok[0].as_i64(),

            range: TextRange::from(t.tok[0].inner()),
        }),
        comb::map(tag_token!(Token::Real), |t| Literal::Real {
            value: t.tok[0].as_f64(),

            range: TextRange::from(t.tok[0].inner()),
        }),
        comb::map(tag_token!(Token::String), |t| Literal::String {
            value: resolve_escape(t.tok[0].as_string()),

            range: {
                // Wrap one back and forth for the quotes
                let mut r = TextRange::from(t.tok[0].inner());
                r.start.col -= 1;
                r.end.col += 1;
                r
            },
        }),
        comb::map(tag_token!(Token::Unit), |t| Literal::Void { range: TextRange::from(t.tok[0].inner()) }),
    ))
    .parse(input)
}
