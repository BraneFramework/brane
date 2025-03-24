//  INSTANCE.rs
//    by Lut99
//
//  Created:
//    10 Aug 2022, 17:20:47
//  Last edited:
//    31 Oct 2023, 10:45:25
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines functions that parse an instance expression from the tokens.
//

use std::num::NonZeroUsize;

use nom::error::{ContextError, ParseError};
use nom::{IResult, Parser, combinator as comb, multi, sequence as seq};
use tracing::trace;

use super::ast::{Expr, Identifier, Node, PropertyExpr};
use crate::parser::{expression, identifier};
use crate::scanner::{Token, Tokens};
use crate::spec::{TextPos, TextRange};
use crate::tag_token;


/***** HELPER FUNCTIONS *****/
/// Parses a `property: value` pair as such.
///
/// # Arguments
/// - `input`: The list of tokens to parse from.
///
/// # Returns
/// The remaining list of tokens and the parsed pair if there was anything to parse. Otherwise, a `nom::Error` is returned (which may be a real error or simply 'could not parse').
pub fn instance_property<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, PropertyExpr, E> {
    trace!("Attempting to parse instance property");

    // Parse the head stuff
    let (r, (name, value)) = seq::separated_pair(identifier::parse, tag_token!(Token::Assign), expression::parse).parse(input)?;
    // Parse the closing comma (if any)
    let (r, c) = comb::opt(tag_token!(Token::Comma)).parse(r)?;

    // Return and put it in a PropertyExpr
    let range: TextRange = TextRange::new(name.start().clone(), c.map(|t| TextPos::end_of(t.tok[0].inner())).unwrap_or_else(|| value.end().clone()));
    Ok((r, PropertyExpr { name, value: Box::new(value), range }))
}





/***** LIBRARY *****/
/// Parses an instance expression to an Expr (`Expr::Instance`).
///
/// # Arguments
/// - `input`: The list of tokens to parse from.
///
/// # Returns
/// The remaining list of tokens and the parsed Expr if there was anything to parse. Otherwise, a `nom::Error` is returned (which may be a real error or simply 'could not parse').
pub fn parse<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Expr, E> {
    trace!("Attempting to parse instance expression");

    // Get the new token first
    let (r, n): (Tokens<'a>, Tokens<'a>) = tag_token!(Token::New)(input)?;
    // Parse the main body
    let (r, (class, properties)): (Tokens<'a>, (Identifier, Option<Vec<PropertyExpr>>)) =
        comb::cut(seq::pair(identifier::parse, seq::preceded(tag_token!(Token::LeftBrace), comb::opt(multi::many1(instance_property)))))(r)?;
    // Parse the closing bracket
    let (r, b): (Tokens<'a>, Tokens<'a>) = comb::cut(tag_token!(Token::RightBrace))(r)?;

    // Now put that in an Expr and return
    Ok((r, Expr::new_instance(class, properties.unwrap_or_default(), TextRange::from((n.tok[0].inner(), b.tok[0].inner())))))
}
