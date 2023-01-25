//  LITERAL.rs
//    by Lut99
// 
//  Created:
//    25 Aug 2022, 11:12:17
//  Last edited:
//    17 Jan 2023, 14:58:53
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines functions that parse various literal tokens.
// 

use nom::error::{ContextError, ParseError};
use nom::{branch, character::complete as cc, combinator as comb, multi, sequence as seq};
use nom::{bytes::complete as bc, IResult, Parser};

use super::Span;
use super::tokens::Token;


/***** SCANNING FUNCTIONS *****/
/// Parses a null-token off of the head of the given input.
/// 
/// # Arguments
/// - `input`: The input text to scan.
/// 
/// # Returns
/// The remaining tokens and the scanned token.
/// 
/// # Errors
/// This function errors if we could not parse the literal token.
fn null<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Span<'a>, E> {
    bc::tag("null").parse(input)
}

/// Parses a boolean token off of the head of the given input.
/// 
/// # Arguments
/// - `input`: The input text to scan.
/// 
/// # Returns
/// The remaining tokens and the scanned token.
/// 
/// # Errors
/// This function errors if we could not parse the literal token.
fn boolean<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Span<'a>, E> {
    branch::alt((bc::tag("true"), bc::tag("false"))).parse(input)
}

/// Parses an integer token off of the head of the given input.
/// 
/// # Arguments
/// - `input`: The input text to scan.
/// 
/// # Returns
/// The remaining tokens and the scanned token.
/// 
/// # Errors
/// This function errors if we could not parse the literal token.
fn integer<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Span<'a>, E> {
    comb::recognize(multi::many1(seq::terminated(
        cc::one_of("0123456789"),
        multi::many0(cc::char('_')),
    )))
    .parse(input)
}

/// Parses a semver token off of the head of the given input.
/// 
/// # Arguments
/// - `input`: The input text to scan.
/// 
/// # Returns
/// The remaining tokens and the scanned token.
/// 
/// # Errors
/// This function errors if we could not parse the literal token.
fn semver<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Span<'a>, E> {
    const NUMBERS: &str = "0123456789";

    comb::recognize(seq::tuple((
        multi::many1(cc::one_of(NUMBERS)),
        seq::delimited(cc::char('.'), multi::many1(cc::one_of(NUMBERS)), cc::char('.')),
        multi::many1(cc::one_of(NUMBERS)),
    )))
    .parse(input)
}

/// Parses a string token off of the head of the given input.
/// 
/// # Arguments
/// - `input`: The input text to scan.
/// 
/// # Returns
/// The remaining tokens and the scanned token.
/// 
/// # Errors
/// This function errors if we could not parse the literal token.
fn string<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Span<'a>, E> {
    nom::error::context(
        "string",
        seq::preceded(
            cc::char('\"'),
            comb::cut(seq::terminated(
                bc::escaped(bc::is_not("\"\\"), '\\', cc::one_of("\"ntr\\\'")),
                cc::char('\"'),
            )),
        ),
    )(input)
}

/// Parses a real token off of the head of the given input.
/// 
/// # Arguments
/// - `input`: The input text to scan.
/// 
/// # Returns
/// The remaining tokens and the scanned token.
/// 
/// # Errors
/// This function errors if we could not parse the literal token.
fn real<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Span<'a>, E> {
    branch::alt((
        comb::recognize(seq::tuple((
            cc::char('.'),
            integer,
            comb::opt(seq::tuple((cc::one_of("eE"), comb::opt(cc::one_of("+-")), integer))),
        ))),
        comb::recognize(seq::tuple((
            integer,
            comb::opt(seq::preceded(cc::char('.'), integer)),
            cc::one_of("eE"),
            comb::opt(cc::one_of("+-")),
            integer,
        ))),
        comb::recognize(seq::tuple((integer, cc::char('.'), comb::opt(integer)))),
    ))(input)
}





/***** LIBRARY *****/
/// Parses a literal token off of the head of the given input.
/// 
/// # Arguments
/// - `input`: The input text to scan.
/// 
/// # Returns
/// The remaining tokens and the scanned token.
/// 
/// # Errors
/// This function errors if we could not parse the literal token.
pub fn parse<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Token, E> {
    branch::alt((
        comb::map(null, Token::Null),
        comb::map(semver, Token::SemVer),
        comb::map(real, Token::Real),
        comb::map(integer, Token::Integer),
        comb::map(boolean, Token::Boolean),
        comb::map(string, Token::String),
    ))
    .parse(input)
}
