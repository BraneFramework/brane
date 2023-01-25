//  SCANNING.rs
//    by Lut99
// 
//  Created:
//    25 Aug 2022, 11:01:54
//  Last edited:
//    17 Jan 2023, 14:58:05
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines the main scanner functions, including its entrypoint.
// 

use nom::error::{ContextError, ParseError, VerboseError};
use nom::{branch, combinator as comb, multi, sequence as seq};
use nom::{bytes::complete as bc, character::complete as cc, IResult, Parser};

use super::Span;
use super::tokens::Token;
use super::comments;
use super::literal;


/***** CONSTANTS *****/
/// Define characters that separate tokens
const SEPARATORS: &str = " \n\t\r{}[]()-=+;:'\"\\|/?>.<,`~*&^%$#@!";





/***** HELPER FUNCTIONS *****/
/// Wraps the given parser such that it may be prefixed or postfixed with whitespace, which will be ignored.
/// 
/// # Arguments
/// - `f`: The parser function to wrap.
/// 
/// # Returns
/// A new function that implements the parser plus the wrapping whitespaces.
fn ws0<'a, O, E: ParseError<Span<'a>>, F: Parser<Span<'a>, O, E>>(f: F) -> impl Parser<Span<'a>, O, E> {
    seq::delimited(
        cc::multispace0,
        f,
        cc::multispace0,
    )
}





/***** SCANNING FUNCTIONS *****/
/// Scans a single token from the start of the given text.
/// 
/// # Arguments
/// - `input`: The String input (wrapped in a Span for token localization later on) to parse.
/// 
/// # Returns
/// A list of the remaining text that we couldn't parse and the parsed token.
/// 
/// # Errors
/// This function errors if we could not successfully parse the text.
fn scan_token<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Token, E> {
    // Keep trying until: eof or non-comment
    branch::alt((
        ws0(comments::parse),
        keyword,
        operator,
        punctuation,
        ws0(literal::parse),
        identifier,
    )).parse(input)
}

/// Scans a keyword token from the start of the given text.
/// 
/// # Arguments
/// - `input`: The String input (wrapped in a Span for token localization later on) to parse.
/// 
/// # Returns
/// A list of the remaining text that we couldn't parse and the parsed token.
/// 
/// # Errors
/// This function errors if we could not successfully parse the text.
fn keyword<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Token, E> {
    ws0(branch::alt((
        comb::map(seq::terminated(bc::tag("break"), comb::peek(separator)), Token::Break),
        comb::map(seq::terminated(bc::tag("class"), comb::peek(separator)), Token::Class),
        comb::map(seq::terminated(bc::tag("continue"), comb::peek(separator)), Token::Continue),
        comb::map(seq::terminated(bc::tag("else"), comb::peek(separator)), Token::Else),
        comb::map(seq::terminated(bc::tag("for"), comb::peek(separator)), Token::For),
        comb::map(seq::terminated(bc::tag("func"), comb::peek(separator)), Token::Function),
        comb::map(seq::terminated(bc::tag("if"), comb::peek(separator)), Token::If),
        comb::map(seq::terminated(bc::tag("import"), comb::peek(separator)), Token::Import),
        comb::map(seq::terminated(bc::tag("let"), comb::peek(separator)), Token::Let),
        comb::map(seq::terminated(bc::tag("new"), comb::peek(separator)), Token::New),
        comb::map(seq::terminated(bc::tag("on"), comb::peek(separator)), Token::On),
        comb::map(seq::terminated(bc::tag("parallel"), comb::peek(separator)), Token::Parallel),
        comb::map(seq::terminated(bc::tag("return"), comb::peek(separator)), Token::Return),
        comb::map(seq::terminated(bc::tag("unit"), comb::peek(separator)), Token::Unit),
        comb::map(seq::terminated(bc::tag("while"), comb::peek(separator)), Token::While),
    )))
    .parse(input)
}

/// Scans an operator token from the start of the given text.
/// 
/// # Arguments
/// - `input`: The String input (wrapped in a Span for token localization later on) to parse.
/// 
/// # Returns
/// A list of the remaining text that we couldn't parse and the parsed token.
/// 
/// # Errors
/// This function errors if we could not successfully parse the text.
fn operator<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Token, E> {
    ws0(branch::alt((
        // Two character tokens
        comb::map(bc::tag(":="), Token::Assign),
        comb::map(bc::tag("=="), Token::Equal),
        comb::map(bc::tag(">="), Token::GreaterOrEqual),
        comb::map(bc::tag("<="), Token::LessOrEqual),
        comb::map(bc::tag("!="), Token::NotEqual),
        // One character token
        comb::map(bc::tag("!"), Token::Not),
        comb::map(bc::tag("&"), Token::And),
        comb::map(bc::tag("%"), Token::Percentage),
        comb::map(bc::tag("*"), Token::Star),
        comb::map(bc::tag("+"), Token::Plus),
        comb::map(bc::tag("-"), Token::Minus),
        comb::map(bc::tag("/"), Token::Slash),
        comb::map(bc::tag("<"), Token::Less),
        comb::map(bc::tag(">"), Token::Greater),
        comb::map(bc::tag("|"), Token::Or),
        comb::map(bc::tag("@"), Token::At),
    )))
    .parse(input)
}

/// Scans an punctuation token from the start of the given text.
/// 
/// # Arguments
/// - `input`: The String input (wrapped in a Span for token localization later on) to parse.
/// 
/// # Returns
/// A list of the remaining text that we couldn't parse and the parsed token.
/// 
/// # Errors
/// This function errors if we could not successfully parse the text.
fn punctuation<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Token, E> {
    ws0(branch::alt((
        comb::map(bc::tag("("), Token::LeftParen),
        comb::map(bc::tag(")"), Token::RightParen),
        comb::map(bc::tag(","), Token::Comma),
        comb::map(bc::tag("."), Token::Dot),
        comb::map(bc::tag(":"), Token::Colon),
        comb::map(bc::tag(";"), Token::Semicolon),
        comb::map(bc::tag("["), Token::LeftBracket),
        comb::map(bc::tag("]"), Token::RightBracket),
        comb::map(bc::tag("{"), Token::LeftBrace),
        comb::map(bc::tag("}"), Token::RightBrace),
    )))
    .parse(input)
}

/// Scans an identifier token from the start of the given text.
/// 
/// # Arguments
/// - `input`: The String input (wrapped in a Span for token localization later on) to parse.
/// 
/// # Returns
/// A list of the remaining text that we couldn't parse and the parsed token.
/// 
/// # Errors
/// This function errors if we could not successfully parse the text.
fn identifier<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, Token, E> {
    ws0(comb::map(
        comb::recognize(seq::pair(
            branch::alt((cc::alpha1, bc::tag("_"))),
            multi::many0(branch::alt((cc::alphanumeric1, bc::tag("_")))),
        )),
        Token::Ident,
    ))
    .parse(input)
}

/// Parses a separator token from the input. This is either a punctuation token or an EOF.
/// 
/// # Arguments
/// - `input`: The input span that this function will attempt to parse a separator off.
/// 
/// # Returns
/// An `IResult` with the remainder and the parsed Token.
/// 
/// # Errors
/// This function may error if it failed to parse a separator.
fn separator<'a, E: ParseError<Span<'a>> + ContextError<Span<'a>>>(input: Span<'a>) -> IResult<Span<'a>, char, E> {
    branch::alt((
        cc::one_of(SEPARATORS),
        comb::map(comb::eof, |_| '\0'),
    ))(input)
}





/***** LIBRARY *****/
/// Parses the given text to a list of tokens, abstracting away over the most nitpicky syntax.
/// 
/// # Arguments
/// - `input`: The String input (wrapped in a Span for token localization later on) to parse.
/// 
/// # Returns
/// A list of the remaining text that we couldn't parse and the list of parsed tokens.
/// 
/// # Errors
/// This function errors if we could not successfully parse the text.
pub fn scan_tokens(input: Span) -> IResult<Span, Vec<Token>, VerboseError<Span>> {
    multi::many0(scan_token)
        .parse(input)
        .map(|(s, t)| {
            let mut t = t;
            t.retain(|t| !t.is_none());

            (s, t)
        })
}
