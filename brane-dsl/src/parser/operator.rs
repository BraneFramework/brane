//  OPERATOR.rs
//    by Lut99
//
//  Created:
//    10 Aug 2022, 17:16:11
//  Last edited:
//    31 Oct 2023, 10:47:18
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains functions that parse operator tokens.
//

use std::num::NonZeroUsize;

use nom::error::{ContextError, ParseError};
use nom::{IResult, Parser, branch, combinator as comb, sequence as seq};
use tracing::trace;

use super::ast::{BinOp, Operator, UnaOp};
use crate::scanner::{Token, Tokens};
use crate::spec::TextRange;
use crate::tag_token;


/// Parses either a binary or a unary operator and its starting position.
///
/// # Returns
/// The remaining list of tokens and the parsed BinOp if there was anything to parse. Otherwise, a `nom::Error` is returned (which may be a real error or simply 'could not parse').
pub fn parse<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Operator, E> {
    branch::alt((comb::map(binary_operator, Operator::Binary), comb::map(unary_operator, Operator::Unary))).parse(input)
}





/// Parses a binary operator to a BinOp.
///
/// # Arguments
/// - `input`: The list of tokens to parse from.
///
/// # Returns
/// The remaining list of tokens and the parsed BinOp if there was anything to parse. Otherwise, a `nom::Error` is returned (which may be a real error or simply 'could not parse').
pub fn binary_operator<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, BinOp, E> {
    trace!("Attempting to parse binary operator");
    branch::alt((
        comb::map(seq::pair(tag_token!(Token::And), tag_token!(Token::And)), |t| BinOp::And {
            range: TextRange::from((t.0.tok[0].inner(), t.1.tok[0].inner())),
        }),
        comb::map(tag_token!(Token::Equal), |t| BinOp::Eq { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(tag_token!(Token::Greater), |t| BinOp::Gt { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(tag_token!(Token::GreaterOrEqual), |t| BinOp::Ge { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(tag_token!(Token::Less), |t| BinOp::Lt { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(tag_token!(Token::LessOrEqual), |t| BinOp::Le { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(tag_token!(Token::Minus), |t| BinOp::Sub { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(tag_token!(Token::NotEqual), |t| BinOp::Ne { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(seq::pair(tag_token!(Token::Or), tag_token!(Token::Or)), |t| BinOp::Or {
            range: TextRange::from((t.0.tok[0].inner(), t.1.tok[0].inner())),
        }),
        comb::map(tag_token!(Token::Percentage), |t| BinOp::Mod { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(tag_token!(Token::Plus), |t| BinOp::Add { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(tag_token!(Token::Slash), |t| BinOp::Div { range: TextRange::from(t.tok[0].inner()) }),
        comb::map(tag_token!(Token::Star), |t| BinOp::Mul { range: TextRange::from(t.tok[0].inner()) }),
    ))
    .parse(input)
}

/// Parses a unary operator to a UnaOp.
///
/// # Arguments
/// - `input`: The list of tokens to parse from.
///
/// # Returns
/// The remaining list of tokens and the parsed UnaOp if there was anything to parse. Otherwise, a `nom::Error` is returned (which may be a real error or simply 'could not parse').
pub fn unary_operator<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, UnaOp, E> {
    trace!("Attempting to parse unary operator");
    branch::alt((
        comb::map(tag_token!(Token::Not), |t| UnaOp::Not { range: t.tok[0].inner().into() }),
        comb::map(tag_token!(Token::Minus), |t| UnaOp::Neg { range: t.tok[0].inner().into() }),
        comb::map(tag_token!(Token::LeftBracket), |t| UnaOp::Idx { range: t.tok[0].inner().into() }),
        comb::map(tag_token!(Token::LeftParen), |t| UnaOp::Prio { range: t.tok[0].inner().into() }),
    ))
    .parse(input)
}
