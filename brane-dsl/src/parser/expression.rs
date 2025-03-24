//  EXPRESSION.rs
//    by Lut99
//
//  Created:
//    16 Aug &2022, 14:42:43
//  Last edited:
//    31 Oct 2023, 10:50:44
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines functions for parsing BraneScript / Bakery expressions.
//

use std::num::NonZeroUsize;

use nom::error::{ContextError, ParseError};
use nom::{IResult, Parser, branch, combinator as comb, multi, sequence as seq};
use tracing::trace;

use super::ast::{Expr, Identifier, Node, Operator, UnaOp};
use crate::location::AllowedLocations;
use crate::parser::{identifier, instance, literal, operator};
use crate::scanner::{Token, Tokens};
use crate::spec::{TextPos, TextRange};
use crate::tag_token;


/// Parses an expression.
///
/// # Arguments
/// - `input`: The input stream of tokens that we use to parse expressions from.
///
/// # Returns
/// A tuple of the remaining tokens and a parsed expression if there was an expression on top.
///
/// # Errors
/// This function returns a nom::Error if it failed to parse an expression.
pub fn parse<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Expr, E> {
    trace!("Attempting to parse expression");

    // Use a pratt parser(?) to actually parse it
    expr_pratt(input, 0)
}

/// Parses the expressions in a pratt-parser style.
///
/// Explanation of pratt parsers may be found here: https://matklad.github.io/2020/04/13/simple-but-powerful-pratt-parsing.html.
///
/// # Arguments
/// - `input`: The input stream of tokens that we use to parse expressions from.
/// - `min_bp`: The minimum binding power of operators to parse (to allow presedence and such).
///
/// # Returns
/// A tuple of the remaining tokens and a parsed expression if there was an expression on top.
///
/// # Errors
/// This function returns a nom::Error if it failed to parse an expression.
fn expr_pratt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>, min_bp: u8) -> IResult<Tokens<'a>, Expr, E> {
    // Attempt to parse a unary operator first
    let (mut remainder, mut lhs) = match operator::unary_operator::<E>(input) {
        Ok((r, UnaOp::Idx { range })) => {
            // Parse the rest as (the rest of) an array
            array_expr(&Some(range)).parse(r)?
        },
        // Simply parse the expression in between the brackets
        Ok((r, UnaOp::Prio { range: _ })) => seq::terminated(self::parse, tag_token!(Token::RightParen)).parse(r)?,
        Ok((r, operator)) => {
            // Try to find an operator with higher binding power
            let (_, r_bp) = operator.binding_power();
            let (r, rhs) = expr_pratt(r, r_bp)?;
            let range: TextRange = TextRange::new(operator.start().clone(), rhs.end().clone());

            // Return the best operator found
            (r, Expr::new_unaop(operator, Box::new(rhs), range))
        },
        _ => expr_atom(input)?,
    };

    // Other operators may be multiple, so start looping and parse (would be a recursion if that was not infinite)
    loop {
        match operator::parse::<E>(remainder) {
            Ok((r, Operator::Binary(operator))) => {
                // Recurse until lower binding power is encountered.
                let (left_bp, right_bp) = operator.binding_power();
                if left_bp < min_bp {
                    break;
                }
                let (remainder_3, rhs) = expr_pratt(r, right_bp)?;

                // We then return the remainder
                remainder = remainder_3;
                let range: TextRange = TextRange::new(lhs.start().clone(), rhs.end().clone());
                lhs = Expr::new_binop(operator, Box::new(lhs), Box::new(rhs), range);
            },
            Ok((r, Operator::Unary(operator))) => {
                let (left_bp, _) = operator.binding_power();
                if left_bp < min_bp {
                    break;
                }

                // If the operator happens to be an index, return the special index array one
                lhs = if let UnaOp::Idx { .. } = operator {
                    let (r2, rhs) = self::parse(r)?;
                    let (r2, bracket) = tag_token!(Token::RightBracket).parse(r2)?;
                    remainder = r2;

                    let range: TextRange = TextRange::new(lhs.start().clone(), TextPos::end_of(bracket.tok[0].inner()));
                    Expr::new_array_index(Box::new(lhs), Box::new(rhs), range)
                } else {
                    // Otherwise, do the default unary operator
                    let range: TextRange = TextRange::new(lhs.start().clone(), operator.end().clone());
                    remainder = r;
                    Expr::new_unaop(operator, Box::new(lhs), range)
                };
            },
            _ => break,
        }
    }

    Ok((remainder, lhs))
}

/// Parses the given token stream as a literal or a variable reference.
///
/// # Arguments
/// - `input`: The input stream of tokens that we use to parse expressions from.
///
/// # Returns
/// A tuple of the remaining tokens and a parsed expression if there was an expression on top.
///
/// # Errors
/// This function returns a nom::Error if it failed to parse an expression.
pub fn expr_atom<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Expr, E> {
    trace!("Attempting to parse atomic expression");

    branch::alt((
        instance::parse,
        call_expr,
        comb::map(literal::parse, |l| Expr::Literal { literal: l }),
        proj_expr,
        comb::map(identifier::parse, Expr::new_varref),
    ))
    .parse(input)
}

/// Parses the given token stream as a call expression.
///
/// TODO: Integrate this in pratt parser? To support, e.g., f()()() ?
///
/// # Arguments
/// - `input`: The input stream of tokens that we use to parse expressions from.
///
/// # Returns
/// A tuple of the remaining tokens and a parsed expression if there was an expression on top.
///
/// # Errors
/// This function returns a nom::Error if it failed to parse an expression.
pub fn call_expr<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Expr, E> {
    trace!("Attempting to parse Call-expression");

    // Parse optionally annotations
    let (r, at) = comb::opt(tag_token!(Token::At)).parse(input)?;
    let (r, annot) = if at.is_some() {
        let (r, annot) = comb::cut(seq::delimited(
            tag_token!(Token::LeftBracket),
            multi::separated_list1(tag_token!(Token::Comma), tag_token!(Token::String)),
            tag_token!(Token::RightBracket),
        ))
        .parse(r)?;
        (r, Some(annot))
    } else {
        (r, None)
    };

    // Parse the call thingy itself
    let (r, (expr, args)) = seq::pair(
        branch::alt((proj_expr, comb::map(identifier::parse, Expr::new_identifier))),
        seq::preceded(
            tag_token!(Token::LeftParen),
            comb::opt(seq::pair(self::parse, multi::many0(seq::preceded(tag_token!(Token::Comma), self::parse)))),
        ),
    )
    .parse(r)?;
    // Parse the closing delimiter
    let (r, paren) = tag_token!(Token::RightParen).parse(r)?;

    // Re-align the arguments to one single vector
    let args: Vec<Box<Expr>> = match args {
        Some((head, rest)) => {
            let mut res: Vec<Box<Expr>> = Vec::with_capacity(rest.len());
            res.push(Box::new(head));
            res.append(&mut rest.into_iter().map(Box::new).collect());
            res
        },
        None => Vec::new(),
    };

    // Put it in an Expr::Call and return
    let range: TextRange =
        TextRange::new(at.map(|a| a.tok[0].inner().into()).unwrap_or_else(|| expr.start().clone()), TextPos::end_of(paren.tok[0].inner()));
    Ok((
        r,
        Expr::new_call(
            Box::new(expr),
            args,
            range,
            annot.map(|l| AllowedLocations::Exclusive(l.into_iter().map(|l| l.tok[0].as_string().into()).collect())).unwrap_or(AllowedLocations::All),
        ),
    ))
}

/// Parses the given token stream as a projection expression.
///
/// # Arguments
/// - `input`: The input stream of tokens that we use to parse expressions from.
///
/// # Returns
/// A tuple of the remaining tokens and a parsed expression if there was an expression on top.
///
/// # Errors
/// This function returns a nom::Error if it failed to parse an expression.
fn proj_expr<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Expr, E> {
    trace!("Attempting to parse Projection-expression");

    // We parse an identifier with dot tentatively
    let (r, lhs) = seq::terminated(tag_token!(Token::Ident), tag_token!(Token::Dot)).parse(input)?;
    // If that is successfully, we force a repetition of at least one next token
    let (r, rhs) = comb::cut(multi::separated_list1(tag_token!(Token::Dot), tag_token!(Token::Ident))).parse(r)?;

    // Rewrite that in a tree of projection expressions
    let mut expr: Expr = Expr::new_varref(Identifier::new(lhs.tok[0].as_string(), lhs.tok[0].inner().into()));
    let mut range: TextRange = expr.range().clone();
    for i in rhs {
        // Encapsulate the existing expr
        range = TextRange::new(range.start, TextPos::end_of(i.tok[0].inner()));
        expr = Expr::new_proj(
            Box::new(expr),
            Box::new(Expr::new_identifier(Identifier::new(i.tok[0].as_string(), i.tok[0].inner().into()))),
            range.clone(),
        )
    }

    // Return it
    Ok((r, expr))
}

/// Parses the given token stream as an array expression.
///
/// # Arguments
/// - `input`: The input stream of tokens that we use to parse expressions from.
/// - `start_range`: If not None, skips parsing the initial '[' bracket and instead uses the given range as the start range.
///
/// # Returns
/// A tuple of the remaining tokens and a parsed expression if there was an expression on top.
///
/// # Errors
/// This function returns a nom::Error if it failed to parse an expression.
fn array_expr<'a, 'b, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(
    start_range: &'b Option<TextRange>,
) -> impl 'b + Parser<Tokens<'a>, Expr, E> {
    trace!("Attempting to parse Array-expression");

    // Return a closure that does the actual thingy
    move |input: Tokens<'a>| -> IResult<Tokens, Expr, E> {
        // Parse the first bracket if needed
        let (r, range): (Tokens<'a>, TextRange) = if let Some(range) = start_range.as_ref() {
            (input, range.clone())
        } else {
            let (r, t) = tag_token!(Token::LeftBracket).parse(input)?;
            (r, TextRange::from(t.tok[0].inner()))
        };

        // It's an array-index; but we parse it as an array expression (so parse a comma-separated list of expressions)
        let (r, entries) = comb::opt(seq::terminated(
            seq::pair(self::parse, multi::many0(seq::preceded(tag_token!(Token::Comma), self::parse))),
            comb::opt(tag_token!(Token::Comma)),
        ))
        .parse(r)?;
        let (r, bracket) = tag_token!(Token::RightBracket).parse(r)?;

        // Return the array with its elements
        if let Some((head, entries)) = entries {
            let mut e = Vec::with_capacity(entries.len() + 1);
            e.push(Box::new(head));
            e.append(&mut entries.into_iter().map(Box::new).collect());

            // Return it
            Ok((r, Expr::new_array(e, TextRange::new(range.start, TextPos::end_of(bracket.tok[0].inner())))))
        } else {
            // It's an empty Array
            Ok((r, Expr::new_array(vec![], TextRange::new(range.start, TextPos::end_of(bracket.tok[0].inner())))))
        }
    }
}
