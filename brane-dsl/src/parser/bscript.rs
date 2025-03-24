//  BSCRIPT.rs
//    by Lut99
//
//  Created:
//    17 Aug 2022, 16:01:41
//  Last edited:
//    08 Dec 2023, 17:30:47
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains the code to parse a BraneScript script, as well as any
//!   BraneScript-specific parsing functions.
//

use std::collections::HashSet;
use std::num::NonZeroUsize;

use nom::error::{ContextError, ErrorKind, ParseError, VerboseError};
use nom::{IResult, Parser, branch, combinator as comb, multi, sequence as seq};
use tracing::trace;

use super::ast::{Block, Identifier, Literal, Node, Program, Property, Stmt};
use crate::ast::Attribute;
use crate::data_type::DataType;
use crate::parser::{expression, identifier, literal};
use crate::scanner::{Token, Tokens};
use crate::spec::{TextPos, TextRange};
use crate::tag_token;


/***** HELPER ENUMS *****/
/// Defines an abstraction over a class method and a class property.
#[derive(Clone, Debug)]
enum ClassStmt {
    /// It's a property, as a (name, type) pair.
    Property(Property),
    /// It's a function definition (but stored in statement form; it still references only function definitions)
    Method(Box<Stmt>),
}

impl Node for ClassStmt {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange {
        match self {
            ClassStmt::Property(prop) => prop.range(),
            ClassStmt::Method(func) => func.range(),
        }
    }
}





/***** HELPER FUNCTIONS *****/
/// Parses a Block node from the given token stream.
///
/// This is not a statement, since it may also be used nested within statements. Instead, it is a series of statements that are in their own scope.
///
/// For example:
/// ```branescript
/// {
///     print("Hello there!");
/// }
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Block`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid block.
fn block<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Block, E> {
    trace!("Attempting to parse block");

    // Parse the left brace
    let (r, left) = tag_token!(Token::LeftBrace).parse(input)?;
    // Parse the statements
    let (r, stmts) = multi::many0(parse_stmt).parse(r)?;
    // Parse the right brace
    let (r, right) = tag_token!(Token::RightBrace).parse(r)?;

    // Put it in a Block, done
    Ok((r, Block::new(stmts, TextRange::from((left.tok[0].inner(), right.tok[0].inner())))))
}

/// Parses a single (identifier, type) pair (separated by a colon).
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of the remaining tokens and a tuple of the identifier, type and start and stop position of the entire thing.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid (identifier, type) pair.
fn property<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Property, E> {
    trace!("Attempting to parse class property");

    // Parse as a separated pair
    let (r, (name, data_type)) = seq::separated_pair(identifier::parse, tag_token!(Token::Colon), tag_token!(Token::Ident)).parse(input)?;
    // Parse the closing semicolon
    let (r, s) = tag_token!(Token::Semicolon).parse(r)?;

    // Put as the tuple and return it
    let range: TextRange = TextRange::new(name.start().clone(), TextPos::end_of(s.tok[0].inner()));
    Ok((r, Property::new(name, DataType::from(data_type.tok[0].as_string()), range)))
}

/// Parses a single 'class statement', i.e., a property or method declaration.
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of the remaining tokens and an abstraction over the resulting property/method pair.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid property or method definition.
fn class_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, ClassStmt, E> {
    trace!("Attempting to parse class property or method");

    // Parse either as one or the other
    branch::alt((comb::map(property, ClassStmt::Property), comb::map(declare_func_stmt, |m| ClassStmt::Method(Box::new(m))))).parse(input)
}





/***** GENERAL PARSING FUNCTIONS *****/
/// Parses a stream of tokens into a full BraneScript AST.
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a series of statements. These are not yet directly executable, but are ready for analysis in `brane-ast`.
///
/// # Errors
/// This function may error if the tokens do not comprise valid BraneScript.
pub fn parse_ast(input: Tokens) -> IResult<Tokens, Program, VerboseError<Tokens>> {
    trace!("Attempting to parse BraneScript AST");

    // Parse it all as statements
    let (r, stmts) = comb::all_consuming(multi::many0(parse_stmt))(input)?;

    // Wrap it in a program and done
    let start_pos: TextPos = stmts.first().map(|s| s.start().clone()).unwrap_or(TextPos::none());
    let end_pos: TextPos = stmts.iter().last().map(|s| s.end().clone()).unwrap_or(TextPos::none());
    Ok((r, Program { block: Block::new(stmts, TextRange::new(start_pos, end_pos)), metadata: HashSet::new() }))
}





/***** STATEMENT PARSING FUNCTIONS *****/
/// Parses a statement in the head of the given token stream.
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed statement.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn parse_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse next statement");

    // If there are no more tokens, then easy
    if input.tok.is_empty() {
        return Err(nom::Err::Error(nom::error_position!(input, ErrorKind::Tag)));
    }

    // Otherwise, parse one of the following statements
    branch::alt((
        attribute_stmt,
        attribute_inner_stmt,
        for_stmt,
        assign_stmt,
        block_stmt,
        parallel_stmt,
        declare_class_stmt,
        declare_func_stmt,
        expr_stmt,
        if_stmt,
        import_stmt,
        let_assign_stmt,
        return_stmt,
        while_stmt,
    ))
    .parse(input)
}



/// Parses the contents of an attribute.
///
/// For example:
/// ```branescript
/// foo = "bar"
/// ```
/// or
/// ```branescript
/// foo("bar", "baz")
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed [`Attribute`].
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn attribute<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Attribute, E> {
    trace!("Attempting to parse Attribute");

    // Parse the possible attribute variants
    comb::cut(branch::alt((
        comb::map(
            seq::separated_pair(identifier::parse, tag_token!(Token::Equal), comb::cut(literal::parse)),
            |(key, value): (Identifier, Literal)| {
                let range: TextRange = TextRange::new(value.start().clone(), value.end().clone());
                Attribute::KeyPair { key, value, range }
            },
        ),
        comb::map(
            seq::tuple((
                identifier::parse,
                tag_token!(Token::LeftParen),
                comb::cut(seq::pair(multi::separated_list1(tag_token!(Token::Comma), literal::parse), tag_token!(Token::RightParen))),
            )),
            |(key, lparen, (values, rparen)): (Identifier, Tokens, (Vec<Literal>, Tokens))| {
                let range: TextRange = TextRange::new(TextPos::from(lparen.tok[0].inner()), TextPos::end_of(rparen.tok[0].inner()));
                Attribute::List { key, values, range }
            },
        ),
    )))
    .parse(input)
}

/// Parses an attribute-statement that annotates something from outside.
///
/// For example:
/// ```branescript
/// #[foo = "bar"]
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed [`Stmt::Attribute`].
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn attribute_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse Attribute-statement");

    // Parse the hashtag and opening square bracket, the attribute and the closing bracket
    let (r, p) = tag_token!(Token::Pound).parse(input)?;
    let (r, _) = tag_token!(Token::LeftBracket).parse(r)?;
    let (r, (mut attr, b)): (Tokens, (Attribute, Tokens)) = comb::cut(seq::pair(attribute, tag_token!(Token::RightBracket))).parse(r)?;

    // Update the ranges
    match &mut attr {
        Attribute::KeyPair { range, .. } => *range = TextRange::new(TextPos::from(p.tok[0].inner()), TextPos::end_of(b.tok[0].inner())),
        Attribute::List { range, .. } => *range = TextRange::new(TextPos::from(p.tok[0].inner()), TextPos::end_of(b.tok[0].inner())),
    }

    // Return the parsed attribute
    Ok((r, Stmt::Attribute(attr)))
}

/// Parses an attribute-statement that annotates something from within.
///
/// For example:
/// ```branescript
/// #![foo = "bar"]
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::AttributeInner`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn attribute_inner_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse AttributeInner-statement");

    // Parse the hashtag and opening square bracket, the attribute and the closing bracket
    let (r, p) = tag_token!(Token::Pound).parse(input)?;
    let (r, _) = tag_token!(Token::Not).parse(r)?;
    let (r, _) = tag_token!(Token::LeftBracket).parse(r)?;
    let (r, (mut attr, b)): (Tokens, (Attribute, Tokens)) = comb::cut(seq::pair(attribute, tag_token!(Token::RightBracket))).parse(r)?;

    // Update the ranges
    match &mut attr {
        Attribute::KeyPair { range, .. } => *range = TextRange::new(TextPos::from(p.tok[0].inner()), TextPos::end_of(b.tok[0].inner())),
        Attribute::List { range, .. } => *range = TextRange::new(TextPos::from(p.tok[0].inner()), TextPos::end_of(b.tok[0].inner())),
    }

    // Return the parsed attribute
    Ok((r, Stmt::AttributeInner(attr)))
}



/// Parses a let assign statement.
///
/// For example:
/// ```branescript
/// let val := 42;
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::LetAssign`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn let_assign_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse LetAssign-statement");

    // Parse the 'let' first
    let (r, l) = tag_token!(Token::Let).parse(input)?;
    // Then, parse the body of the statement
    let (r, (name, value)) = comb::cut(seq::separated_pair(identifier::parse, tag_token!(Token::Assign), expression::parse)).parse(r)?;
    // Finally, parse the semicolon
    let (r, s) = tag_token!(Token::Semicolon).parse(r)?;

    // Put it in a letassign and done
    Ok((r, Stmt::new_letassign(name, value, TextRange::from((l.tok[0].inner(), s.tok[0].inner())))))
}

/// Parses an assign statement.
///
/// For example:
/// ```branescript
/// val := 42;
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::Assign`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn assign_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse Assign-statement");

    // Parse the body of the statement
    let (r, (name, value)) = seq::separated_pair(identifier::parse, tag_token!(Token::Assign), expression::parse).parse(input)?;
    // Parse the semicolon
    let (r, s) = comb::cut(tag_token!(Token::Semicolon)).parse(r)?;

    // Put it in an assign and done
    let range: TextRange = TextRange::new(name.start().clone(), TextPos::end_of(s.tok[0].inner()));
    Ok((r, Stmt::new_assign(name, value, range)))
}

/// Parses a Block-statement.
///
/// For example:
/// ```branescript
/// {
///     print("Hello there!");
/// }
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::Block`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
#[inline]
pub fn block_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse Block-statement");

    // Simply map the block helper function
    block(input).map(|(r, b)| (r, Stmt::Block { block: Box::new(b) }))
}

/// Parses a Parallel-statement.
///
/// For example:
/// ```branescript
/// parallel [{
///     print("Hello there!");
/// }, {
///     print("General Kenobi, you are a bold one");
/// }];
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::Parallel`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn parallel_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse Parallel-statement");

    // Plausibly, parse a preceded part
    let (r, l) = comb::opt(tag_token!(Token::Let)).parse(input)?;
    let (r, identifier) = comb::opt(seq::terminated(identifier::parse, tag_token!(Token::Assign))).parse(r)?;

    // Always parse the 'parallel' token next
    let (r, p) = tag_token!(Token::Parallel).parse(r)?;
    // Parse the optional merge strategy
    let (r, m) = comb::opt(seq::delimited(tag_token!(Token::LeftBracket), identifier::parse, comb::cut(tag_token!(Token::RightBracket)))).parse(r)?;
    // Do the body then
    let (r, blocks): (Tokens<'a>, Option<(Block, Vec<Block>)>) = comb::cut(seq::delimited(
        tag_token!(Token::LeftBracket),
        comb::opt(seq::pair(block, multi::many0(seq::preceded(tag_token!(Token::Comma), block)))),
        tag_token!(Token::RightBracket),
    ))
    .parse(r)?;
    // Finally, parse the ending semicolon
    let (r, s) = comb::cut(tag_token!(Token::Semicolon)).parse(r)?;

    // Flatten the blocks
    let blocks = blocks
        .map(|(h, e)| {
            let mut res: Vec<Block> = Vec::with_capacity(1 + e.len());
            res.push(h);
            res.extend(e);
            res
        })
        .unwrap_or_default();

    // Put it in a Parallel and return
    Ok((r, Stmt::new_parallel(identifier, blocks, m, TextRange::from(((l.unwrap_or(p)).tok[0].inner(), s.tok[0].inner())))))
}

/// Parses a ClassDef-statement.
///
/// For example:
/// ```branescript
/// class Jedi {
///     name: string;
///     is_master: bool;
///     lightsaber_colour: string;
///
///     func swoosh(self) {
///         print(self.name + " is swinging their " + self.lightsaber_colour + " lightsaber!");
///     }
/// }
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::ClassDef`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn declare_class_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse Class-statement");

    // Parse the class keyword first
    let (r, c) = tag_token!(Token::Class).parse(input)?;
    // Parse the class body
    let (r, (ident, body)) = seq::pair(identifier::parse, seq::preceded(tag_token!(Token::LeftBrace), multi::many0(class_stmt))).parse(r)?;
    // Parse the closing right brace
    let (r, b) = tag_token!(Token::RightBrace).parse(r)?;

    // Parse the body into a set of vectors
    let mut props: Vec<Property> = Vec::with_capacity(body.len() / 2);
    let mut methods: Vec<Box<Stmt>> = Vec::with_capacity(body.len() / 2);
    for stmt in body.into_iter() {
        match stmt {
            ClassStmt::Property(prop) => {
                props.push(prop);
            },
            ClassStmt::Method(method) => {
                methods.push(method);
            },
        }
    }

    // Done, wrap in the class
    Ok((r, Stmt::new_classdef(ident, props, methods, TextRange::from((c.tok[0].inner(), b.tok[0].inner())))))
}

/// Parses a FuncDef-statement.
///
/// For example:
/// ```branescript
/// class Jedi {
///     name: string;
///     is_master: bool;
///     lightsaber_colour: string;
///
///     func swoosh(self) {
///         print(self.name + " is swinging their " + self.lightsaber_colour + " lightsaber!");
///     }
/// }
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::FuncDef`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn declare_func_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse Func-statement");

    // Hit the function token first
    let (r, f) = tag_token!(Token::Function).parse(input)?;
    // Parse everything else
    let (r, ((ident, params), code)) = seq::tuple((
        comb::cut(seq::pair(
            identifier::parse,
            seq::delimited(
                tag_token!(Token::LeftParen),
                comb::opt(seq::pair(identifier::parse, multi::many0(seq::preceded(tag_token!(Token::Comma), identifier::parse)))),
                tag_token!(Token::RightParen),
            ),
        )),
        comb::cut(block),
    ))
    .parse(r)?;

    // Flatten the parameters
    let params = params
        .map(|(h, mut e)| {
            let mut res: Vec<Identifier> = Vec::with_capacity(1 + e.len());
            res.push(h);
            res.append(&mut e);
            res
        })
        .unwrap_or_default();

    // Put in a FuncDef and done
    let range: TextRange = TextRange::new(f.tok[0].inner().into(), code.end().clone());
    Ok((r, Stmt::new_funcdef(ident, params, Box::new(code), range)))
}

/// Parses an if-statement.
///
/// For example:
/// ```branescript
/// if (some_value == 1) {
///     print("Hello there!");
/// } else {
///     print("General Kenobi, you are a bold one");
/// }
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::If`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn if_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse If-statement");

    // As usual, parse the token first
    let (r, f) = tag_token!(Token::If).parse(input)?;
    // Parse the expression followed by the body that is always there + optionally and else
    let (r, (cond, consequent, alternative)) = comb::cut(seq::tuple((
        seq::delimited(tag_token!(Token::LeftParen), expression::parse, tag_token!(Token::RightParen)),
        block,
        comb::opt(seq::preceded(tag_token!(Token::Else), block)),
    )))
    .parse(r)?;

    // Put it in a Stmt::If and done
    let range: TextRange =
        TextRange::new(f.tok[0].inner().into(), alternative.as_ref().map(|b| b.end().clone()).unwrap_or_else(|| consequent.end().clone()));
    Ok((r, Stmt::If { cond, consequent: Box::new(consequent), alternative: alternative.map(Box::new), attrs: vec![], range }))
}

/// Parses an import-statement.
///
/// For example:
/// ```branescript
/// import hello_world;
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::Import`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn import_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse Import-statement");

    // Parse the import token first
    let (r, i) = nom::error::context("'import' statement", tag_token!(Token::Import)).parse(input)?;
    // Parse the identifier followed by an optional version number
    let (r, (package, version)) = nom::error::context(
        "'import' statement",
        comb::cut(seq::pair(
            identifier::parse,
            comb::opt(seq::delimited(tag_token!(Token::LeftBracket), tag_token!(Token::SemVer), tag_token!(Token::RightBracket))),
        )),
    )
    .parse(r)?;
    // Parse the closing semicolon
    let (r, s) = nom::error::context("'import' statement", tag_token!(Token::Semicolon)).parse(r)?;

    // Put it in an Import and done
    Ok((
        r,
        Stmt::new_import(
            package,
            version
                .map(|t| Literal::Semver { value: t.tok[0].inner().fragment().to_string(), range: t.tok[0].inner().into() })
                .unwrap_or(Literal::Semver { value: "latest".into(), range: TextRange::none() }),
            TextRange::from((i.tok[0].inner(), s.tok[0].inner())),
        ),
    ))
}

/// Parses a for-loop.
///
/// For example:
/// ```branescript
/// for (let i := 0; i < 10; i++) {
///     print("Hello there!");
/// }
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::For`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn for_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse For-statement");

    // Parse the for token first
    let (r, f) = nom::error::context("'for' statement", tag_token!(Token::For)).parse(input)?;
    // Parse the rest
    let (r, ((initializer, condition, increment), consequent)) = nom::error::context(
        "'for' statement",
        comb::cut(seq::pair(
            seq::delimited(
                tag_token!(Token::LeftParen),
                seq::tuple((
                    let_assign_stmt,
                    seq::terminated(expression::parse, tag_token!(Token::Semicolon)),
                    comb::map(seq::separated_pair(identifier::parse, tag_token!(Token::Assign), expression::parse), |(name, value)| {
                        // Get the start and end pos for this assign
                        let range: TextRange = TextRange::new(name.start().clone(), value.end().clone());

                        // Return as the proper struct
                        Stmt::new_assign(name, value, range)
                    }),
                )),
                tag_token!(Token::RightParen),
            ),
            block,
        )),
    )
    .parse(r)?;

    // Hey-ho, let's go put it in a struct
    let range: TextRange = TextRange::new(f.tok[0].inner().into(), consequent.end().clone());
    Ok((r, Stmt::For {
        initializer: Box::new(initializer),
        condition,
        increment: Box::new(increment),
        consequent: Box::new(consequent),
        attrs: vec![],
        range,
    }))
}

/// Parses a while-loop.
///
/// For example:
/// ```branescript
/// while (say_hello) {
///     print("Hello there!");
/// }
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::While`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn while_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse While-statement");

    // Parse the for token first
    let (r, w) = tag_token!(Token::While).parse(input)?;
    // Parse the rest
    let (r, (condition, consequent)) =
        seq::pair(seq::delimited(tag_token!(Token::LeftParen), expression::parse, tag_token!(Token::RightParen)), block).parse(r)?;

    // Return it as a result
    let range: TextRange = TextRange::new(w.tok[0].inner().into(), consequent.end().clone());
    Ok((r, Stmt::While { condition, consequent: Box::new(consequent), attrs: vec![], range }))
}

/// Parses a return-statement.
///
/// For example:
/// ```branescript
/// return 42;
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::Return`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn return_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse Return-statement");

    // Parse the return token first
    let (r, ret) = tag_token!(Token::Return).parse(input)?;
    // Parse the expression, optionally
    let (r, expression) = comb::opt(expression::parse).parse(r)?;
    // Parse the closing semicolon
    let (r, s) = comb::cut(tag_token!(Token::Semicolon)).parse(r)?;

    // Put it in a return statement
    Ok((r, Stmt::new_return(expression, TextRange::from((ret.tok[0].inner(), s.tok[0].inner())))))
}

/// Parses a loose expression-statement.
///
/// For example:
/// ```branescript
/// print("Hello there!");
/// ```
/// or
/// ```branescript
/// 1 + 1;
/// ```
///
/// # Arguments
/// - `input`: The token stream that will be parsed.
///
/// # Returns
/// A pair of remaining tokens and a parsed `Stmt::Expr`.
///
/// # Errors
/// This function may error if the tokens do not comprise a valid statement.
pub fn expr_stmt<'a, E: ParseError<Tokens<'a>> + ContextError<Tokens<'a>>>(input: Tokens<'a>) -> IResult<Tokens<'a>, Stmt, E> {
    trace!("Attempting to parse Expr-statement");

    // Simply do an expression + semicolon
    let (r, expr) = expression::parse(input)?;
    let (r, s) = comb::cut(tag_token!(Token::Semicolon)).parse(r)?;

    // Return as Stmt::Expr
    let range: TextRange = TextRange::new(expr.start().clone(), TextPos::end_of(s.tok[0].inner()));
    Ok((r, Stmt::new_expr(expr, range)))
}
