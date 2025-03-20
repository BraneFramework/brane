//  ERRORS.rs
//    by Lut99
//
//  Created:
//    17 Aug 2022, 11:29:00
//  Last edited:
//    16 Nov 2022, 16:39:28
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines errors that occur in the `brane-dsl` crate. Additionally,
//!   provides some nice formatting options for parser errors.
//

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};

use nom_language::error::{VerboseError, VerboseErrorKind};

use crate::scanner::{Span, Tokens};
use crate::spec::{Language, TextRange};


/***** FORMATTING *****/
pub(crate) fn convert_parser_error(input: Tokens, e: VerboseError<Tokens>) -> String {
    use std::fmt::Write;

    let mut result = String::new();

    for (i, (tokens, kind)) in e.errors.iter().enumerate() {
        match kind {
            VerboseErrorKind::Char(c) => {
                if tokens.tok.is_empty() {
                    if let Some(mismatch) = input.tok.last() {
                        let mismatch = mismatch.inner();
                        let line = String::from_utf8(mismatch.get_line_beginning().to_vec()).unwrap();
                        let line_number = mismatch.location_line();
                        let column_number = mismatch.get_column() + 1;

                        write!(
                            &mut result,
                            "{i}: at line {line_number}:\n\n{line}\n{caret:>column$}\nexpected '{expected}', but encountered EOF\n\n",
                            i = i,
                            line_number = line_number,
                            line = line,
                            caret = '^',
                            column = column_number,
                            expected = c,
                        )
                        .unwrap();
                    } else {
                        write!(&mut result, "{i}: expected '{c}', but EOF\n\n",).unwrap();
                    }
                } else {
                    let mismatch = tokens.tok[0].inner();
                    let line = String::from_utf8(mismatch.get_line_beginning().to_vec()).unwrap();
                    let line_number = mismatch.location_line();
                    let column_number = mismatch.get_column();
                    let actual = mismatch.fragment();

                    write!(
                        &mut result,
                        "{i}: at line {line_number}:\n\n{line}\n{caret:>column$}\nexpected '{expected}', found '{actual}'\n\n",
                        i = i,
                        line_number = line_number,
                        line = line,
                        caret = '^',
                        column = column_number,
                        expected = c,
                        actual = actual,
                    )
                    .unwrap();
                }
            },
            VerboseErrorKind::Nom(nom::error::ErrorKind::Tag) => {
                let mismatch = tokens.tok[0].inner();
                let line = String::from_utf8(mismatch.get_line_beginning().to_vec()).unwrap();
                let line_number = mismatch.location_line();
                let column_number = mismatch.get_column();
                let actual = mismatch.fragment();

                write!(
                    &mut result,
                    "{i}: at line {line_number}:\n{line}\n{caret:>column$}\nunexpected token '{actual}'\n\n",
                    i = i,
                    line_number = line_number,
                    line = line,
                    caret = '^',
                    column = column_number,
                    actual = actual,
                )
                .unwrap();
            },
            VerboseErrorKind::Context(s) => {
                let mismatch = tokens.tok[0].inner();
                let line = String::from_utf8(mismatch.get_line_beginning().to_vec()).unwrap();

                writeln!(result, "{i} in section '{s}', at: {line}").unwrap()
            },
            e => {
                writeln!(result, "Compiler error: unkown error from parser: {e:?}").unwrap();
            },
        }
    }

    result
}

pub(crate) fn convert_scanner_error(input: Span, e: VerboseError<Span>) -> String {
    use std::fmt::Write;

    use nom::Offset;

    let mut result = String::new();

    for (i, (substring, kind)) in e.errors.iter().enumerate() {
        let offset = input.offset(substring);

        if input.is_empty() {
            match kind {
                VerboseErrorKind::Char(c) => write!(&mut result, "{i}: expected '{c}', got empty input\n\n"),
                VerboseErrorKind::Context(s) => write!(&mut result, "{i}: in {s}, got empty input\n\n"),
                VerboseErrorKind::Nom(e) => write!(&mut result, "{i}: in {e:?}, got empty input\n\n"),
            }
        } else {
            let prefix = &input.as_bytes()[..offset];

            // Count the number of newlines in the first `offset` bytes of input
            let line_number = prefix.iter().filter(|&&b| b == b'\n').count() + 1;

            // Find the line that includes the subslice:
            // Find the *last* newline before the substring starts
            let line_begin = prefix
                .iter()
                .rev()
                .position(|&b| b == b'\n')
                .map(|pos| offset - pos)
                .unwrap_or(0);

            // Find the full line after that newline
            let line = input[line_begin..]
                .lines()
                .next()
                .unwrap_or(&input[line_begin..])
                .trim_end();

            // The (1-indexed) column number is the offset of our substring into that line
            let column_number = line.offset(substring) + 1;

            match kind {
                VerboseErrorKind::Char(c) => {
                    if let Some(actual) = substring.chars().next() {
                        write!(
                            &mut result,
                            "{i}: at line {line_number}:\n\
                 {line}\n\
                 {caret:>column$}\n\
                 expected '{expected}', found {actual}\n\n",
                            i = i,
                            line_number = line_number,
                            line = line,
                            caret = '^',
                            column = column_number,
                            expected = c,
                            actual = actual,
                        )
                    } else {
                        write!(
                            &mut result,
                            "{i}: at line {line_number}:\n\
                 {line}\n\
                 {caret:>column$}\n\
                 expected '{expected}', got end of input\n\n",
                            i = i,
                            line_number = line_number,
                            line = line,
                            caret = '^',
                            column = column_number,
                            expected = c,
                        )
                    }
                }
                VerboseErrorKind::Context(s) => write!(
                    &mut result,
                    "{i}: at line {line_number}, in {context}:\n\
               {line}\n\
               {caret:>column$}\n\n",
                    i = i,
                    line_number = line_number,
                    context = s,
                    line = line,
                    caret = '^',
                    column = column_number,
                ),
                VerboseErrorKind::Nom(e) => write!(
                    &mut result,
                    "{i}: at line {line_number}, in {nom_err:?}:\n\
               {line}\n\
               {caret:>column$}\n\n",
                    i = i,
                    line_number = line_number,
                    nom_err = e,
                    line = line,
                    caret = '^',
                    column = column_number,
                ),
            }
        }
        // Because `write!` to a `String` is infallible, this `unwrap` is fine.
        .unwrap();
    }

    result
}





/***** ERRORS *****/
/// Defines errors that relate to the SymbolTable.
#[derive(Debug)]
pub enum SymbolTableError {
    /// A given function already existed in the SymbolTable and could not be easily shadowed.
    DuplicateFunction { name: String, existing: TextRange, got: TextRange },
    /// A given class already existed in the SymbolTable and could not be easily shadowed.
    DuplicateClass { name: String, existing: TextRange, got: TextRange },
    /// A given variable already existed in the SymbolTable and could not be easily shadowed.
    DuplicateVariable { name: String, existing: TextRange, got: TextRange },
    /// A given field (property or method) already existing in the given class.
    DuplicateField { c_name: String, name: String, existing: TextRange, got: TextRange },
}

impl Display for SymbolTableError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use SymbolTableError::*;
        match self {
            DuplicateFunction { name, .. } => write!(f, "Duplicate definition of function '{name}'"),
            DuplicateClass { name, .. } => write!(f, "Duplicate definition of class '{name}'"),
            DuplicateVariable { name, .. } => write!(f, "Duplicate definition of variable '{name}'"),
            DuplicateField { c_name, name, .. } => write!(f, "Duplicate definition of field '{name}' in class '{c_name}'"),
        }
    }
}

impl Error for SymbolTableError {}



/// Defines errors that occur when converting language identifiers to Language enums.
#[derive(Debug)]
pub enum LanguageParseError {
    /// Encountered an unknown language ID.
    UnknownLanguageId { raw: String },
}

impl Display for LanguageParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use LanguageParseError::*;
        match self {
            UnknownLanguageId { raw } => write!(f, "Unknown language ID '{raw}'"),
        }
    }
}

impl Error for LanguageParseError {}

/// Defines errors that occur when converting patterns to calls.
#[derive(Debug)]
pub enum PatternError {
    /// The given pattern was unknown
    UnknownPattern { raw: String, range: TextRange },
}

impl Display for PatternError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PatternError::*;
        match self {
            UnknownPattern { raw, .. } => write!(f, "Pattern '{raw}' is unknown (are you missing a package import?)"),
        }
    }
}

impl Error for PatternError {}



/// Defines errors that occur in the topmost process of conveting raw readers into Programs.
#[derive(Debug)]
pub enum ParseError {
    /// The scanner failed to scan.
    ScanError { err: String },
    /// Some non-Nom error occurred while scanning.
    ScannerError { err: String },
    /// Not all source was parsed (indicating a syntax error).
    LeftoverSourceError,

    /// The parser failed to parse.
    ParseError { lang: Language, err: String },
    /// Some non-Nom error occurred while parsing.
    ParserError { lang: Language, err: String },
    /// We did not have enough tokens to make an informed decision (i.e., an error occurred).
    Eof { lang: Language, err: String },
    /// Not all tokens were parsed (indicating an error).
    LeftoverTokensError { lang: Language },
}

impl Display for ParseError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use self::ParseError::*;
        match self {
            ScanError { err } => write!(f, "Syntax error: {err}"),
            ScannerError { err } => write!(f, "Syntax error: {err}"),
            LeftoverSourceError => write!(f, "Syntax error: not all input could be parsed"),

            ParseError { lang, err } => write!(f, "{lang} parse error: {err}"),
            ParserError { lang, err } => write!(f, "{lang} parse error: {err}"),
            Eof { lang, err } => write!(f, "{lang} parse error: reached end-of-file unexpectedly ({err})"),
            LeftoverTokensError { lang } => write!(f, "{lang} parse error: not all input could be parsed"),
        }
    }
}

impl Error for ParseError {}
