//  COMPILER.rs
//    by Lut99
//
//  Created:
//    18 Aug 2022, 09:51:07
//  Last edited:
//    31 Oct 2023, 10:30:23
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the general compilation functions that generate the
//!   (incomplete) AST.
//

use nom::InputLength;
use nom::error::VerboseErrorKind;
use specifications::package::PackageIndex;
use tracing::trace;

use crate::errors;
pub use crate::errors::ParseError as Error;
use crate::parser::ast::Program;
use crate::parser::{bakery, bscript};
use crate::scanner::{self, Span, Token, Tokens};
use crate::spec::Language;


/***** TESTS *****/
#[cfg(test)]
pub mod tests {
    use brane_shr::utilities::{create_package_index, test_on_dsl_files};

    use super::*;


    /// Tests BraneScript files.
    #[test]
    fn test_bscript() {
        // Simply pass to the compiler
        test_on_dsl_files("BraneScript", |path, code| {
            // Print the header always
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Read the package index
            let pindex: PackageIndex = create_package_index();

            // Create a compiler and compile it;
            let res: Program = match parse(code, &pindex, &ParserOptions::bscript()) {
                Ok(res) => res,
                Err(err) => {
                    panic!("Failed to parse BraneScript file '{}': {}", path.display(), err);
                },
            };

            // Print it for good measure
            println!("{res:#?}");
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }

    /// Tests Bakery files.
    #[test]
    fn test_bakery() {
        // Simply pass to the compiler
        test_on_dsl_files("Bakery", |path, code| {
            // Print the header always
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Read the package index
            let pindex: PackageIndex = create_package_index();

            // Create a compiler and compile it;
            let res: Program = match parse(code, &pindex, &ParserOptions::bakery()) {
                Ok(res) => res,
                Err(err) => {
                    panic!("Failed to parse Bakery file '{}': {}", path.display(), err);
                },
            };

            // Print it for good measure
            println!("{res:#?}");
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}





/***** AUXILLARY STRUCTS *****/
/// Defines options that configure the compiler before we use it.
#[derive(Clone, Debug)]
pub struct ParserOptions {
    /// The language the compiler will parse (i.e., BraneScript or Bakery).
    pub lang: Language,
}

impl ParserOptions {
    /// Constructor for the ParserOptions.
    ///
    /// # Arguments
    /// - `lang`: The language which the compiler will parse.
    ///
    /// # Returns
    /// A new ParserOptions with the given settings.
    #[inline]
    pub fn new(lang: Language) -> Self { Self { lang } }

    /// Constructor for the ParserOptions that defaults it to a BraneScript setup.
    ///
    /// # Returns
    /// A new ParserOptions that will make the compiler compile BraneScript.
    #[inline]
    pub fn bscript() -> Self { Self { lang: Language::BraneScript } }

    /// Constructor for the ParserOptions that defaults it to a Bakery setup.
    ///
    /// # Returns
    /// A new ParserOptions that will make the compiler compile Bakery.
    #[inline]
    pub fn bakery() -> Self { Self { lang: Language::Bakery } }
}





/***** LIBRARY *****/
/// Parses the given reader to a BraneScript / Bakery Program.
///
/// # Generic arguments
/// - `S`: The &str-like type of the `source` text.
///
/// # Arguments
/// - `source`: The source text to parse from.
/// - `pindex`: The PackageIndex that we use to resolve patterns.
/// - `options`: Some auxillary ParserOptions that finetune its behaviour.
///
/// # Returns
/// A new Program that is the parsed source code. It still needs to be compiled to a workflow using `brane-ast`.
///
/// # Errors
/// This function may error if we could not read the reader or if the source code was somehow malformed.
pub fn parse<S: AsRef<str>>(source: S, pindex: &PackageIndex, options: &ParserOptions) -> Result<Program, Error> {
    let source: &str = source.as_ref();

    // Run that through the scanner
    trace!("Parsing input to tokens...");
    let (remain, tokens): (Span, Vec<Token>) = match scanner::scan_tokens(Span::from(source)) {
        Ok(res) => res,
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
            return Err(Error::ScanError { err: errors::convert_scanner_error(Span::from(source), e) });
        },
        Err(err) => {
            return Err(Error::ScannerError { err: format!("{err}") });
        },
    };
    if remain.input_len() > 0 && !remain.fragment().to_string().trim().is_empty() {
        return Err(Error::LeftoverSourceError);
    }

    // Run the tokens through the parser (depending on the selected language)
    trace!("Parsing tokens to Program...");
    let tks = Tokens::new(&tokens);
    let (remain, ast): (Tokens, Program) = match options.lang {
        Language::BraneScript => match bscript::parse_ast(tks) {
            Ok(ast) => ast,

            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
                // Match the EOF-error
                if e.errors[0].1 == VerboseErrorKind::Nom(nom::error::ErrorKind::Eof) {
                    return Err(Error::Eof { lang: Language::BraneScript, err: errors::convert_parser_error(tks, e) });
                }
                return Err(Error::ParseError { lang: Language::BraneScript, err: errors::convert_parser_error(tks, e) });
            },
            Err(err) => {
                return Err(Error::ParserError { lang: Language::BraneScript, err: format!("{err}") });
            },
        },

        Language::Bakery => match bakery::parse_ast(tks, pindex.clone()) {
            Ok(ast) => ast,

            Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
                // Match the EOF-error
                if e.errors[0].1 == VerboseErrorKind::Nom(nom::error::ErrorKind::Eof) {
                    return Err(Error::Eof { lang: Language::BraneScript, err: errors::convert_parser_error(tks, e) });
                }
                return Err(Error::ParseError { lang: Language::Bakery, err: errors::convert_parser_error(tks, e) });
            },
            Err(err) => {
                return Err(Error::ParserError { lang: Language::Bakery, err: format!("{err}") });
            },
        },
    };
    if remain.input_len() > 0 {
        return Err(Error::LeftoverTokensError { lang: options.lang });
    }

    // Alright, that's a parsed program
    Ok(ast)
}
