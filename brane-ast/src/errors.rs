//  ERRORS.rs
//    by Lut99
//
//  Created:
//    10 Aug 2022, 13:52:37
//  Last edited:
//    31 Jan 2024, 11:35:11
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the errors for the `brane-ast` crate.
//

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::io::Write;

use brane_dsl::ast::Expr;
use brane_dsl::spec::MergeStrategy;
use brane_dsl::{DataType, TextRange};
use console::{Style, style};
use specifications::version::Version;

use crate::spec::BuiltinClasses;


/***** HELPER MACROS *****/
/// Print either the given number or '?' if it is `usize::MAX`.
macro_rules! n {
    ($n:expr) => {
        if $n < usize::MAX { format!("{}", $n) } else { String::from("?") }
    };
}
pub(crate) use n;





/***** HELPER FUNCTIONS *****/
/// Computes the length of the number as if it was a string.
///
/// # Generic arguments
/// - `N`: The f64-like type of `n`.
///
/// # Arguments
/// - `n`: The number to compute the length of.
///
/// # Returns
/// The number of digits in the number.
#[inline]
fn num_len<N: Into<usize>>(n: N) -> usize { ((n.into() as f64).log10() + 1.0) as usize }

/// Pads the given number by adding enough spaced prefix to reach the desired length.
///
/// # Generic arguments
/// - `N`: The usize-like type of `n`.
///
/// # Arguments
/// - `n`: The number to pad.
/// - `l`: The to-be-padded-to length.
///
/// # Returns
/// The number as a string with appropriate padding.
#[inline]
fn pad_num<N: Copy + Into<usize>>(n: N, l: usize) -> String { format!("{}{}", (0..l - num_len(n)).map(|_| ' ').collect::<String>(), n.into()) }

/// Prettyprints the given list to a string.
///
/// # Generic arguments
/// - `T`: The element type of the `list` to print.
/// - `S`: The &str-like type of the `word`.
///
/// # Arguments
/// - `list`: The list to print.
/// - `word`: The word to use in the final stage of the list (e.g., "or", "and", ..).
///
/// # Returns
/// A string representation of the list.
#[inline]
fn prettyprint_list<T: Display, S: AsRef<str>>(list: &[T], word: S) -> String {
    let mut res: String = String::new();
    for (i, e) in list.iter().enumerate() {
        if i > 0 && i < list.len() - 2 {
            res.push_str(", ");
        } else if i == list.len() - 2 {
            res.push_str(word.as_ref());
        }
        res.push_str(&format!("{e}"));
    }
    res
}



/// Given the source text, extracts the given line and prints it with the range highlighted.
///
/// If the range is multi-line, then only the first line is printed.
///
/// # Arguments
/// - `writer`: The [`Write`]-enabled stream to write to.
/// - `source`: The source text (as a string) to extract the line from.
/// - `range`: The TextRange to extract.
/// - `colour`: The colour to print in.
///
/// # Errors
/// This function may error if we failed to write to the given writer.
///
/// # Panics
/// This function errors if the range is out-of-bounds for the source text.
pub(crate) fn ewrite_range(mut writer: impl Write, source: impl AsRef<str>, range: &TextRange, colour: Style) -> Result<(), std::io::Error> {
    // Do nothing if the range is none
    if range.is_none() {
        return Ok(());
    }

    // Convert the &str-like into a &str
    let source: &str = source.as_ref();

    // Find the start of the range in the source text
    let mut line_i: usize = 1;
    let mut line_start: usize = 0;
    let mut line: Option<&str> = None;
    for (i, c) in source.char_indices() {
        // Search until the end of the line
        if c == '\n' {
            if line_i == range.start.line {
                // It's the correct line; take it
                line = Some(&source[line_start..i]);
                break;
            }
            line_start = i + 1;
            line_i += 1;
        }
    }
    if line.is_none() && line_start < source.len() && line_i == range.start.line {
        line = Some(&source[line_start..]);
    }
    let line: &str = line.unwrap_or_else(|| panic!("A position of {}:{} is out-of-bounds for given source text.", range.start, range.end));

    // Now print the line up until the correct position
    let red_start: usize = range.start.col - 1;
    let red_end: usize = if range.start.line == range.end.line { range.end.col - 1 } else { line.len() };
    write!(
        &mut writer,
        "{} {}",
        style(format!(
            " {} |",
            if range.start.line == range.end.line { format!("{}", range.start.line) } else { pad_num(range.start.line, num_len(range.end.line)) }
        ))
        .blue()
        .bright(),
        &line[0..red_start]
    )?;
    // Print the red part
    write!(&mut writer, "{}", colour.apply_to(&line[red_start..red_end]))?;
    // Print the rest (if any)
    writeln!(&mut writer, "{}", &line[red_end..])?;

    // Print the red area
    writeln!(
        &mut writer,
        " {} {} {}{}",
        (0..(if range.start.line == range.end.line { num_len(range.start.line) } else { num_len(range.end.line) })).map(|_| ' ').collect::<String>(),
        style("|").blue().bright(),
        (0..red_start).map(|_| ' ').collect::<String>(),
        colour.apply_to((red_start..red_end).map(|_| '^').collect::<String>()),
    )?;

    // If the range is longer, print dots
    if range.start.line != range.end.line {
        writeln!(&mut writer, "{} {}", style(format!(" {} |", range.start.line + 1)).blue().bright(), colour.apply_to("..."))?;
        writeln!(
            &mut writer,
            "{} {}",
            style(format!(" {} |", (0..num_len(range.end.line)).map(|_| ' ').collect::<String>())).blue().bright(),
            colour.apply_to("^^^")
        )?;
    }

    // Done
    Ok(())
}

/// Prettyprints an error with only one 'reason'.
///
/// # Arguments
/// - `writer`: The [`Write`]-enabled stream to write to.
/// - `source`: The source text to extract the line from.
/// - `err`: The Error to print.
/// - `range`: The range of the error.
///
/// # Errors
/// This function may error if we failed to write to the given writer.
fn prettywrite_err(
    mut writer: impl Write,
    file: impl AsRef<str>,
    source: impl AsRef<str>,
    err: &dyn Error,
    range: &TextRange,
) -> Result<(), std::io::Error> {
    // Print the top line
    writeln!(
        &mut writer,
        "{}: {}: {}",
        style(format!("{}:{}:{}", file.as_ref(), n!(range.start.line), n!(range.start.col))).bold(),
        style("error").red().bold(),
        err
    )?;

    // Print the range
    ewrite_range(&mut writer, source, range, Style::new().red().bold())?;
    writeln!(&mut writer)?;

    // Done
    Ok(())
}

/// Prettyprints an error with a range and a 'it's defined here' range.
///
/// # Arguments
/// - `writer`: The [`Write`]-enabled stream to write to.
/// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
/// - `source`: The source text to extract the line from.
/// - `err`: The Error to print.
/// - `range`: The range that indicates the actual reference.
/// - `defined`: The range that indicates the location of the defition.
///
/// # Errors
/// This function may error if we failed to write to the given writer.
fn prettywrite_err_defined(
    mut writer: impl Write,
    file: impl AsRef<str>,
    source: impl AsRef<str>,
    err: &dyn Error,
    range: &TextRange,
    defined: &TextRange,
) -> Result<(), std::io::Error> {
    // Print the top line
    writeln!(
        &mut writer,
        "{}: {}: {}",
        style(format!("{}:{}:{}", file.as_ref(), n!(range.start.line), n!(range.start.col))).bold(),
        style("error").red().bold(),
        err
    )?;

    // Print the normal range
    ewrite_range(&mut writer, &source, range, Style::new().red().bold())?;

    // Print the expected range
    writeln!(&mut writer, "{}: Defined here:", style("note").cyan().bold())?;
    ewrite_range(&mut writer, source, defined, Style::new().cyan().bold())?;
    writeln!(&mut writer)?;

    // Done
    Ok(())
}

/// Prettyprints an error with only one 'expected' value or type and one 'got' value or type.
///
/// # Arguments
/// - `writer`: The [`Write`]-enabled stream to write to.
/// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
/// - `source`: The source text to extract the line from.
/// - `err`: The Error to print.
/// - `expected`: The range that indicates the expected value or type.
/// - `got`: The range that indicates the got value or type.
///
/// # Errors
/// This function may error if we failed to write to the given writer.
fn prettywrite_err_exp_got(
    mut writer: impl Write,
    file: impl AsRef<str>,
    source: impl AsRef<str>,
    err: &dyn Error,
    expected: &TextRange,
    got: &TextRange,
) -> Result<(), std::io::Error> {
    // Print the top line
    writeln!(
        &mut writer,
        "{}: {}: {}",
        style(format!("{}:{}:{}", file.as_ref(), n!(got.start.line), n!(got.start.col))).bold(),
        style("error").red().bold(),
        err
    )?;

    // Print the normal range
    ewrite_range(&mut writer, &source, got, Style::new().red().bold())?;

    // Print the expected range
    writeln!(&mut writer, "{}: Expected because of:", style("note").cyan().bold())?;
    ewrite_range(&mut writer, source, expected, Style::new().cyan().bold())?;
    writeln!(&mut writer)?;

    // Done
    Ok(())
}

/// Prettyprints an error with only one 'existing' value or type and one 'new' value or type.
///
/// # Arguments
/// - `writer`: The [`Write`]-enabled stream to write to.
/// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
/// - `source`: The source text to extract the line from.
/// - `err`: The Error to print.
/// - `existing`: The range that indicates the existing value or type.
/// - `new`: The range that indicates the new value or type.
///
/// # Errors
/// This function may error if we failed to write to the given writer.
fn prettywrite_err_exist_new(
    mut writer: impl Write,
    file: impl AsRef<str>,
    source: impl AsRef<str>,
    err: &dyn Error,
    existing: &TextRange,
    new: &TextRange,
) -> Result<(), std::io::Error> {
    // Print the top line
    writeln!(
        &mut writer,
        "{}: {}: {}",
        style(format!("{}:{}:{}", file.as_ref(), n!(new.start.line), n!(new.start.col))).bold(),
        style("error").red().bold(),
        err
    )?;

    // Print the normal range
    ewrite_range(&mut writer, &source, new, Style::new().red().bold())?;

    // Print the expected range
    writeln!(&mut writer, "{}: Previous occurrence:", style("note").cyan().bold())?;
    ewrite_range(&mut writer, source, existing, Style::new().cyan().bold())?;
    writeln!(&mut writer)?;

    // Done
    Ok(())
}

/// Prettyprints an error with somewhere between zero and many reasons for this happening.
///
/// # Arguments
/// - `writer`: The [`Write`]-enabled stream to write to.
/// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
/// - `source`: The source text to extract the line from.
/// - `err`: The Error to print.
/// - `range`: The range that indicates the error itself.
/// - `reasons`: Zero or more ranges that indicates the sources.
///
/// # Errors
/// This function may error if we failed to write to the given writer.
fn prettywrite_err_reasons(
    mut writer: impl Write,
    file: impl AsRef<str>,
    source: impl AsRef<str>,
    err: &dyn Error,
    range: &TextRange,
    reasons: &[TextRange],
) -> Result<(), std::io::Error> {
    // Print the top line
    writeln!(
        &mut writer,
        "{}: {}: {}",
        style(format!("{}:{}:{}", file.as_ref(), n!(range.start.line), n!(range.start.col))).bold(),
        style("error").red().bold(),
        err
    )?;

    // Print the normal range
    ewrite_range(&mut writer, &source, range, Style::new().red().bold())?;

    // Print the expected ranges
    for r in reasons {
        writeln!(&mut writer, "{}: Error occurred because of:", style("note").cyan().bold())?;
        ewrite_range(&mut writer, &source, r, Style::new().cyan().bold())?;
        writeln!(&mut writer)?;
    }

    // Done
    Ok(())
}





/***** ERRORS *****/
/// Defines toplevel errors that occur in this crate.
#[derive(Debug)]
pub enum AstError {
    // Toplevel errors
    /// We could not read from the given parser.
    ReaderReadError { err: std::io::Error },
    /// The parser failed.
    ParseError { err: brane_dsl::Error },
    /// Failed to write to the given writer.
    WriteError { err: std::io::Error },

    // Nested errors
    /// An error has occurred while resolving enum variants.
    SanityError(SanityError),
    /// An error has occurred while resolving variable scopes.
    ResolveError(ResolveError),
    /// An error has occurred during type checking.
    TypeError(TypeError),
    /// An error has occurred during null-analysis.
    NullError(NullError),
    /// An error has occurred during location analysis.
    LocationError(LocationError),
    /// An error has occurred while pruning the tree for compilation.
    PruneError(PruneError),
    /// An error has occurred while flattening the AST's symbol tables.
    FlattenError(FlattenError),
}

impl AstError {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    #[inline]
    pub fn prettyprint(&self, file: impl AsRef<str>, source: impl AsRef<str>) { self.prettywrite(std::io::stderr(), file, source).unwrap() }

    /// Prints the warning in a pretty way to the given [`Write`]r.
    ///
    /// # Arguments:
    /// - `writer`: The [`Write`]-enabled object to write to.
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Errors
    /// This function may error if we failed to write to the given writer.
    #[inline]
    pub fn prettywrite(&self, mut writer: impl Write, file: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), std::io::Error> {
        use AstError::*;
        match self {
            ReaderReadError { .. } => {
                writeln!(writer, "{self}")
            },
            ParseError { .. } => {
                writeln!(writer, "{self}")
            },
            WriteError { .. } => {
                writeln!(writer, "{self}")
            },

            SanityError(err) => err.prettywrite(writer, file, source),
            ResolveError(err) => err.prettywrite(writer, file, source),
            TypeError(err) => err.prettywrite(writer, file, source),
            NullError(err) => err.prettywrite(writer, file, source),
            LocationError(err) => err.prettywrite(writer, file, source),
            PruneError(err) => err.prettywrite(writer, file, source),
            FlattenError(err) => err.prettywrite(writer, file, source),
        }
    }
}

impl From<SanityError> for AstError {
    #[inline]
    fn from(err: SanityError) -> Self { Self::SanityError(err) }
}
impl From<ResolveError> for AstError {
    #[inline]
    fn from(err: ResolveError) -> Self { Self::ResolveError(err) }
}
impl From<TypeError> for AstError {
    #[inline]
    fn from(err: TypeError) -> Self { Self::TypeError(err) }
}
impl From<NullError> for AstError {
    #[inline]
    fn from(err: NullError) -> Self { Self::NullError(err) }
}
impl From<LocationError> for AstError {
    #[inline]
    fn from(err: LocationError) -> Self { Self::LocationError(err) }
}
impl From<PruneError> for AstError {
    #[inline]
    fn from(err: PruneError) -> Self { Self::PruneError(err) }
}
impl From<FlattenError> for AstError {
    #[inline]
    fn from(err: FlattenError) -> Self { Self::FlattenError(err) }
}

impl Display for AstError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AstError::*;
        match self {
            ReaderReadError { err } => write!(f, "Failed to read given reader: {err}"),
            ParseError { err } => write!(f, "{err}"),
            WriteError { err } => write!(f, "Failed to write to given writer: {err}"),

            SanityError(err) => write!(f, "{err}"),
            ResolveError(err) => write!(f, "{err}"),
            TypeError(err) => write!(f, "{err}"),
            NullError(err) => write!(f, "{err}"),
            LocationError(err) => write!(f, "{err}"),
            PruneError(err) => write!(f, "{err}"),
            FlattenError(err) => write!(f, "{err}"),
        }
    }
}

impl Error for AstError {}



/// Defines errors that relate to wrong usage of variants.
#[derive(Debug)]
pub enum SanityError {
    /// Used a projection operator where the user shouldn't have.
    ProjError { what: &'static str, raw: String, range: TextRange },
}

impl SanityError {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    #[inline]
    pub fn prettyprint(&self, file: impl AsRef<str>, source: impl AsRef<str>) { self.prettywrite(std::io::stderr(), file, source).unwrap() }

    /// Prints the warning in a pretty way to the given [`Write`]r.
    ///
    /// # Arguments:
    /// - `writer`: The [`Write`]-enabled object to write to.
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Errors
    /// This function may error if we failed to write to the given writer.
    #[inline]
    pub fn prettywrite(&self, writer: impl Write, file: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), std::io::Error> {
        use SanityError::*;
        match self {
            ProjError { range, .. } => prettywrite_err(writer, file, source, self, range),
        }
    }
}

impl Display for SanityError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use SanityError::*;
        match self {
            ProjError { what, raw, .. } => write!(f, "Illegal {what} '{raw}'"),
        }
    }
}

impl Error for SanityError {}



/// Defines errors that occur while building symbol tables.
#[derive(Debug)]
pub enum ResolveError {
    /// Failed to parse a package version number.
    VersionParseError { err: specifications::version::ParseError, range: TextRange },
    /// The given package/version pair was not found.
    UnknownPackageError { name: String, version: Version, range: TextRange },
    /// Failed to declare an imported package function
    FunctionImportError { package_name: String, name: String, err: brane_dsl::errors::SymbolTableError, range: TextRange },
    /// Failed to declare an imported package class
    ClassImportError { package_name: String, name: String, err: brane_dsl::errors::SymbolTableError, range: TextRange },

    /// Failed to declare a new function.
    FunctionDefineError { name: String, err: brane_dsl::errors::SymbolTableError, range: TextRange },
    /// Failed to declare a new parameter for a function.
    ParameterDefineError { func_name: String, name: String, err: brane_dsl::errors::SymbolTableError, range: TextRange },

    /// Failed to declare a new class.
    ClassDefineError { name: String, err: brane_dsl::errors::SymbolTableError, range: TextRange },
    /// The given class was not declared before.
    UndefinedClass { ident: String, range: TextRange },
    /// A method has the same name as a property in this class.
    DuplicateMethodAndProperty { c_name: String, name: String, new_range: TextRange, existing_range: TextRange },
    /// A method haf a 'self' parameter but in an incorrect position.
    IllegalSelf { c_name: String, name: String, arg: usize, range: TextRange },
    /// A method did not have a 'self' parameter.
    MissingSelf { c_name: String, name: String, range: TextRange },

    /// Failed to parse the merge strategy.
    UnknownMergeStrategy { raw: String, range: TextRange },
    /// Failed to declare a new variable.
    VariableDefineError { name: String, err: brane_dsl::errors::SymbolTableError, range: TextRange },

    /// The given function was not declared before.
    UndefinedFunction { ident: String, range: TextRange },
    /// A `commit_result()` did not have a string literal as 'name' field.
    CommitResultIncorrectExpr { range: TextRange },

    /// A project operator was used on a non-class type.
    NonClassProjection { name: String, got: DataType, range: TextRange },
    /// The given field is not known in the given class.
    UnknownField { class_name: String, name: String, range: TextRange },

    /// A data structure did not have a string literal as 'name' field.
    DataIncorrectExpr { range: TextRange },
    /// An unknown dataset was references.
    UnknownDataError { name: String, range: TextRange },

    /// The given variable was not declared before.
    UndefinedVariable { ident: String, range: TextRange },
}

impl ResolveError {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    #[inline]
    pub fn prettyprint(&self, file: impl AsRef<str>, source: impl AsRef<str>) { self.prettywrite(std::io::stderr(), file, source).unwrap() }

    /// Prints the warning in a pretty way to the given [`Write`]r.
    ///
    /// # Arguments:
    /// - `writer`: The [`Write`]-enabled object to write to.
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Errors
    /// This function may error if we failed to write to the given writer.
    pub fn prettywrite(&self, writer: impl Write, file: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), std::io::Error> {
        use ResolveError::*;
        match self {
            VersionParseError { range, .. } => prettywrite_err(writer, file, source, self, range),
            UnknownPackageError { range, .. } => prettywrite_err(writer, file, source, self, range),
            FunctionImportError { range, .. } => prettywrite_err(writer, file, source, self, range),
            ClassImportError { range, .. } => prettywrite_err(writer, file, source, self, range),

            FunctionDefineError { range, .. } => prettywrite_err(writer, file, source, self, range),
            ParameterDefineError { range, .. } => prettywrite_err(writer, file, source, self, range),

            ClassDefineError { range, .. } => prettywrite_err(writer, file, source, self, range),
            UndefinedClass { range, .. } => prettywrite_err(writer, file, source, self, range),
            DuplicateMethodAndProperty { new_range, existing_range, .. } => {
                prettywrite_err_exist_new(writer, file, source, self, existing_range, new_range)
            },
            IllegalSelf { range, .. } => prettywrite_err(writer, file, source, self, range),
            MissingSelf { range, .. } => prettywrite_err(writer, file, source, self, range),

            UnknownMergeStrategy { range, .. } => prettywrite_err(writer, file, source, self, range),
            VariableDefineError { range, .. } => prettywrite_err(writer, file, source, self, range),

            UndefinedFunction { range, .. } => prettywrite_err(writer, file, source, self, range),
            CommitResultIncorrectExpr { range, .. } => prettywrite_err(writer, file, source, self, range),

            NonClassProjection { range, .. } => prettywrite_err(writer, file, source, self, range),
            UnknownField { range, .. } => prettywrite_err(writer, file, source, self, range),

            DataIncorrectExpr { range, .. } => prettywrite_err(writer, file, source, self, range),
            UnknownDataError { range, .. } => prettywrite_err(writer, file, source, self, range),

            UndefinedVariable { range, .. } => prettywrite_err(writer, file, source, self, range),
        }
    }
}

impl Display for ResolveError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ResolveError::*;
        match self {
            VersionParseError { err, .. } => write!(f, "Failed to parse package version: {err}"),
            UnknownPackageError { name, version, .. } => write!(
                f,
                "Package '{}' does not exist{}",
                name,
                if !version.is_latest() { format!(" or has no version '{version}'") } else { String::new() }
            ),
            FunctionImportError { package_name, name, err, .. } => {
                write!(f, "Could not import function '{name}' from package '{package_name}': {err}")
            },
            ClassImportError { package_name, name, err, .. } => write!(f, "Could not import class '{name}' from package '{package_name}': {err}"),

            FunctionDefineError { name, err, .. } => write!(f, "Could not define function '{name}': {err}"),
            ParameterDefineError { func_name, name, err, .. } => write!(f, "Could not define parmater '{name}' of function '{func_name}': {err}"),

            ClassDefineError { name, err, .. } => write!(f, "Could not define class '{name}': {err}"),
            UndefinedClass { ident, .. } => write!(f, "Undefined class or type '{ident}'"),
            DuplicateMethodAndProperty { c_name, name, .. } => {
                write!(f, "'{name}' refers to both a name and a property in class {c_name} (make sure all names are unique)")
            },
            IllegalSelf { arg, .. } => write!(f, "'self' can only be first parameter of method, not at position {arg}"),
            MissingSelf { c_name, name, .. } => write!(f, "Missing 'self' parameter as first parameter in method '{name}' in class {c_name}"),

            UnknownMergeStrategy { raw, .. } => write!(f, "Unknown merge strategy '{raw}'"),
            VariableDefineError { name, err, .. } => write!(f, "Could not define variable '{name}': {err}"),

            UndefinedFunction { ident, .. } => write!(f, "Undefined function or method '{ident}'"),
            CommitResultIncorrectExpr { .. } => write!(f, "Builtin function 'commit_result()' can only accept string literals as data name"),

            NonClassProjection { name, got, .. } => write!(f, "Cannot access field '{name}' of non-class type {got}"),
            UnknownField { class_name, name, .. } => write!(f, "Class '{class_name}' has no field '{name}'"),

            DataIncorrectExpr { .. } => write!(f, "Data class can only take String literals as name"),
            UnknownDataError { name, .. } => write!(f, "No location has access to data asset '{name}'"),

            UndefinedVariable { ident, .. } => write!(f, "Undefined variable or parameter '{ident}'"),
        }
    }
}

impl Error for ResolveError {}



/// Defines errors that occur during type checking.
#[derive(Debug)]
pub enum TypeError {
    /// The projection operator was used on a non-class variable.
    ProjOnNonClassError { got: DataType, range: TextRange },
    /// A method was used as if it was a field.
    UnexpectedMethod { class_name: String, name: String, range: TextRange },
    /// The given field is not known in the given class.
    UnknownField { class_name: String, name: String, range: TextRange },

    /// A type cannot be (implicitly) casted to another.
    IncorrectType { got: DataType, expected: DataType, range: TextRange },

    /// An imported function returned a Data, while it cannot do that anymore.
    IllegalDataReturnError { name: String, range: TextRange },

    /// The return statements of a function did not all return the same type.
    IncompatibleReturns { got: DataType, expected: DataType, got_range: TextRange, expected_range: TextRange },

    /// A block in a parallel statement did not return while it should have.
    ParallelNoReturn { block: usize, range: TextRange },
    /// A block in a parallel statement did return while it should not have.
    ParallelUnexpectedReturn { block: usize, got: DataType, range: TextRange },
    /// Not all blocks in a parallel statement return a non-void value.
    ParallelIncompleteReturn { block: usize, expected: DataType, range: TextRange },
    /// The parallel returned the wrong value for the merge strategy
    ParallelIllegalType { merge: MergeStrategy, got: DataType, expected: Vec<DataType>, range: TextRange, reason: TextRange },
    /// The parallel returns a value but the merge is None
    ParallelNoStrategy { range: TextRange },

    /// A function call has been attempted on a non-function.
    NonFunctionCall { got: DataType, range: TextRange, defined_range: TextRange },
    /// The function identifier was not known.
    UndefinedFunctionCall { name: String, range: TextRange },
    /// A function was given an incorrect number of parameters.
    FunctionArityError { name: String, got: usize, expected: usize, got_range: TextRange, expected_range: TextRange },

    /// An Array had confusing types
    InconsistentArrayError { got: DataType, expected: DataType, got_range: TextRange, expected_range: TextRange },

    /// An Array Index was used on a non-array.
    NonArrayIndexError { got: DataType, range: TextRange },

    /// The user specified something else as a Data than a literal string.
    DataNameNotAStringError { name: String, got: Box<Expr>, range: TextRange },
    /// The user did not specify a name field in a Data or IntermediateResult field.
    DataNoNamePropertyError { name: String, range: TextRange },
}

impl TypeError {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    #[inline]
    pub fn prettyprint(&self, file: impl AsRef<str>, source: impl AsRef<str>) { self.prettywrite(std::io::stderr(), file, source).unwrap() }

    /// Prints the warning in a pretty way to the given [`Write`]r.
    ///
    /// # Arguments:
    /// - `writer`: The [`Write`]-enabled object to write to.
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Errors
    /// This function may error if we failed to write to the given writer.
    pub fn prettywrite(&self, writer: impl Write, file: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), std::io::Error> {
        use TypeError::*;
        match self {
            ProjOnNonClassError { range, .. } => prettywrite_err(writer, file, source, self, range),
            UnexpectedMethod { range, .. } => prettywrite_err(writer, file, source, self, range),
            UnknownField { range, .. } => prettywrite_err(writer, file, source, self, range),

            IncorrectType { range, .. } => prettywrite_err(writer, file, source, self, range),

            IllegalDataReturnError { range, .. } => prettywrite_err(writer, file, source, self, range),

            IncompatibleReturns { got_range, expected_range, .. } => prettywrite_err_exp_got(writer, file, source, self, expected_range, got_range),

            ParallelNoReturn { range, .. } => prettywrite_err(writer, file, source, self, range),
            ParallelUnexpectedReturn { range, .. } => prettywrite_err(writer, file, source, self, range),
            ParallelIncompleteReturn { range, .. } => prettywrite_err(writer, file, source, self, range),
            ParallelIllegalType { range, reason, .. } => prettywrite_err_reasons(writer, file, source, self, range, &[reason.clone()]),
            ParallelNoStrategy { range, .. } => prettywrite_err(writer, file, source, self, range),

            NonFunctionCall { range, defined_range, .. } => prettywrite_err_defined(writer, file, source, self, range, defined_range),
            UndefinedFunctionCall { range, .. } => prettywrite_err(writer, file, source, self, range),
            FunctionArityError { got_range, expected_range, .. } => prettywrite_err_exp_got(writer, file, source, self, expected_range, got_range),

            InconsistentArrayError { got_range, expected_range, .. } => {
                prettywrite_err_exp_got(writer, file, source, self, expected_range, got_range)
            },

            NonArrayIndexError { range, .. } => prettywrite_err(writer, file, source, self, range),

            DataNameNotAStringError { range, .. } => prettywrite_err(writer, file, source, self, range),
            DataNoNamePropertyError { range, .. } => prettywrite_err(writer, file, source, self, range),
        }
    }
}

impl Display for TypeError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use TypeError::*;
        match self {
            ProjOnNonClassError { got, .. } => write!(f, "Cannot use projection (.) on non-Class type {got}"),
            UnexpectedMethod { name, .. } => write!(f, "Cannot use method '{name}' as property"),
            UnknownField { class_name, name, .. } => write!(f, "Class '{class_name}' has no field '{name}'"),

            IncorrectType { got, expected, .. } => write!(f, "Expected a {expected}, got {got}"),

            IllegalDataReturnError { name, .. } => write!(
                f,
                "Function '{}' returns a {}, whereas this is illegal (use an {} instead)",
                name,
                BuiltinClasses::Data.name(),
                BuiltinClasses::IntermediateResult.name()
            ),

            IncompatibleReturns { got, expected, .. } => {
                write!(f, "Not all return paths return the same value: the first returns {expected}, this returns {got}")
            },

            ParallelNoReturn { block, .. } => write!(f, "Block {block} in parallel statement does not return while it should"),
            ParallelUnexpectedReturn { block, got, .. } => {
                write!(f, "Block {block} in parallel statement does returns a value of type {got} while it should not return")
            },
            ParallelIncompleteReturn { block, expected, .. } => {
                write!(f, "Block {block} in parallel statement does not return a value of type {expected} while it should")
            },
            ParallelIllegalType { merge, got, expected, .. } => write!(
                f,
                "Using '{:?}' merge strategy requires parallel branches to return values of type {}, but got {}",
                merge,
                prettyprint_list(expected, "or"),
                got
            ),
            ParallelNoStrategy { .. } => write!(f, "Specify a merge strategy that returns a value if you intend to store the value"),

            NonFunctionCall { got, .. } => write!(f, "Cannot call object of type {got}"),
            UndefinedFunctionCall { name, .. } => write!(f, "Undefined function '{name}'"),
            FunctionArityError { name, got, expected, .. } => write!(f, "Function '{name}' expected {expected} arguments, but {got} were given"),

            InconsistentArrayError { got, expected, .. } => {
                write!(f, "Array expression has conflicting type requirements: started out as {expected}, got {got}")
            },

            NonArrayIndexError { got, .. } => write!(f, "Cannot index non-Array type {got}"),

            DataNameNotAStringError { name, got, .. } => {
                write!(f, "Expected class {name} to have a `name` property with a literal string, got {got:?}")
            },
            DataNoNamePropertyError { name, .. } => write!(f, "Missing `name` property for class {name}"),
        }
    }
}

impl Error for TypeError {}



/// Defines errors that occur while resolving null-usage.
#[derive(Debug)]
pub enum NullError {
    /// We found a Null used in an illegal spot.
    IllegalNull { range: TextRange },
}

impl NullError {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    #[inline]
    pub fn prettyprint(&self, file: impl AsRef<str>, source: impl AsRef<str>) { self.prettywrite(std::io::stderr(), file, source).unwrap() }

    /// Prints the warning in a pretty way to the given [`Write`]r.
    ///
    /// # Arguments:
    /// - `writer`: The [`Write`]-enabled object to write to.
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Errors
    /// This function may error if we failed to write to the given writer.
    pub fn prettywrite(&self, writer: impl Write, file: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), std::io::Error> {
        use NullError::*;
        match self {
            IllegalNull { range } => prettywrite_err(writer, file, source, self, range),
        }
    }
}

impl Display for NullError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use NullError::*;
        match self {
            IllegalNull { .. } => write!(f, "You can only use 'null' to initialize a new variable"),
        }
    }
}

impl Error for NullError {}



/// Defines errors that occur during location resolving.
#[derive(Debug)]
pub enum LocationError {
    /// A location was not a literal string.
    IllegalLocation { range: TextRange },
    /// An On-structure combination already limited the locations too much.
    OnNoLocation { range: TextRange, reasons: Vec<TextRange> },

    /// The usage of On-structures and/or annotations caused a function to never-ever be able to run.
    NoLocation { range: TextRange, reasons: Vec<TextRange> },
}

impl LocationError {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    #[inline]
    pub fn prettyprint(&self, file: impl AsRef<str>, source: impl AsRef<str>) { self.prettywrite(std::io::stderr(), file, source).unwrap() }

    /// Prints the warning in a pretty way to the given [`Write`]r.
    ///
    /// # Arguments:
    /// - `writer`: The [`Write`]-enabled object to write to.
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Errors
    /// This function may error if we failed to write to the given writer.
    pub fn prettywrite(&self, writer: impl Write, file: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), std::io::Error> {
        use LocationError::*;
        match self {
            IllegalLocation { range, .. } => prettywrite_err(writer, file, source, self, range),
            OnNoLocation { range, reasons, .. } => prettywrite_err_reasons(writer, file, source, self, range, reasons),

            NoLocation { range, reasons, .. } => prettywrite_err_reasons(writer, file, source, self, range, reasons),
        }
    }
}

impl Display for LocationError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use LocationError::*;
        match self {
            IllegalLocation { .. } => write!(f, "On-structures can only accept string literals as location specifiers."),
            OnNoLocation { .. } => write!(f, "Combination of attributes already over-restrict locations (no location left to run any calls)."),

            NoLocation { .. } => write!(f, "External function call is over-restricted and has no locations left to run."),
        }
    }
}

impl Error for LocationError {}



/// Defines errors that occur during type checking.
#[derive(Debug)]
pub enum PruneError {
    /// Missing a return statement
    MissingReturn { expected: DataType, range: TextRange },
}

impl PruneError {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    #[inline]
    pub fn prettyprint(&self, file: impl AsRef<str>, source: impl AsRef<str>) { self.prettywrite(std::io::stderr(), file, source).unwrap() }

    /// Prints the warning in a pretty way to the given [`Write`]r.
    ///
    /// # Arguments:
    /// - `writer`: The [`Write`]-enabled object to write to.
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Errors
    /// This function may error if we failed to write to the given writer.
    pub fn prettywrite(&self, writer: impl Write, file: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), std::io::Error> {
        use PruneError::*;
        match self {
            MissingReturn { range, .. } => prettywrite_err(writer, file, source, self, range),
        }
    }
}

impl Display for PruneError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use PruneError::*;
        match self {
            MissingReturn { expected, .. } => write!(f, "Missing return statement of type {expected}"),
        }
    }
}

impl Error for PruneError {}



/// Defines errors that occur during the flatten traversal.
#[derive(Debug)]
pub enum FlattenError {
    /// There was a name conflict between intermediate results
    IntermediateResultConflict { name: String },
}

impl FlattenError {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    #[inline]
    pub fn prettyprint(&self, file: impl AsRef<str>, source: impl AsRef<str>) { self.prettywrite(std::io::stderr(), file, source).unwrap() }

    /// Prints the warning in a pretty way to the given [`Write`]r.
    ///
    /// # Arguments:
    /// - `writer`: The [`Write`]-enabled object to write to.
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Errors
    /// This function may error if we failed to write to the given writer.
    pub fn prettywrite(&self, writer: impl Write, file: impl AsRef<str>, source: impl AsRef<str>) -> Result<(), std::io::Error> {
        use FlattenError::*;
        match self {
            IntermediateResultConflict { .. } => prettywrite_err(writer, file, source, self, &TextRange::none()),
        }
    }
}

impl Display for FlattenError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use FlattenError::*;
        match self {
            IntermediateResultConflict { name } => write!(
                f,
                "Conflicting generated identifiers for intermediate results ('{name}'). This is a very unlikely event, and probably solved by \
                 simply trying again."
            ),
        }
    }
}

impl Error for FlattenError {}
