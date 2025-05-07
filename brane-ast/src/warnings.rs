//  WARNINGS.rs
//    by Lut99
//
//  Created:
//    05 Sep 2022, 16:08:42
//  Last edited:
//    14 Nov 2024, 17:14:53
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines warnings for the different compiler stages.
//

use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::io::Write;

use brane_dsl::TextRange;
use console::{Style, style};
use specifications::wir::builtins::BuiltinClasses;
use specifications::wir::merge_strategy::MergeStrategy;

use crate::errors::{ewrite_range, n};


/***** HELPER FUNCTIONS *****/
/// Prettyprints a warning with only one 'reason' to the given [`Write`]r.
///
/// # Arguments
/// - `writer`: The [`Write`]-enabled object to write the serialized warning to.
/// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
/// - `source`: The source text to extract the line from.
/// - `warn`: The Warning to print.
/// - `range`: The range of the warning.
///
/// # Errors
/// This function may error if we failed to write to the given writer.
pub(crate) fn prettywrite_warn(
    mut writer: impl Write,
    file: impl AsRef<str>,
    source: impl AsRef<str>,
    warn: &dyn Display,
    range: &TextRange,
) -> Result<(), std::io::Error> {
    // Print the top line
    writeln!(
        &mut writer,
        "{}: {}: {}",
        style(format!("{}:{}:{}", file.as_ref(), n!(range.start.line), n!(range.start.col))).bold(),
        style("warning").yellow().bold(),
        warn
    )?;

    // Print the range
    ewrite_range(&mut writer, source, range, Style::new().yellow().bold())?;
    writeln!(&mut writer)?;

    // Done
    Ok(())
}

/// Prettyprints an warning with only one 'existing' value or type and one 'new' value or type.
///
/// # Arguments
/// - `writer`: The [`Write`]-enabled stream to write to.
/// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
/// - `source`: The source text to extract the line from.
/// - `warn`: The Warning to print.
/// - `existing`: The range that indicates the existing value or type.
/// - `new`: The range that indicates the new value or type.
///
/// # Errors
/// This function may error if we failed to write to the given writer.
fn prettywrite_warn_exist_new(
    mut writer: impl Write,
    file: impl AsRef<str>,
    source: impl AsRef<str>,
    err: &dyn Warning,
    existing: &TextRange,
    new: &TextRange,
) -> Result<(), std::io::Error> {
    // Print the top line
    writeln!(
        &mut writer,
        "{}: {}: {}",
        style(format!("{}:{}:{}", file.as_ref(), n!(new.start.line), n!(new.start.col))).bold(),
        style("warning").yellow().bold(),
        err
    )?;

    // Print the normal range
    ewrite_range(&mut writer, &source, new, Style::new().yellow().bold())?;

    // Print the expected range
    writeln!(&mut writer, "{}: Previous occurrence:", style("note").cyan().bold())?;
    ewrite_range(&mut writer, source, existing, Style::new().cyan().bold())?;
    writeln!(&mut writer)?;

    // Done
    Ok(())
}





/***** AUXILLARY *****/
/// A warning trait much like the Error trait.
pub trait Warning: Debug + Display {}





/***** LIBRARY *****/
// Defines toplevel warnings that occur in this crate.
#[derive(Debug)]
pub enum AstWarning {
    /// An warning has occurred while processing attributes.
    AttributesWarning(AttributesWarning),
    /// An warning has occurred while analysing types.
    TypeWarning(TypeWarning),
    /// An warning has occurred while processing tags/metadata.
    MetadataWarning(MetadataWarning),
    /// An warning has occurred while doing the actual compiling.
    CompileWarning(CompileWarning),
}

impl AstWarning {
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
        use AstWarning::*;
        match self {
            AttributesWarning(warn) => warn.prettywrite(writer, file, source),
            TypeWarning(warn) => warn.prettywrite(writer, file, source),
            MetadataWarning(warn) => warn.prettywrite(writer, file, source),
            CompileWarning(warn) => warn.prettywrite(writer, file, source),
        }
    }
}

impl From<AttributesWarning> for AstWarning {
    #[inline]
    fn from(warn: AttributesWarning) -> Self { Self::AttributesWarning(warn) }
}

impl From<TypeWarning> for AstWarning {
    #[inline]
    fn from(warn: TypeWarning) -> Self { Self::TypeWarning(warn) }
}

impl From<MetadataWarning> for AstWarning {
    #[inline]
    fn from(warn: MetadataWarning) -> Self { Self::MetadataWarning(warn) }
}

impl From<CompileWarning> for AstWarning {
    #[inline]
    fn from(warn: CompileWarning) -> Self { Self::CompileWarning(warn) }
}

impl Display for AstWarning {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AstWarning::*;
        match self {
            AttributesWarning(warn) => write!(f, "{warn}"),
            TypeWarning(warn) => write!(f, "{warn}"),
            MetadataWarning(warn) => write!(f, "{warn}"),
            CompileWarning(warn) => write!(f, "{warn}"),
        }
    }
}

impl Warning for AstWarning {}



/// Defines warnings that may occur during attribute processing.
#[derive(Debug)]
pub enum AttributesWarning {
    /// An attribute was not matched with a statement.
    UnmatchedAttribute { range: TextRange },
}
impl AttributesWarning {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Returns
    /// Nothing, but does print the warning to stderr.
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
        use AttributesWarning::*;
        match self {
            UnmatchedAttribute { range } => prettywrite_warn(writer, file, source, self, range),
        }
    }
}
impl Display for AttributesWarning {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AttributesWarning::*;
        match self {
            UnmatchedAttribute { .. } => write!(f, "Attribute does not annotate anything"),
        }
    }
}
impl Warning for AttributesWarning {}



/// Defines warnings that may occur during compilation.
#[derive(Debug)]
pub enum TypeWarning {
    /// A merge strategy was specified but the result not stored.
    UnusedMergeStrategy { merge: MergeStrategy, range: TextRange },

    /// The user is returning an IntermediateResult.
    ReturningIntermediateResult { range: TextRange },
}

impl TypeWarning {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Returns
    /// Nothing, but does print the warning to stderr.
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
        use TypeWarning::*;
        match self {
            UnusedMergeStrategy { range, .. } => prettywrite_warn(writer, file, source, self, range),

            ReturningIntermediateResult { range, .. } => prettywrite_warn(writer, file, source, self, range),
        }
    }
}

impl Display for TypeWarning {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use TypeWarning::*;
        match self {
            UnusedMergeStrategy { merge, .. } => {
                write!(f, "Merge strategy '{merge:?}' specified but not used; did you forget 'let <var> := parallel ...'?")
            },

            ReturningIntermediateResult { .. } => write!(
                f,
                "Returning an {} will not let you see the result; consider committing using the builtin `commit_result()` function",
                BuiltinClasses::IntermediateResult.name()
            ),
        }
    }
}

impl Warning for TypeWarning {}



/// Defines warnings that may occur when processing metadata.
#[derive(Debug)]
pub enum MetadataWarning {
    /// A tag was applied more than once.
    DuplicateTag { prev: TextRange, range: TextRange },
    /// A tag was not a string.
    NonStringTag { range: TextRange },
    /// A metadata was found without separating dot (`.`)
    TagWithoutDot { raw: String, range: TextRange },
    /// A piece of metadata was applied (directly) to a statement that did not take it.
    UselessTag { range: TextRange },
}
impl MetadataWarning {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Returns
    /// Nothing, but does print the warning to stderr.
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
        use MetadataWarning::*;
        match self {
            DuplicateTag { prev, range } => prettywrite_warn_exist_new(writer, file, source, self, prev, range),
            NonStringTag { range } => prettywrite_warn(writer, file, source, self, range),
            TagWithoutDot { range, .. } => prettywrite_warn(writer, file, source, self, range),
            UselessTag { range } => prettywrite_warn(writer, file, source, self, range),
        }
    }
}
impl Display for MetadataWarning {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use MetadataWarning::*;
        match self {
            DuplicateTag { .. } => write!(f, "Duplicate application of the same tag"),
            NonStringTag { .. } => write!(f, "Tags must be string literals"),
            TagWithoutDot { raw, .. } => write!(f, "Missing dot in metadata '{raw}' to separate owner and tag"),
            UselessTag { .. } => write!(f, "Applying tag here has no effect (only has effect on entire workflow or external function calls)"),
        }
    }
}
impl Warning for MetadataWarning {}



/// Defines warnings that may occur during compilation.
#[derive(Debug)]
pub enum CompileWarning {
    /// An On-struct was used, which is now deprecated.
    OnDeprecated { range: TextRange },
}

impl CompileWarning {
    /// Prints the warning in a pretty way to stderr.
    ///
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    ///
    /// # Returns
    /// Nothing, but does print the warning to stderr.
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
        use CompileWarning::*;
        match self {
            OnDeprecated { range, .. } => prettywrite_warn(writer, file, source, self, range),
        }
    }
}

impl Display for CompileWarning {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use CompileWarning::*;
        match self {
            OnDeprecated { .. } => {
                write!(f, "'On'-structures are deprecated; they will be removed in a future release. Use location annotations instead.")
            },
        }
    }
}

impl Warning for CompileWarning {}
