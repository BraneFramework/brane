//  WARNINGS.rs
//    by Lut99
// 
//  Created:
//    05 Sep 2022, 16:08:42
//  Last edited:
//    20 Oct 2022, 15:29:41
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines warnings for the different compiler stages.
// 

use std::fmt::{Debug, Display, Formatter, Result as FResult};

use console::{style, Style};

use brane_dsl::TextRange;
use brane_dsl::spec::MergeStrategy;

use crate::errors::{n, eprint_range};
use crate::spec::BuiltinClasses;


/***** HELPER FUNCTIONS *****/
/// Prettyprints a warning with only one 'reason'.
/// 
/// # Generic arguments
/// - `S1`: The &str-like type of the `file` path.
/// - `S2`: The &str-like type of the `source` text.
/// 
/// # Arguments
/// - `source`: The source text to extract the line from.
/// - `warn`: The Warning to print.
/// - `range`: The range of the warning.
/// 
/// # Returns
/// Nothing, but does print the warning to stderr.
pub(crate) fn prettyprint_warn<S1: AsRef<str>, S2: AsRef<str>>(file: S1, source: S2, err: &dyn Display, range: &TextRange) {
    // Print the top line
    eprintln!("{}: {}: {}", style(format!("{}:{}:{}", file.as_ref(), n!(range.start.line), n!(range.start.col))).bold(), style("warning").yellow().bold(), err);

    // Print the range
    eprint_range(source, range, Style::new().yellow().bold());
    eprintln!();

    // Done
}





/***** AUXILLARY *****/
/// A warning trait much like the Error trait.
pub trait Warning: Debug + Display {}





/***** LIBRARY *****/
// Defines toplevel warnings that occur in this crate.
#[derive(Debug)]
pub enum AstWarning {
    /// An warning has occurred while analysing types.
    TypeWarning(TypeWarning),
    /// An warning has occurred while doing the actual compiling.
    CompileWarning(CompileWarning),
}

impl AstWarning {
    /// Prints the warning in a pretty way to stderr.
    /// 
    /// # Generic arguments:
    /// - `S1`: The &str-like type of the `file` path.
    /// - `S2`: The &str-like type of the `source` text.
    /// 
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    /// 
    /// # Returns
    /// Nothing, but does print the warning to stderr.
    #[inline]
    pub fn prettyprint<S1: AsRef<str>, S2: AsRef<str>>(&self, file: S1, source: S2) {
        use AstWarning::*;
        match self {
            TypeWarning(warn)    => warn.prettyprint(file, source),
            CompileWarning(warn) => warn.prettyprint(file, source),
        }
    }
}

impl From<TypeWarning> for AstWarning {
    #[inline]
    fn from(warn: TypeWarning) -> Self {
        Self::TypeWarning(warn)
    }
}

impl From<CompileWarning> for AstWarning {
    #[inline]
    fn from(warn: CompileWarning) -> Self {
        Self::CompileWarning(warn)
    }
}

impl Display for AstWarning {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use AstWarning::*;
        match self {
            TypeWarning(warn)    => write!(f, "{warn}"),
            CompileWarning(warn) => write!(f, "{warn}"),
        }
    }
}

impl Warning for AstWarning {}



/// Defines warnings that may occur during compilation.
#[derive(Debug)]
pub enum TypeWarning {
    /// A merge strategy was specified but the result not stored.
    UnusedMergeStrategy{ merge: MergeStrategy, range: TextRange },

    /// The user is returning an IntermediateResult.
    ReturningIntermediateResult{ range: TextRange },
}

impl TypeWarning {
    /// Prints the warning in a pretty way to stderr.
    /// 
    /// # Generic arguments:
    /// - `S1`: The &str-like type of the `file` path.
    /// - `S2`: The &str-like type of the `source` text.
    /// 
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    /// 
    /// # Returns
    /// Nothing, but does print the warning to stderr.
    #[inline]
    pub fn prettyprint<S1: AsRef<str>, S2: AsRef<str>>(&self, file: S1, source: S2) {
        use TypeWarning::*;
        match self {
            UnusedMergeStrategy{ range, .. } => prettyprint_warn(file, source, self, range),

            ReturningIntermediateResult{ range, .. } => prettyprint_warn(file, source, self, range),
        }
    }
}

impl Display for TypeWarning {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use TypeWarning::*;
        match self {
            UnusedMergeStrategy{ merge, .. } => write!(f, "Merge strategy '{merge:?}' specified but not used; did you forget 'let <var> := parallel ...'?"),

            ReturningIntermediateResult{ .. } => write!(f, "Returning an {} will not let you see the result; consider committing using the builtin `commit_result()` function", BuiltinClasses::IntermediateResult.name()),
        }
    }
}

impl Warning for TypeWarning {}



/// Defines warnings that may occur during compilation.
#[derive(Debug)]
pub enum CompileWarning {
    /// An On-struct was used, which is now deprecated.
    OnDeprecated{ range: TextRange },
}

impl CompileWarning {
    /// Prints the warning in a pretty way to stderr.
    /// 
    /// # Generic arguments:
    /// - `S1`: The &str-like type of the `file` path.
    /// - `S2`: The &str-like type of the `source` text.
    /// 
    /// # Arguments
    /// - `file`: The 'path' of the file (or some other identifier) where the source text originates from.
    /// - `source`: The source text to read the debug range from.
    /// 
    /// # Returns
    /// Nothing, but does print the warning to stderr.
    #[inline]
    pub fn prettyprint<S1: AsRef<str>, S2: AsRef<str>>(&self, file: S1, source: S2) {
        use CompileWarning::*;
        match self {
            OnDeprecated{ range, .. } => prettyprint_warn(file, source, self, range),
        }
    }
}

impl Display for CompileWarning {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use CompileWarning::*;
        match self {
            OnDeprecated{ .. } => write!(f, "'On'-structures are deprecated; they will be removed in a future release. Use location annotations instead."),
        }
    }
}

impl Warning for CompileWarning {}
