//  BUILTINS.rs
//    by Lut99
//
//  Created:
//    14 Nov 2024, 15:46:16
//  Last edited:
//    14 Nov 2024, 17:30:04
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines builtin functions & classes in the WIR.
//

use strum::IntoEnumIterator as _;

use super::data_type::DataType;


/***** LIBRARY *****/
/// Defines the builtin functions that exist in BraneScript.
#[derive(Clone, Copy, Debug, strum_macros::EnumIter)]
pub enum BuiltinFunctions {
    /// The print-function, which prints some text to stdout.
    Print,
    /// The println-function, which does the same as `Print` but now with a newline appended to the text.
    PrintLn,

    /// The len-function, which returns the length of an array.
    Len,

    /// The commit_builtin-function, which turns an IntermediateResult into a Data.
    CommitResult,
}

impl BuiltinFunctions {
    /// Returns the identifier of this builtin function.
    #[inline]
    pub fn name(&self) -> &'static str {
        use BuiltinFunctions::*;
        match self {
            Print => "print",
            PrintLn => "println",

            Len => "len",

            CommitResult => "commit_result",
        }
    }

    /// Checks if the given string is a builtin.
    #[inline]
    pub fn is_builtin(name: impl AsRef<str>) -> bool { name.as_ref().parse::<Self>().is_ok() }
}

impl std::str::FromStr for BuiltinFunctions {
    type Err = ParseBuiltinFunctionsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for builtin in Self::iter() {
            if s == builtin.name() {
                return Ok(builtin);
            }
        }
        Err(ParseBuiltinFunctionsError { provided: s.into() })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("provided string: {provided} is not a built-in")]
pub struct ParseBuiltinFunctionsError {
    pub provided: String,
}


/// Defines the builtin classes that exist in BraneScript.
#[derive(Clone, Copy, Debug, strum_macros::EnumIter)]
pub enum BuiltinClasses {
    /// The data-class.
    Data,
    /// The intermediate-result-class.
    IntermediateResult,
}

impl BuiltinClasses {
    /// Returns the identifier of this builtin class.
    #[inline]
    pub fn name(&self) -> &'static str {
        use BuiltinClasses::*;
        match self {
            Data => "Data",
            IntermediateResult => "IntermediateResult",
        }
    }

    /// Defines the fields of this class.
    ///
    /// # Returns
    /// A list of pairs of the name and the [`DataType`] of that field.
    #[inline]
    pub fn props(&self) -> &'static [(&'static str, DataType)] {
        match self {
            Self::Data => &[("name", DataType::String)],
            Self::IntermediateResult => &[("path", DataType::String)],
        }
    }

    /// Defines the methods of this class.
    ///
    /// # Returns
    /// A list of pairs of the name and a pair with the arguments and return type of that method.
    #[inline]
    pub fn methods(&self) -> &'static [(&'static str, (Vec<DataType>, DataType))] {
        match self {
            Self::Data => &[],
            Self::IntermediateResult => &[],
        }
    }
}
