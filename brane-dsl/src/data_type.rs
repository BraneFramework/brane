//  DATA TYPE.rs
//    by Lut99
//
//  Created:
//    23 Aug 2022, 20:34:33
//  Last edited:
//    14 Nov 2024, 17:09:58
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the possible data types in the BraneScript/Bakery AST.
//

use std::fmt::{Display, Formatter, Result as FResult};
use std::mem::discriminant;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use specifications::wir::builtins::{BuiltinClasses, BuiltinFunctions};


/***** LIBRARY *****/
/// Defines a Function's signature (i.e., unique type information).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FunctionSignature {
    /// The types (and number) of arguments.
    pub args: Vec<DataType>,
    /// The return type
    pub ret:  DataType,
}

impl FunctionSignature {
    /// Constructor for the FunctionSignature.
    ///
    /// # Arguments
    /// - `args_types`: The types of the arguments of the function. Also determines the number of them.
    /// - `return_type`: The return type of the function.
    ///
    /// # Returns
    /// A new FunctionSignature.
    #[inline]
    pub fn new(args_types: Vec<DataType>, return_type: DataType) -> Self { Self { args: args_types, ret: return_type } }
}

impl Default for FunctionSignature {
    #[inline]
    fn default() -> Self { Self { args: vec![], ret: DataType::Any } }
}

impl Display for FunctionSignature {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        write!(f, "({}) -> {}", self.args.iter().map(|d| format!("{d}")).collect::<Vec<String>>().join(", "), self.ret)
    }
}

impl From<BuiltinFunctions> for FunctionSignature {
    #[inline]
    fn from(value: BuiltinFunctions) -> Self { Self::from(&value) }
}
impl From<&BuiltinFunctions> for FunctionSignature {
    #[inline]
    fn from(value: &BuiltinFunctions) -> Self {
        match value {
            BuiltinFunctions::Print => Self::new(vec![DataType::String], DataType::Void),
            BuiltinFunctions::PrintLn => Self::new(vec![DataType::String], DataType::Void),

            BuiltinFunctions::Len => Self::new(vec![DataType::Array(Box::new(DataType::Any))], DataType::Integer),

            BuiltinFunctions::CommitResult => Self::new(
                vec![DataType::String, DataType::Class(BuiltinClasses::IntermediateResult.name().into())],
                DataType::Class(BuiltinClasses::Data.name().into()),
            ),
        }
    }
}



/// Defines a Class' signature (i.e., unique type information).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClassSignature {
    /// The name of the class (which is precisely all we need to uniquely identify the class and its type).
    pub name: String,
}

impl ClassSignature {
    /// Constructor for the ClassSignature.
    ///
    /// # Generic types
    /// - `S`: The String-like type of the class' `name`.
    ///
    /// # Arguments
    /// - `name`: The name of the class.
    ///
    /// # Returns
    /// A new ClassSignature.
    #[inline]
    pub fn new<S: Into<String>>(name: S) -> Self { Self { name: name.into() } }
}

impl Display for ClassSignature {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}{{}}", self.name) }
}





/// Defines the datatypes in the BraneScript/Bakery AST.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DataType {
    // Meta types
    /// The 'Any' type basically means 'resolve at runtime'.
    Any,
    /// The 'Void' type basically means 'no type / value'.
    Void,

    // Literals
    /// Boolean values (i.e., true or false, 1 or 0, yes or no, etc).
    Boolean,
    /// Integral values (i.e., non-decimal numbers)
    Integer,
    /// Real values (i.e., decimal numbers)
    Real,
    /// String values (i.e., arrays of characters)
    String,
    /// Semantic versioning (i.e., major.minor.patch)
    Semver,

    // Composite types (sorry Thomas)
    // /// References (i.e., types that live somewhere else)
    // Ref(Box<DataType>),
    /// Arrays (i.e., a memory area divided into homogeneous types)
    Array(Box<DataType>),
    /// Functions (i.e., executable pieces of code)
    Function(Box<FunctionSignature>),
    /// Classes (i.e., a memory area divided into heterogeneous types)
    Class(String),
}

impl DataType {
    /// Returns whether or not this DataType may be implicitly converted to the given one.
    ///
    /// # Generic arguments
    /// - `D`: The DataType-like type of `other`.
    ///
    /// # Arguments
    /// - `other`: The DataType to which we attempt to implicitly convert.
    ///
    /// # Returns
    /// True if it is convertible, false otherwise.
    #[inline]
    pub fn coercible_to<D: AsRef<DataType>>(&self, other: D) -> bool {
        // Compare as pairs
        use DataType::*;
        match (self, other.as_ref()) {
            // Specific conversions
            (Integer, Boolean) => true,
            (Boolean, Integer) => true,
            (Integer, Real) => true,

            // Types that are always casteable in one way
            (Any, _) => true,
            (_, Any) => true,
            (_, String) => true,

            // Trivial conversions
            (Array(t1), Array(t2)) => t1.coercible_to(t2),
            (t1, Array(t2)) => t1.coercible_to(t2),
            (Class(n1), Class(n2)) => {
                // We do allow data to be demoted to intermediate results
                // Note: we do this quick 'n' dirty, ideally we wanna used the defined BuiltinClass for this (but that's in a crate with cyclic dependency, jadda jadda)
                if n1 == "Data" && n2 == "IntermediateResult" { true } else { n1 == n2 }
            },
            (t1, t2) => discriminant(t1) == discriminant(t2),
        }
    }

    /// Returns whether or not this DataType may be implicitly converted to a function at all (of any signature).
    ///
    /// To determine if the DataType is implicitly convertible to a function of a specific signature, use `DataType::coercible_to()`.
    ///
    /// # Returns
    /// True if it is convertible, false otherwise.
    #[inline]
    pub fn coercible_to_function(&self) -> bool {
        use DataType::*;
        matches!(self, Any | Function(_))
    }
}

impl AsRef<DataType> for DataType {
    #[inline]
    fn as_ref(&self) -> &DataType { self }
}

impl From<&DataType> for DataType {
    #[inline]
    fn from(value: &DataType) -> Self { value.clone() }
}

impl From<&str> for DataType {
    #[inline]
    fn from(value: &str) -> Self {
        // First: any arrays are done recursively
        if !value.is_empty() && &value[..1] == "[" && &value[value.len() - 1..] == "]" {
            return Self::Array(Box::new(Self::from(&value[1..value.len() - 1])));
        } else if value.len() >= 2 && &value[value.len() - 2..] == "[]" {
            return Self::Array(Box::new(Self::from(&value[..value.len() - 2])));
        }

        // Otherwise, match literals & classes
        use DataType::*;
        match value {
            // Literal types
            "bool" | "boolean" => Boolean,
            "int" | "integer" => Integer,
            "float" | "real" => Real,
            "string" => String,

            // The rest is always a class
            value => Class(value.into()),
        }
    }
}

impl From<&String> for DataType {
    #[inline]
    fn from(value: &String) -> Self {
        // Use the string-one
        Self::from(value.as_str())
    }
}

impl From<String> for DataType {
    #[inline]
    fn from(value: String) -> Self {
        // Use the string-one
        Self::from(value.as_str())
    }
}

impl FromStr for DataType {
    type Err = ();

    #[inline]
    fn from_str(value: &str) -> Result<Self, Self::Err> { Ok(Self::from(value)) }
}

impl Display for DataType {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DataType::*;
        match self {
            Any => write!(f, "Any"),
            Void => write!(f, "Void"),

            Boolean => write!(f, "Boolean"),
            Integer => write!(f, "Integer"),
            Real => write!(f, "Real"),
            String => write!(f, "String"),
            Semver => write!(f, "Semver"),

            Array(t) => write!(f, "Array<{t}>"),
            Function(s) => write!(f, "Func<{s}>"),
            Class(n) => write!(f, "Class<{n}>"),
        }
    }
}
