//  DATA TYPE.rs
//    by Lut99
//
//  Created:
//    30 Aug 2022, 12:02:57
//  Last edited:
//    14 Nov 2024, 17:47:02
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines conversions for compatability with [`brane_dsl`] types.
//

use brane_dsl::data_type::FunctionSignature;
use brane_dsl::location::AllowedLocations;
use specifications::wir::builtins::BuiltinClasses;
use specifications::wir::data_type::DataType;
use specifications::wir::locations::Locations;


/***** LIBRARY *****/
/// Converts from a [DSL Datatype](brane_dsl::DataType) to the executable one.
///
/// # Arguments
/// - `dtype`: The [`DataType`](brane_dsl::DataType) to convert.
///
/// # Returns
/// A converted [`DataType`].
#[inline]
pub fn dtype_dsl_to_ast(value: brane_dsl::DataType) -> DataType {
    use brane_dsl::DataType::*;
    match value {
        Any => DataType::Any,
        Void => DataType::Void,

        Boolean => DataType::Boolean,
        Integer => DataType::Integer,
        Real => DataType::Real,
        String => DataType::String,
        Semver => DataType::Semver,

        Array(a) => DataType::Array { elem_type: Box::new(dtype_dsl_to_ast(*a)) },
        Function(sig) => DataType::Function { args: sig.args.into_iter().map(dtype_dsl_to_ast).collect(), ret: Box::new(dtype_dsl_to_ast(sig.ret)) },
        Class(name) => {
            // Match if 'Data' or 'IntermediateResult'
            if name == BuiltinClasses::Data.name() {
                DataType::Data
            } else if name == BuiltinClasses::IntermediateResult.name() {
                DataType::IntermediateResult
            } else {
                DataType::Class { name }
            }
        },
    }
}

/// Converts from an [executable Datatype](DataType) to the DSL one.
///
/// # Arguments
/// - `dtype`: The [`DataType`] to convert.
///
/// # Returns
/// A converted [`brane_dsl::DataType`].
#[inline]
pub fn dtype_ast_to_dsl(value: DataType) -> brane_dsl::DataType {
    use brane_dsl::DataType::*;
    match value {
        DataType::Any => Any,
        DataType::Void => Void,

        DataType::Numeric | DataType::Addable | DataType::Callable | DataType::NonVoid => {
            panic!("Cannot convert permissive data type (i.e., set of types) to a single brane_dsl::DataType")
        },

        DataType::Boolean => Boolean,
        DataType::Integer => Integer,
        DataType::Real => Real,
        DataType::String => String,
        DataType::Semver => Semver,

        DataType::Array { elem_type } => Array(Box::new(dtype_ast_to_dsl(*elem_type))),
        DataType::Function { args, ret } => {
            Function(Box::new(FunctionSignature { args: args.into_iter().map(dtype_ast_to_dsl).collect(), ret: dtype_ast_to_dsl(*ret) }))
        },
        DataType::Class { name } => Class(name),
        DataType::Data => Class(BuiltinClasses::Data.name().into()),
        DataType::IntermediateResult => Class(BuiltinClasses::IntermediateResult.name().into()),
    }
}



/// Converts from an [`AllowedLocations`] to a [`Locations`].
///
/// # Arguments
/// - `locs`: The [`AllowedLocations`] to convert.
///
/// # Returns
/// A new [`Locations`].
#[inline]
pub fn locs_dsl_to_ast(locs: AllowedLocations) -> Locations {
    match locs {
        AllowedLocations::All => Locations::All,
        AllowedLocations::Exclusive(locs) => Locations::Restricted(locs.into_iter().map(|l| l.into()).collect()),
    }
}
