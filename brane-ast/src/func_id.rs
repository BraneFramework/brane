//  FUNC ID.rs
//    by Lut99
//
//  Created:
//    16 Jan 2024, 11:31:56
//  Last edited:
//    16 Jan 2024, 15:03:01
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a better [`FunctionId`] that does not rely on
//!   platform-dependent [`usize::MAX`] to indicate the main function.
//

use std::fmt::{Display, Formatter, Result as FResult};
use std::str::FromStr;

use enum_debug::EnumDebug;
use num_traits::AsPrimitive;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};


/***** ERRORS *****/
/// Defines errors when parsing `FunctionId` from a string.
#[derive(Debug, thiserror::Error)]
pub enum FunctionIdParseError {
    /// Failed to parse the given string as a numerical ID.
    #[error("Failed to parse '{raw}' as a valid function ID (i.e., unsigned integer)")]
    InvalidId { raw: String, source: std::num::ParseIntError },
}

/***** LIBRARY *****/
/// Enum that can be used for function identifiers, to specially handle `main`.
#[derive(Clone, Copy, Debug, EnumDebug, Eq, Hash, PartialEq)]
pub enum FunctionId {
    /// It's the main function
    Main,
    /// It's a non-main function.
    Func(usize),
}
impl FunctionId {
    /// Constructor for the FunctionId that initializes it as a [`FunctionId::Main`].
    ///
    /// # Returns
    /// A new [`FunctionId`] instance.
    #[inline]
    pub const fn main() -> Self { Self::Main }

    /// Constructor for the FunctionId that initializes it as a [`FunctionId::Func`].
    ///
    /// # Arguments
    /// - `id`: The identifier of the function to point to.
    ///
    /// # Returns
    /// A new [`FunctionId`] instance.
    #[inline]
    pub fn func(id: impl AsPrimitive<usize>) -> Self { Self::Func(id.as_()) }

    /// Returns if this FunctionId is a [`FunctionId::Main`].
    ///
    /// # Returns
    /// True if it is, or false if it's a [`FunctionId::Func`].
    #[inline]
    pub const fn is_main(&self) -> bool { matches!(self, Self::Main) }

    /// Returns if this FunctionId is a [`FunctionId::Func`].
    ///
    /// # Returns
    /// True if it is, or false if it's a [`FunctionId::Main`].
    #[inline]
    pub const fn is_func(&self) -> bool { matches!(self, Self::Func(_)) }

    /// Returns the identifier in this FunctionId.
    ///
    /// # Returns
    /// The identifier within.
    ///
    /// # Panics
    /// This function panics if it's not a [`FunctionId::Func`].
    #[inline]
    pub const fn id(&self) -> usize {
        if let Self::Func(id) = self {
            *id
        } else {
            panic!("Cannot unwrap FunctionId::Main as a FunctionId::Func");
        }
    }
}
impl Display for FunctionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        match self {
            Self::Main => write!(f, "<main>"),
            Self::Func(id) => write!(f, "{id}"),
        }
    }
}
impl FromStr for FunctionId {
    type Err = FunctionIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Catch main
        if s == "<main>" {
            return Ok(Self::Main);
        }

        // Then parse it as an integer number
        match usize::from_str(s) {
            Ok(id) => Ok(Self::Func(id)),
            Err(source) => Err(FunctionIdParseError::InvalidId { raw: s.into(), source }),
        }
    }
}
impl<'de> Deserialize<'de> for FunctionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Visitor for the [`FunctionId`].
        struct FunctionIdVisitor;
        impl Visitor<'_> for FunctionIdVisitor {
            type Value = FunctionId;

            #[inline]
            fn expecting(&self, f: &mut Formatter) -> FResult { write!(f, "a function identifier (i.e., either '<main>' or an unsigned integer") }

            #[inline]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Implement the string deserializer
                Self::Value::from_str(v).map_err(|err| E::custom(err))
            }

            #[cfg(target_pointer_width = "16")]
            #[inline]
            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Forward to the u16 instead of the u64
                self.visit_u32(v as u32)
            }

            #[cfg(target_pointer_width = "16")]
            #[inline]
            fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Just always parse a non-main number
                Ok(FunctionId::Func(v as usize))
            }

            #[cfg(target_pointer_width = "16")]
            #[inline]
            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Type error ;(
                Err(Error::invalid_type(Unexpected::Unsigned(v), &self))
            }

            #[cfg(target_pointer_width = "32")]
            #[inline]
            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Forward to the u32 instead of the u64
                self.visit_u32(v as u32)
            }

            #[cfg(target_pointer_width = "32")]
            #[inline]
            fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Forward to the u32 instead of the u64
                self.visit_u32(v as u32)
            }

            #[cfg(target_pointer_width = "32")]
            #[inline]
            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Just always parse a non-main number
                Ok(FunctionId::Func(v as usize))
            }

            #[cfg(target_pointer_width = "64")]
            #[inline]
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Just always parse a non-main number
                Ok(FunctionId::Func(v as usize))
            }
        }


        // Use the visitor to either parse a string value or a direct number
        deserializer.deserialize_any(FunctionIdVisitor)
    }
}
impl Serialize for FunctionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize either '<main>' or the numerical function ID
        match self {
            Self::Main => serializer.serialize_str("<main>"),
            Self::Func(id) => serializer.serialize_u64(*id as u64),
        }
    }
}
impl From<usize> for FunctionId {
    #[inline]
    fn from(value: usize) -> Self { Self::Func(value) }
}
impl From<&FunctionId> for FunctionId {
    #[inline]
    fn from(value: &Self) -> Self { *value }
}
impl From<&mut FunctionId> for FunctionId {
    #[inline]
    fn from(value: &mut Self) -> Self { *value }
}
