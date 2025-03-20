//  PC.rs
//    by Lut99
//
//  Created:
//    16 Jan 2024, 09:59:53
//  Last edited:
//    16 Jan 2024, 15:08:41
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a program counter that correctly serializes.
//

use std::error::Error;
use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::ops::{Add, AddAssign};
use std::str::FromStr;

use brane_ast::SymTable;
use brane_ast::func_id::FunctionId;
use num_traits::AsPrimitive;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, SerializeSeq, Serializer};


/***** ERRORS *****/
/// Defines errors when parsing [`ProgramCounter`] from a string.
#[derive(Debug)]
pub enum ProgramCounterParseError {
    /// Failed to find a ':' in the program counter string.
    MissingColon { raw: String },
    /// Failed to parse the given string as a [`FunctionId`].
    InvalidFunctionId { err: brane_ast::func_id::FunctionIdParseError },
    /// Failed to parse the given string as a numerical index.
    InvalidIdx { raw: String, err: std::num::ParseIntError },
}
impl Display for ProgramCounterParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ProgramCounterParseError::*;
        match self {
            MissingColon { raw } => write!(f, "Given string '{raw}' does not contain a separating colon (':')"),
            InvalidFunctionId { err } => write!(f, "{err}"),
            InvalidIdx { raw, .. } => write!(f, "Failed to parse '{raw}' as a valid edge index (i.e., unsigned integer)"),
        }
    }
}
impl Error for ProgramCounterParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use ProgramCounterParseError::*;
        match self {
            MissingColon { .. } => None,
            InvalidFunctionId { err } => err.source(),
            InvalidIdx { err, .. } => Some(err),
        }
    }
}





/***** LIBRARY *****/
/// Used to keep track of the current executing edge in a workflow.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProgramCounter {
    /// The function ID of the function currently being executed.
    pub func_id:  FunctionId,
    /// The edge that we're executing in that function.
    pub edge_idx: usize,
}
impl Default for ProgramCounter {
    #[inline]
    fn default() -> Self { Self::start() }
}
impl ProgramCounter {
    /// Creates a new program counter from the given [`FunctionId`] and the given index in that function.
    ///
    /// # Arguments
    /// - `func_id`: A [`FunctionId`]-like to use as current function.
    /// - `edge_idx`: A [`usize`]-like to use as edge index within the given `func_id`.
    ///
    /// # Returns
    /// A new ProgramCounter instance.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn new(func_id: impl Into<FunctionId>, edge_idx: impl AsPrimitive<usize>) -> Self {
        Self { func_id: func_id.into(), edge_idx: edge_idx.as_() }
    }

    /// Creates a new program counter that points to the start of the `<main>`-function.
    ///
    /// # Returns
    /// A new ProgramCounter instance.
    #[inline]
    #[must_use]
    pub const fn start() -> Self { Self { func_id: FunctionId::Main, edge_idx: 0 } }

    /// Creates a new program counter that points to the start of the given function.
    ///
    /// # Arguments
    /// - `func_id`: A [`FunctionId`]-like to use as current function.
    ///
    /// # Returns
    /// A new ProgramCounter instance.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn start_of(func_id: impl Into<FunctionId>) -> Self { Self { func_id: func_id.into(), edge_idx: 0 } }

    /// Returns a ProgramCounter that points to the given edge within the same function.
    ///
    /// This function returns a new instance. To update an existing one, use [`ProgramCounter::jump_mut()`].
    ///
    /// # Arguments
    /// - `next`: The edge index of the new edge within this function.
    ///
    /// # Returns
    /// A new ProgramCounter that points to the same function as self and the given `next`.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn jump(&self, next: impl AsPrimitive<usize>) -> Self { Self { func_id: self.func_id, edge_idx: next.as_() } }

    /// Updates this program counter with a new edge index.
    ///
    /// This function mutates `self`. To instead receive a new instance, use [`ProgramCounter::jump`]
    ///
    /// # Arguments
    /// - `next`: The edge index of the new edge within this function.
    ///
    /// # Returns
    /// Self for chaining.
    #[inline]
    #[track_caller]
    pub fn jump_mut(&mut self, next: impl AsPrimitive<usize>) -> &mut Self {
        self.edge_idx = next.as_();
        self
    }

    /// Returns a ProgramCounter that points to the start of another function.
    ///
    /// This function returns a new instance. To update an existing one, use [`ProgramCounter::call_mut`].
    ///
    /// # Arguments
    /// - `func`: The identifier of the function to point to.
    ///
    /// # Returns
    /// A new ProgramCounter that points to the given `func` and the first edge within (i.e., edge `0`).
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn call(func: impl Into<FunctionId>) -> Self { Self { func_id: func.into(), edge_idx: 0 } }

    /// Updates this program counter such that it points to the start of the given function.
    ///
    /// This function mutates `self`. To instead receive a new instance, use [`ProgramCounter::call`].
    ///
    /// # Arguments
    /// - `func`: The identifier of the function to point to.
    ///
    /// # Returns
    /// Self for chaining.
    #[inline]
    #[track_caller]
    pub fn call_mut(&mut self, func: impl Into<FunctionId>) -> &mut Self {
        self.func_id = func.into();
        self.edge_idx = 0;
        self
    }

    /// Returns a formatter that shows the resolved name of the function.
    ///
    /// # Arguments
    /// - `symtable`: A workflow [`SymTable`] that is used to resolve the function identifiers to names.
    ///
    /// # Returns
    /// A [`ResolvedProgramCounter`] that does the actual formatting as it implements [`Display`].
    #[inline]
    pub fn resolved(&self, symtable: &SymTable) -> ResolvedProgramCounter {
        // Check if we can find a name
        let name: Option<String> = match self.func_id {
            FunctionId::Func(id) => symtable.funcs.get(id).map(|def| def.name.clone()),
            FunctionId::Main => None,
        };

        // Build the serialization with it
        ResolvedProgramCounter { func_id: self.func_id, func_name: name, edge_idx: self.edge_idx }
    }

    /// Returns whether this ProgramCounter points to somewhere in the `<main>` function.
    ///
    /// # Returns
    /// True if [`self.func_id.is_main()`](FunctionId::is_main()) is true, or else false.
    #[inline]
    #[must_use]
    #[track_caller]
    pub fn is_main(&self) -> bool { self.func_id.is_main() }
}
impl Display for ProgramCounter {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}:{}", self.func_id, self.edge_idx) }
}
impl FromStr for ProgramCounter {
    type Err = ProgramCounterParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Attempt to split the input on a separating colon
        let (func_id, edge_idx): (&str, &str) = match s.find(':') {
            Some(pos) => (&s[..pos], &s[pos + 1..]),
            None => return Err(ProgramCounterParseError::MissingColon { raw: s.into() }),
        };

        // Now parse the function ID and edge index separately
        let func_id: FunctionId = match FunctionId::from_str(func_id) {
            Ok(id) => id,
            Err(err) => return Err(ProgramCounterParseError::InvalidFunctionId { err }),
        };
        let edge_idx: usize = match usize::from_str(edge_idx) {
            Ok(id) => id,
            Err(err) => return Err(ProgramCounterParseError::InvalidIdx { raw: edge_idx.into(), err }),
        };

        // OK!
        Ok(Self { func_id, edge_idx })
    }
}
impl<'de> Deserialize<'de> for ProgramCounter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// Visitor for the [`ProgramCounter`].
        struct ProgramCounterVisitor;
        impl<'de> Visitor<'de> for ProgramCounterVisitor {
            type Value = ProgramCounter;

            #[inline]
            fn expecting(&self, f: &mut Formatter) -> FResult {
                write!(f, "a program counter (i.e., a tuple of first either '<main>' or an unsigned integer, then another unsigned integer")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                // Fetch the two elements in sequence
                let func_id: FunctionId = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let edge_idx: usize = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;

                // Alright done!
                Ok(ProgramCounter { func_id, edge_idx })
            }
        }


        // Use the visitor to either parse a string value or a direct number
        deserializer.deserialize_seq(ProgramCounterVisitor)
    }
}
impl Serialize for ProgramCounter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize a a tuple of two things (ordered pair of function ID and edge index)
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&self.func_id)?;
        seq.serialize_element(&self.edge_idx)?;
        seq.end()
    }
}
impl PartialOrd for ProgramCounter {
    #[inline]
    #[track_caller]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // Only define an ordering if the functions are the same
        if self.func_id == other.func_id { self.edge_idx.partial_cmp(&other.edge_idx) } else { None }
    }
}
impl Add<usize> for ProgramCounter {
    type Output = Self;

    /// Adds a number of edges to this ProgramCounter.
    ///
    /// # Arguments
    /// - `rhs`: The number of edges to move forward.
    ///
    /// # Returns
    /// A new [`ProgramCounter`] that points to the same function and the same edge index, except the latter is added to `rhs`.
    #[inline]
    #[track_caller]
    fn add(self, rhs: usize) -> Self::Output { Self { func_id: self.func_id, edge_idx: self.edge_idx + rhs } }
}
impl AddAssign<usize> for ProgramCounter {
    /// Adds a number of edges to this ProgramCounter, but mutably instead of returning a new object.
    ///
    /// # Arguments
    /// - `rhs`: The number of edges to move forward.
    #[inline]
    #[track_caller]
    fn add_assign(&mut self, rhs: usize) { self.edge_idx += rhs; }
}
impl From<&ProgramCounter> for ProgramCounter {
    #[inline]
    fn from(value: &Self) -> Self { *value }
}
impl From<&mut ProgramCounter> for ProgramCounter {
    #[inline]
    fn from(value: &mut Self) -> Self { *value }
}



/// A less usable counterpart to the [`ProgramCounter`] that can be used in errors as pretty serializations of one.
#[derive(Clone)]
pub struct ResolvedProgramCounter {
    /// The function ID of the function currently being executed.
    func_id:   FunctionId,
    /// The name of the function we're wrapping, if it is known.
    func_name: Option<String>,
    /// The edge that we're executing in that function.
    edge_idx:  usize,
}
impl ResolvedProgramCounter {
    /// Returns the identifier of the function to which this ProgramCounter points.
    ///
    /// # Returns
    /// A [`FunctionId`] describing the function.
    #[inline]
    #[must_use]
    pub const fn func_id(&self) -> FunctionId { self.func_id }

    /// Returns the name of the function to which this ProgramCounter points.
    ///
    /// # Returns
    /// A [`String`] reference describing the function.
    #[inline]
    #[must_use]
    pub const fn func_name(&self) -> Option<&String> { self.func_name.as_ref() }

    /// Returns the index of the edge within the function to which this ProgramCounter points.
    ///
    /// # Returns
    /// A [`usize`] that is the current edge's index.
    #[inline]
    #[must_use]
    pub const fn edge_idx(&self) -> usize { self.edge_idx }

    /// Returns a usable [`ProgramCounter`] from this ResolvedProgramCounter.
    ///
    /// # Returns
    /// A [`ProgramCounter`] that can be practically used in code.
    #[inline]
    #[must_use]
    pub const fn to_pc(&self) -> ProgramCounter { ProgramCounter { func_id: self.func_id, edge_idx: self.edge_idx } }
}
impl Debug for ResolvedProgramCounter {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        // Show as the function ID
        write!(
            f,
            "{}{}:{}",
            self.func_id,
            if let Some(func_name) = &self.func_name { format!(" ({func_name})") } else { String::new() },
            self.edge_idx
        )
    }
}
impl Display for ResolvedProgramCounter {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        // Show the name
        write!(f, "{}:{}", if let Some(func_name) = &self.func_name { func_name.clone() } else { self.func_id.to_string() }, self.edge_idx)
    }
}
