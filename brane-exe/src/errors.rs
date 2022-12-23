//  ERRORS.rs
//    by Lut99
// 
//  Created:
//    26 Aug 2022, 18:01:09
//  Last edited:
//    19 Dec 2022, 10:48:01
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines errors that occur in the `brane-exe` crate.
// 

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};
use std::path::PathBuf;

use console::style;

use brane_ast::{DataType, MergeStrategy};
use brane_ast::ast::DataName;
use specifications::version::Version;


/***** HELPER FUNCTIONS *****/
/// Prints the given error (of an instruction) to stderr.
/// 
/// # Arguments
/// - `edge`: The edge index to print.
/// - `instr`: The instruction index to print.
/// - `err`: The Error to print.
/// 
/// # Returns
/// Nothing, but does print the err to stderr.
fn prettyprint_err_instr(edge: usize, instr: Option<usize>, err: &dyn Error) {
    // Print the thing
    eprintln!("{}: {}: {}", style(format!("{}{}", edge, if let Some(instr) = instr { format!(":{}", instr) } else { String::new() })).bold(), style("error").red().bold(), err);

    // Done
}

/// Prints the given error to stderr.
/// 
/// # Arguments
/// - `edge`: The edge index to print.
/// - `err`: The Error to print.
/// 
/// # Returns
/// Nothing, but does print the err to stderr.
fn prettyprint_err(edge: usize, err: &dyn Error) {
    // Print the thing
    eprintln!("{}: {}: {}", style(format!("{}", edge)).bold(), style("error").red().bold(), err);

    // Done
}





/***** AUXILLARY *****/
/// Trait that makes printing shit a bit easier.
pub trait ReturnEdge {
    /// The return type
    type Ret;


    /// Maps this result to a VmError that has only an edge.
    /// 
    /// # Arguments
    /// - `edge`: The edge to insert.
    fn to(self, edge: usize) -> Result<Self::Ret, VmError>;

    /// Maps this result to a VmError that has some instructions.
    /// 
    /// # Arguments
    /// - `edge`: The edge to insert.
    /// - `instr`: The instruction to insert.
    fn to_instr(self, edge: usize, instr: usize) -> Result<Self::Ret, VmError>;
}

impl<T> ReturnEdge for Result<T, StackError> {
    /// The return type
    type Ret = T;


    /// Maps this result to a VmError that has only an edge.
    /// 
    /// # Arguments
    /// - `edge`: The edge to insert.
    fn to(self, edge: usize) -> Result<Self::Ret, VmError> {
        match self {
            Ok(val)  => Ok(val),
            Err(err) => Err(VmError::StackError { edge, instr: None, err })
        }
    }

    /// Maps this result to a VmError that has some instructions.
    /// 
    /// # Arguments
    /// - `edge`: The edge to insert.
    /// - `instr`: The instruction to insert.
    fn to_instr(self, edge: usize, instr: usize) -> Result<Self::Ret, VmError> {
        match self {
            Ok(val)  => Ok(val),
            Err(err) => Err(VmError::StackError { edge, instr: Some(instr), err })
        }
    }
}





/***** LIBRARY *****/
/// Defines errors that relate to the values.
#[derive(Debug)]
pub enum ValueError {
    /// Failed to parse the Value from the given `serde_json::Value` object.
    JsonError{ err: serde_json::Error },

    /// Failed to cast a value from one type to another.
    CastError{ got: DataType, target: DataType },
}

impl Display for ValueError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use ValueError::*;
        match self {
            JsonError{ err } => write!(f, "Cannot parse the given JSON value to a Value: {}", err),

            CastError { got, target } => write!(f, "Cannot cast a value of type {} to {}", got, target),
        }
    }
}

impl Error for ValueError {}



/// Defines errors that relate to the stack.
#[derive(Debug)]
pub enum StackError {
    /// The stack overflowed :(
    StackOverflowError{ size: usize },
}

impl Display for StackError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use StackError::*;
        match self {
            StackOverflowError { size } => write!(f, "Stack overflow occurred (has space for {} values)", size),
        }
    }
}

impl Error for StackError {}



/// Defines errors that relate to the frame stack.
#[derive(Debug)]
pub enum FrameStackError {
    /// The FrameStack was empty but still popped.
    EmptyError,
    /// The FrameStack overflowed.
    OverflowError{ size: usize },

    /// The new value of a variable did not match the expected.
    VarTypeError{ name: String, got: DataType, expected: DataType },
    /// The given variable was not known in the FrameStack.
    VariableNotInScope{ name: String },
}

impl Display for FrameStackError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use FrameStackError::*;
        match self {
            EmptyError            => write!(f, "Frame stack empty"),
            OverflowError{ size } => write!(f, "Frame stack overflow occurred (has space for {} frames/nested calls)", size),

            VarTypeError{ name, got, expected } => write!(f, "Cannot assign value of type {} to variable '{}' of type {}", got, name, expected),
            VariableNotInScope{ name }          => write!(f, "Variable '{}' is declared but not currently in scope", name),
        }
    }
}

impl Error for FrameStackError {}



/// Defines errors that relate to the variable register.
#[derive(Debug)]
pub enum VarRegError {
    /// The given variable was already declared.
    DuplicateDeclaration{ id: usize, old_name: String, old_type: DataType, new_name: String, new_type: DataType },
    /// The given variable was not declared.
    UndeclaredVariable{ id: usize },
    /// The given variable was declared but never initialized.
    UninitializedVariable{ id: usize },
}

impl Display for VarRegError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use VarRegError::*;
        match self {
            DuplicateDeclaration{ id, old_name, old_type, new_name, new_type } => write!(f, "Variable {} was already declared before (old '{}: {}', new '{}: {}')", id, old_name, old_type, new_name, new_type),
            UndeclaredVariable{ id }                                           => write!(f, "Variable {} was not declared", id),
            UninitializedVariable{ id }                                        => write!(f, "Variable {} was not initialized", id),
        }
    }
}

impl Error for VarRegError {}



/// Defines errors that relate to a VM's execution.
#[derive(Debug)]
pub enum VmError {
    // /// Failed to read the given reader.
    // ReaderReadError{ err: std::io::Error },
    // /// Failed to compile the source (but already printed why).
    // CompileError{ errs: Vec<brane_ast::Error> },
    /// An error occurred while instantiating the custom state.
    GlobalStateError{ err: Box<dyn Send + Sync + Error> },

    /// We expected there to be a value on the stack but there wasn't.
    EmptyStackError{ edge: usize, instr: Option<usize>, expected: DataType },
    /// The value on top of the stack was of unexpected data type.
    StackTypeError{ edge: usize, instr: Option<usize>, got: DataType, expected: DataType },
    /// The two values on top of the stack (in a lefthand-side, righthand-side fashion) are of incorrect data types.
    StackLhsRhsTypeError{ edge: usize, instr: usize, got: (DataType, DataType), expected: DataType },
    /// A value in an Array was incorrectly typed.
    ArrayTypeError{ edge: usize, instr: usize, got: DataType, expected: DataType },
    /// A value in an Instance was incorrectly typed.
    InstanceTypeError{ edge: usize, instr: usize, class: String, field: String, got: DataType, expected: DataType },
    /// Failed to perform a cast instruction.
    CastError{ edge: usize, instr: usize, err: ValueError },
    /// The given integer was out-of-bounds for an array with given length.
    ArrIdxOutOfBoundsError{ edge: usize, instr: usize, got: i64, max: usize },
    /// The given field was not present in the given class
    ProjUnknownFieldError{ edge: usize, instr: usize, class: String, field: String },
    /// Could not get the value of a variable.
    VarGetError{ edge: usize, instr: usize, err: FrameStackError },
    /// Could not set the value of a variable.
    VarSetError{ edge: usize, instr: usize, err: FrameStackError },

    /// Failed to spawn a new thread.
    SpawnError{ edge: usize, err: tokio::task::JoinError },
    /// One of the branches of a parallel returned an invalid type.
    BranchTypeError{ edge: usize, branch: usize, got: DataType, expected: DataType },
    /// The branch' type does not match that of the current merge strategy at all
    IllegalBranchType{ edge: usize, branch: usize, merge: MergeStrategy, got: DataType, expected: DataType },
    /// One of a function's arguments was of an incorrect type.
    FunctionTypeError{ edge: usize, name: String, arg: usize, got: DataType, expected: DataType },
    /// We got told to run a function but do not know where.
    UnresolvedLocation{ edge: usize, name: String },
    /// The given dataset was not locally available by the time it has to be executed.
    UnavailableDataset{ edge: usize, name: DataName },
    /// Attempted to call a function but the framestack thought otherwise.
    FrameStackPushError{ edge: usize, err: FrameStackError },
    /// Attempted to call a function but the framestack was empty.
    FrameStackPopError{ edge: usize, err: FrameStackError },
    /// The return type of a function was not correct
    ReturnTypeError{ edge: usize, got: DataType, expected: DataType },

    /// There was a type mismatch in a task call.
    TaskTypeError{ edge: usize, name: String, arg: usize, got: DataType, expected: DataType },

    /// A given asset was not found at all.
    UnknownData{ edge: usize, name: String },
    /// A given intermediate result was not found at all.
    UnknownResult{ edge: usize, name: String },
    /// The given package was not known.
    UnknownPackage{ edge: usize, name: String, version: Version },
    /// Failed to serialize the given argument list.
    ArgumentsSerializeError{ edge: usize, err: serde_json::Error },

    /// An error that relates to the stack.
    StackError{ edge: usize, instr: Option<usize>, err: StackError },
    /// A Vm-defined error.
    Custom{ edge: usize, err: Box<dyn Send + Sync + Error> },
}

impl VmError {
    /// Prints the VM error neatly to stderr.
    #[inline]
    pub fn prettyprint(&self) {
        use VmError::*;
        match self {
            // ReaderReadError{ .. }  => eprintln!("{}", self),
            // CompileError{ .. }     => eprintln!("{}", self),
            GlobalStateError{ .. } => eprintln!("{}", self),

            EmptyStackError { edge, instr, .. }        => prettyprint_err_instr(*edge, *instr, self),
            StackTypeError { edge, instr, .. }         => prettyprint_err_instr(*edge, *instr, self),
            StackLhsRhsTypeError { edge, instr, .. }   => prettyprint_err_instr(*edge, Some(*instr), self),
            ArrayTypeError{ edge, instr, .. }          => prettyprint_err_instr(*edge, Some(*instr), self),
            InstanceTypeError{ edge, instr, .. }       => prettyprint_err_instr(*edge, Some(*instr), self),
            CastError{ edge, instr, .. }               => prettyprint_err_instr(*edge, Some(*instr), self),
            ArrIdxOutOfBoundsError { edge, instr, .. } => prettyprint_err_instr(*edge, Some(*instr), self),
            ProjUnknownFieldError{ edge, instr, .. }   => prettyprint_err_instr(*edge, Some(*instr), self),
            VarGetError{ edge, instr, .. }             => prettyprint_err_instr(*edge, Some(*instr), self),
            VarSetError{ edge, instr, .. }             => prettyprint_err_instr(*edge, Some(*instr), self),

            SpawnError{ edge, .. }          => prettyprint_err(*edge, self),
            BranchTypeError{ edge, .. }     => prettyprint_err(*edge, self),
            IllegalBranchType{ edge, .. }   => prettyprint_err(*edge, self),
            FunctionTypeError{ edge, .. }   => prettyprint_err(*edge, self),
            UnresolvedLocation{ edge, .. }  => prettyprint_err(*edge, self),
            UnavailableDataset{ edge, .. }  => prettyprint_err(*edge, self),
            FrameStackPushError{ edge, .. } => prettyprint_err(*edge, self),
            FrameStackPopError{ edge, .. }  => prettyprint_err(*edge, self),
            ReturnTypeError{ edge, .. }     => prettyprint_err(*edge, self),

            TaskTypeError{ edge, .. } => prettyprint_err(*edge, self),

            UnknownData{ edge, .. }             => prettyprint_err(*edge, self),
            UnknownResult{ edge, .. }           => prettyprint_err(*edge, self),
            UnknownPackage{ edge, .. }          => prettyprint_err(*edge, self),
            ArgumentsSerializeError{ edge, .. } => prettyprint_err(*edge, self),

            StackError{ edge, instr, .. } => prettyprint_err_instr(*edge, *instr, self),
            Custom{ edge, .. }            => prettyprint_err(*edge, self),
        }
    }
}

impl Display for VmError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use VmError::*;
        match self {
            // ReaderReadError { err } => write!(f, "Failed to read from the given reader: {}", err),
            // CompileError{ .. }      => write!(f, "Could not compile the given source text (see output above)"),
            GlobalStateError{ err } => write!(f, "Could not create custom state: {}", err),

            EmptyStackError { expected, .. }                     => write!(f, "Expected a value of type {} on the stack, but stack was empty", expected),
            StackTypeError { got, expected, .. }                 => write!(f, "Expected a value of type {} on the stack, but got a value of type {}", expected, got),
            StackLhsRhsTypeError { got, expected, .. }           => write!(f, "Expected a lefthand-side and righthand-side of (the same) {} type on the stack, but got types {} and {}, respectively (remember that rhs is on top)", expected, got.0, got.1),
            ArrayTypeError{ got, expected, .. }                  => write!(f, "Expected an array element of type {} on the stack, but got a value of type {}", expected, got),
            InstanceTypeError{ class, field, got, expected, .. } => write!(f, "Expected field '{}' of class '{}' to have type {}, but found type {}", field, class, expected, got),
            CastError{ err, .. }                                 => write!(f, "Failed to cast top value on the stack: {}", err),
            ArrIdxOutOfBoundsError { got, max, .. }              => write!(f, "Index {} is out-of-bounds for an array of length {}", got, max),
            ProjUnknownFieldError{ class, field, .. }            => write!(f, "Class '{}' has not field '{}'", class, field),
            VarGetError{ err, .. }                               => write!(f, "Could not get variable: {}", err),
            VarSetError{ err, .. }                               => write!(f, "Could not set variable: {}", err),

            SpawnError{ err, .. }                                 => write!(f, "Failed to spawn new thread: {}", err),
            BranchTypeError{ branch, got, expected, .. }          => write!(f, "Branch {} in parallel statement did not return value of type {}; got {} instead", branch, expected, got),
            IllegalBranchType{ branch, merge, got, expected, .. } => write!(f, "Branch {} returned a value of type {}, but the current merge strategy ({:?}) requires values of {} type", branch, got, merge, expected),
            FunctionTypeError{ name, arg, got, expected, .. }     => write!(f, "Argument {} for function '{}' has incorrect type: expected {}, got {}", arg, name, expected, got),
            UnresolvedLocation{ name, .. }                        => write!(f, "Cannot call task '{}' because it has no resolved location.", name),
            UnavailableDataset{ name, .. }                        => write!(f, "Dataset '{}' is unavailable at execution time", name),
            FrameStackPushError{ err, .. }                        => write!(f, "Failed to push to frame stack: {}", err),
            FrameStackPopError{ err, .. }                         => write!(f, "Failed to pop from frame stack: {}", err),
            ReturnTypeError{ got, expected, .. }                  => write!(f, "Got incorrect return type for function: expected {}, got {}", expected, got),

            TaskTypeError{ name, arg, got, expected, .. } => write!(f, "Task '{}' expected argument {} to be of type {}, but got {}", name, arg, expected, got),

            UnknownData{ name, .. }             => write!(f, "Encountered unknown dataset '{}'", name),
            UnknownResult{ name, .. }           => write!(f, "Encountered unknown result '{}'", name),
            UnknownPackage{ name, version, .. } => write!(f, "Unknown package with name '{}'{}", name, if !version.is_latest() { format!(" and version {}", version) } else { String::new() }),
            ArgumentsSerializeError{ err, .. }  => write!(f, "Could not serialize task arguments: {}", err),

            StackError{ err, .. } => write!(f, "{}", err),
            Custom{ err, .. }     => write!(f, "{}", err),
        }
    }
}

impl Error for VmError {}



/// Defines errors that occur only in the LocalVm.
#[derive(Debug)]
pub enum LocalVmError {
    /// Failed to Base64-decode a Task's response.
    Base64DecodeError{ name: String, raw: String, err: base64::DecodeError },
    /// Failed to decode the given bytes as UTF-8.
    Utf8DecodeError{ name: String, err: std::string::FromUtf8Error },
    /// Failed to decode the string as JSON.
    JsonDecodeError{ name: String, raw: String, err: serde_json::Error },

    /// A given dataset was not found at the current location.
    DataNotAvailable{ name: String, loc: String },
    /// The given data's path was not found.
    IllegalDataPath{ name: String, path: PathBuf, err: std::io::Error },
    /// The given asset's path contained a colon.
    ColonInDataPath{ name: String, path: PathBuf },
    /// The Transfer task is not supported by the LocalVm.
    TransferNotSupported,
}

impl Display for LocalVmError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use LocalVmError::*;
        match self {
            Base64DecodeError{ name, raw, err } => write!(f, "Could not decode result '{}' from task '{}' as Base64: {}", raw, name, err),
            Utf8DecodeError{ name, err }        => write!(f, "Could not decode base64-decoded result from task '{}' as UTF-8: {}", name, err),
            JsonDecodeError{ name, raw, err }   => write!(f, "Could not decode result '{}' from task '{}' as JSON: {}", raw, name, err),

            DataNotAvailable{ name, loc }      => write!(f, "Dataset '{}' is not available on the local location '{}'", name, loc),
            IllegalDataPath{ name, path, err } => write!(f, "Invalid path '{}' to dataset '{}': {}", path.display(), name, err),
            ColonInDataPath{ name, path }      => write!(f, "Encountered colon (:) in path '{}' to dataset '{}'; provide another path without", path.display(), name),
            TransferNotSupported               => write!(f, "Transfers are not supported in the LocalVm"),
        }
    }
}

impl Error for LocalVmError {}
