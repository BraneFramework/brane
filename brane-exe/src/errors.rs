//  ERRORS.rs
//    by Lut99
//
//  Created:
//    26 Aug 2022, 18:01:09
//  Last edited:
//    14 Nov 2024, 17:21:49
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines errors that occur in the `brane-exe` crate.
//

use std::error::Error;
use std::path::PathBuf;

use console::style;
use enum_debug::EnumDebug as _;
use specifications::data::DataName;
use specifications::pc::ProgramCounter;
use specifications::version::Version;
use specifications::wir::data_type::DataType;
use specifications::wir::func_id::FunctionId;
use specifications::wir::merge_strategy::MergeStrategy;


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
fn prettyprint_err_instr(pc: ProgramCounter, instr: Option<usize>, err: &dyn Error) {
    // Print the thing
    eprintln!(
        "{}: {}: {}",
        style(format!("{}{}", pc, if let Some(instr) = instr { format!(":{instr}") } else { String::new() })).bold(),
        style("error").red().bold(),
        err
    );

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
fn prettyprint_err(pc: ProgramCounter, err: &dyn Error) {
    // Print the thing
    eprintln!("{}: {}: {}", style(format!("{pc}")).bold(), style("error").red().bold(), err);

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
    fn to(self, pc: ProgramCounter) -> Result<Self::Ret, VmError>;

    /// Maps this result to a VmError that has some instructions.
    ///
    /// # Arguments
    /// - `edge`: The edge to insert.
    /// - `instr`: The instruction to insert.
    fn to_instr(self, pc: ProgramCounter, instr: usize) -> Result<Self::Ret, VmError>;
}

impl<T> ReturnEdge for Result<T, StackError> {
    /// The return type
    type Ret = T;

    /// Maps this result to a VmError that has only an edge.
    ///
    /// # Arguments
    /// - `edge`: The edge to insert.
    fn to(self, pc: ProgramCounter) -> Result<Self::Ret, VmError> { self.map_err(|source| VmError::StackError { pc, instr: None, source }) }

    /// Maps this result to a VmError that has some instructions.
    ///
    /// # Arguments
    /// - `edge`: The edge to insert.
    /// - `instr`: The instruction to insert.
    fn to_instr(self, pc: ProgramCounter, instr: usize) -> Result<Self::Ret, VmError> {
        self.map_err(|source| VmError::StackError { pc, instr: Some(instr), source })
    }
}

/***** LIBRARY *****/
/// Defines errors that relate to the values.
#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    /// Failed to parse the Value from the given `serde_json::Value` object.
    #[error("Cannot parse the given JSON value to a Value")]
    JsonError { err: serde_json::Error },

    /// Failed to cast a value from one type to another.
    #[error("Cannot cast a value of type {got} to {target}")]
    CastError { got: DataType, target: DataType },
}

/// Defines errors that relate to the stack.
#[derive(Debug, thiserror::Error)]
pub enum StackError {
    /// The stack overflowed :(
    #[error("Stack overflow occurred (has space for {size} values)")]
    StackOverflowError { size: usize },
}

/// Defines errors that relate to the frame stack.
#[derive(Debug, thiserror::Error)]
pub enum FrameStackError {
    /// The FrameStack was empty but still popped.
    #[error("Frame stack empty")]
    EmptyError,
    /// The FrameStack overflowed.
    #[error("Frame stack overflow occurred (has space for {size} frames/nested calls)")]
    OverflowError { size: usize },

    /// A certain variable was not declared before it was set/gotten.
    #[error("Undeclared variable '{name}'")]
    UndeclaredVariable { name: String },
    /// A certain variable was declared twice.
    #[error("Cannot declare variable '{name}' if it is already declared")]
    DuplicateDeclaration { name: String },
    /// A certain variable was undeclared without it ever being declared.
    #[error("Cannot undeclare variable '{name}' that was never declared")]
    UndeclaredUndeclaration { name: String },
    /// The given variable was declared but not initialized.
    #[error("Uninitialized variable '{name}'")]
    UninitializedVariable { name: String },
    /// The new value of a variable did not match the expected.
    #[error("Cannot assign value of type {got} to variable '{name}' of type {expected}")]
    VarTypeError { name: String, got: DataType, expected: DataType },
    /// The given variable was not known in the FrameStack.
    #[error("Variable '{name}' is declared but not currently in scope")]
    VariableNotInScope { name: String },
}

/// Defines errors that relate to the variable register.
#[derive(Debug, thiserror::Error)]
pub enum VarRegError {
    /// The given variable was already declared.
    #[error("Variable {id} was already declared before (old '{old_name}: {old_type}', new '{new_name}: {new_type}')")]
    DuplicateDeclaration { id: usize, old_name: String, old_type: DataType, new_name: String, new_type: DataType },
    /// The given variable was not declared.
    #[error("Variable {id} was not declared")]
    UndeclaredVariable { id: usize },
    /// The given variable was declared but never initialized.
    #[error("Variable {id} was not initialized")]
    UninitializedVariable { id: usize },
}

/// Defines errors that relate to a VM's execution.
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    /// An error occurred while instantiating the custom state.
    #[error("Could not create custom state: {err}")]
    GlobalStateError { err: Box<dyn Send + Sync + Error> },

    /// The given function pointer was out-of-bounds for the given workflow.
    #[error("Unknown function {func}")]
    UnknownFunction { func: FunctionId },
    /// The given program counter was out-of-bounds for the given function.
    #[error("Edge index {got} is out-of-bounds for function {func} with {edges} edges")]
    PcOutOfBounds { func: FunctionId, edges: usize, got: usize },

    /// We expected there to be a value on the stack but there wasn't.
    #[error("Expected a value of type {expected} on the stack, but stack was empty")]
    EmptyStackError { pc: ProgramCounter, instr: Option<usize>, expected: DataType },
    /// The value on top of the stack was of unexpected data type.
    #[error("Expected a value of type {expected} on the stack, but got a value of type {got}")]
    StackTypeError { pc: ProgramCounter, instr: Option<usize>, got: DataType, expected: DataType },
    /// The two values on top of the stack (in a lefthand-side, righthand-side fashion) are of incorrect data types.
    #[error("Expected a lefthand-side and righthand-side of (the same) {} type on the stack, but got types {} and {}, respectively (remember that rhs is on top)", expected, got.0, got.1)]
    StackLhsRhsTypeError { pc: ProgramCounter, instr: usize, got: (DataType, DataType), expected: DataType },
    /// A value in an Array was incorrectly typed.
    #[error("Expected an array element of type {expected} on the stack, but got a value of type {got}")]
    ArrayTypeError { pc: ProgramCounter, instr: usize, got: DataType, expected: DataType },
    /// A value in an Instance was incorrectly typed.
    #[error("Expected field '{field}' of class '{class}' to have type {expected}, but found type {got}")]
    InstanceTypeError { pc: ProgramCounter, instr: usize, class: String, field: String, got: DataType, expected: DataType },
    /// Failed to perform a cast instruction.
    #[error("Failed to cast top value on the stack")]
    CastError { pc: ProgramCounter, instr: usize, source: ValueError },
    /// The given integer was out-of-bounds for an array with given length.
    #[error("Index {got} is out-of-bounds for an array of length {max}")]
    ArrIdxOutOfBoundsError { pc: ProgramCounter, instr: usize, got: i64, max: usize },
    /// The given field was not present in the given class
    #[error("Class '{class}' has not field '{field}'")]
    ProjUnknownFieldError { pc: ProgramCounter, instr: usize, class: String, field: String },
    /// Could not declare the variable.
    #[error("Could not declare variable")]
    VarDecError { pc: ProgramCounter, instr: usize, source: FrameStackError },
    /// Could not un-declare the variable.
    #[error("Could not undeclare variable")]
    VarUndecError { pc: ProgramCounter, instr: usize, source: FrameStackError },
    /// Could not get the value of a variable.
    #[error("Could not get variable")]
    VarGetError { pc: ProgramCounter, instr: usize, source: FrameStackError },
    /// Could not set the value of a variable.
    #[error("Could not set variable")]
    VarSetError { pc: ProgramCounter, instr: usize, source: FrameStackError },

    /// Failed to spawn a new thread.
    #[error("Failed to spawn new thread")]
    SpawnError { pc: ProgramCounter, source: tokio::task::JoinError },
    /// One of the branches of a parallel returned an invalid type.
    #[error("Branch {branch} in parallel statement did not return value of type {expected}; got {got} instead")]
    BranchTypeError { pc: ProgramCounter, branch: usize, got: DataType, expected: DataType },
    /// The branch' type does not match that of the current merge strategy at all
    #[error("Branch {branch} returned a value of type {got}, but the current merge strategy ({merge:?}) requires values of {expected} type")]
    IllegalBranchType { pc: ProgramCounter, branch: usize, merge: MergeStrategy, got: DataType, expected: DataType },
    /// One of a function's arguments was of an incorrect type.
    #[error("Argument {arg} for function '{name}' has incorrect type: expected {expected}, got {got}")]
    FunctionTypeError { pc: ProgramCounter, name: String, arg: usize, got: DataType, expected: DataType },
    /// We got told to run a function but do not know where.
    #[error("Cannot call task '{name}' because it has no resolved location.")]
    UnresolvedLocation { pc: ProgramCounter, name: String },
    /// The given input (dataset, result) was not there as possible option for the given task.
    #[error("{} '{}' is not a possible input for task '{}'", name.variant(), name.name(), task)]
    UnknownInput { pc: ProgramCounter, task: String, name: DataName },
    /// The given input (dataset, result) was not yet planned at the time of execution.
    #[error("{} '{}' as input for task '{}' is not yet planned", name.variant(), name.name(), task)]
    UnplannedInput { pc: ProgramCounter, task: String, name: DataName },
    /// Attempted to call a function but the framestack thought otherwise.
    #[error("Failed to push to frame stack")]
    FrameStackPushError { pc: ProgramCounter, source: FrameStackError },
    /// Attempted to call a function but the framestack was empty.
    #[error("Failed to pop from frame stack")]
    FrameStackPopError { pc: ProgramCounter, source: FrameStackError },
    /// The return type of a function was not correct
    #[error("Got incorrect return type for function: expected {expected}, got {got}")]
    ReturnTypeError { pc: ProgramCounter, got: DataType, expected: DataType },

    /// There was a type mismatch in a task call.
    #[error("Task '{name}' expected argument {arg} to be of type {expected}, but got {got}")]
    TaskTypeError { pc: ProgramCounter, name: String, arg: usize, got: DataType, expected: DataType },

    /// A given asset was not found at all.
    #[error("Encountered unknown dataset '{name}'")]
    UnknownData { pc: ProgramCounter, name: String },
    /// A given intermediate result was not found at all.
    #[error("Encountered unknown result '{name}'")]
    UnknownResult { pc: ProgramCounter, name: String },
    /// The given package was not known.
    #[error("Unknown package with name '{}'{}", name, if !version.is_latest() { format!(" and version {version}") } else { String::new() })]
    UnknownPackage { pc: ProgramCounter, name: String, version: Version },
    /// Failed to serialize the given argument list.
    #[error("Could not serialize task arguments")]
    ArgumentsSerializeError { pc: ProgramCounter, source: serde_json::Error },

    /// An error that relates to the stack.
    #[error("{source}")]
    StackError { pc: ProgramCounter, instr: Option<usize>, source: StackError },
    /// A Vm-defined error.
    #[error("{source}")]
    Custom { pc: ProgramCounter, source: Box<dyn Send + Sync + Error> },
}


impl VmError {
    /// Prints the VM error neatly to stderr.
    #[inline]
    pub fn prettyprint(&self) {
        use VmError::*;
        match self {
            GlobalStateError { .. } => eprintln!("{self}"),

            UnknownFunction { .. } => eprintln!("{self}"),
            PcOutOfBounds { .. } => eprintln!("{self}"),

            EmptyStackError { pc, instr, .. } => prettyprint_err_instr(*pc, *instr, self),
            StackTypeError { pc, instr, .. } => prettyprint_err_instr(*pc, *instr, self),
            StackLhsRhsTypeError { pc, instr, .. } => prettyprint_err_instr(*pc, Some(*instr), self),
            ArrayTypeError { pc, instr, .. } => prettyprint_err_instr(*pc, Some(*instr), self),
            InstanceTypeError { pc, instr, .. } => prettyprint_err_instr(*pc, Some(*instr), self),
            CastError { pc, instr, .. } => prettyprint_err_instr(*pc, Some(*instr), self),
            ArrIdxOutOfBoundsError { pc, instr, .. } => prettyprint_err_instr(*pc, Some(*instr), self),
            ProjUnknownFieldError { pc, instr, .. } => prettyprint_err_instr(*pc, Some(*instr), self),
            VarDecError { pc, instr, .. } => prettyprint_err_instr(*pc, Some(*instr), self),
            VarUndecError { pc, instr, .. } => prettyprint_err_instr(*pc, Some(*instr), self),
            VarGetError { pc, instr, .. } => prettyprint_err_instr(*pc, Some(*instr), self),
            VarSetError { pc, instr, .. } => prettyprint_err_instr(*pc, Some(*instr), self),

            SpawnError { pc, .. } => prettyprint_err(*pc, self),
            BranchTypeError { pc, .. } => prettyprint_err(*pc, self),
            IllegalBranchType { pc, .. } => prettyprint_err(*pc, self),
            FunctionTypeError { pc, .. } => prettyprint_err(*pc, self),
            UnresolvedLocation { pc, .. } => prettyprint_err(*pc, self),
            UnknownInput { pc, .. } => prettyprint_err(*pc, self),
            UnplannedInput { pc, .. } => prettyprint_err(*pc, self),
            // UnavailableDataset{ pc, .. }  => prettyprint_err(*pc, self),
            FrameStackPushError { pc, .. } => prettyprint_err(*pc, self),
            FrameStackPopError { pc, .. } => prettyprint_err(*pc, self),
            ReturnTypeError { pc, .. } => prettyprint_err(*pc, self),

            TaskTypeError { pc, .. } => prettyprint_err(*pc, self),

            UnknownData { pc, .. } => prettyprint_err(*pc, self),
            UnknownResult { pc, .. } => prettyprint_err(*pc, self),
            UnknownPackage { pc, .. } => prettyprint_err(*pc, self),
            ArgumentsSerializeError { pc, .. } => prettyprint_err(*pc, self),

            StackError { pc, instr, .. } => prettyprint_err_instr(*pc, *instr, self),
            Custom { pc, .. } => prettyprint_err(*pc, self),
        }
    }
}


/// Defines errors that occur only in the LocalVm.
#[derive(Debug, thiserror::Error)]
pub enum LocalVmError {
    /// Failed to Base64-decode a Task's response.
    #[error("Could not decode result '{raw}' from task '{name}' as Base64")]
    Base64DecodeError { name: String, raw: String, source: base64::DecodeError },
    /// Failed to decode the given bytes as UTF-8.
    #[error("Could not decode base64-decoded result from task '{name}' as UTF-8")]
    Utf8DecodeError { name: String, source: std::string::FromUtf8Error },
    /// Failed to decode the string as JSON.
    #[error("Could not decode result '{raw}' from task '{name}' as JSON")]
    JsonDecodeError { name: String, raw: String, source: serde_json::Error },

    /// A given dataset was not found at the current location.
    #[error("Dataset '{name}' is not available on the local location '{loc}'")]
    DataNotAvailable { name: String, loc: String },
    /// The given data's path was not found.
    #[error("Invalid path '{}' to dataset '{}'", path.display(), name)]
    IllegalDataPath { name: String, path: PathBuf, source: std::io::Error },
    /// The given asset's path contained a colon.
    #[error("Encountered colon (:) in path '{}' to dataset '{}'; provide another path without", path.display(), name)]
    ColonInDataPath { name: String, path: PathBuf },
    /// The Transfer task is not supported by the LocalVm.
    #[error("Transfers are not supported in the LocalVm")]
    TransferNotSupported,
}

/// Defines errors for the DummyVm.
#[derive(Debug, thiserror::Error)]
pub enum DummyVmError {
    /// Failed to run a workflow.
    #[error("Failed to execute workflow")]
    ExecError { source: VmError },
}
