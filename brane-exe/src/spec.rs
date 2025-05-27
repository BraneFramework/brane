//  SPEC.rs
//    by Lut99
//
//  Created:
//    26 Aug 2022, 18:26:40
//  Last edited:
//    14 Nov 2024, 17:22:02
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines some non-Vm-trait structs and interfaces useful when using
//!   this crate.
//

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::Path;
use std::sync::{Arc, RwLock};

use specifications::data::{AccessKind, DataName, PreprocessKind};
use specifications::package::Capability;
use specifications::pc::ProgramCounter;
use specifications::profiling::ProfileScopeHandle;
use specifications::version::Version;
use specifications::wir::SymTable;
use specifications::wir::locations::Location;

use crate::frame_stack::FrameStack;
use crate::value::FullValue;


/***** LIBRARY *****/
/// Defines whatever is needed for the custom global part of a RunState.
pub trait CustomGlobalState: 'static + Send + Sync {}
impl CustomGlobalState for () {}

/// Defines whatever is needed for the custom local part of a RunState.
pub trait CustomLocalState: 'static + Send + Sync + Clone {
    /// Constructs a new CustomLocalState from the given global state.
    ///
    /// # Arguments
    /// - `global`: The global state to create this state from.
    ///
    /// # Returns
    /// A new instance of Self.
    fn new(global: &Arc<RwLock<impl CustomGlobalState>>) -> Self;
}
impl CustomLocalState for () {
    #[inline]
    fn new(_global: &Arc<RwLock<impl CustomGlobalState>>) -> Self {}
}



/// A trait that implements various missing pieces in task execution. See the `brane-tsk` crate for implementations.
#[async_trait::async_trait]
pub trait VmPlugin: 'static + Send + Sync {
    /// The type of the custom, App-wide, global state.
    type GlobalState: CustomGlobalState;
    /// The type of the custom, thread-local, local state.
    type LocalState: CustomLocalState;

    /// The error type of the preprocess function.
    type PreprocessError: 'static + Send + Sync + Error;
    /// The error type of the execute function.
    type ExecuteError: 'static + Send + Sync + Error;
    /// The error type of the stdout function.
    type StdoutError: 'static + Send + Sync + Error;
    /// The error type of the publicize and commit functions.
    type CommitError: 'static + Send + Sync + Error;


    /// A function that preprocesses a given dataset in the given way. Typically, this involves "transferring data" as a preprocessing step.
    ///
    /// # Generic arguments
    /// - `E`: The kind of error this function returns. Should, of course, implement `Error`.
    ///
    /// # Arguments
    /// - `global`: The custom global state for keeping track of your own things during execution.
    /// - `local`: The custom local state for keeping track of your own things faster but only local to this (execution) thread.
    /// - `pc`: A [`ProgramCounter`] that denotes for which task in the workflow we're preprocessing.
    /// - `loc`: The location where this preprocessing should happen.
    /// - `name`: The name of the intermediate result to make public. You'll typically only use this for debugging.
    /// - `preprocess`: The PreprocessKind that determines what you must do to make the dataset available.
    /// - `prof`: A ProfileScopeHandle that can be used to prove additional details about the timings of this function.
    ///
    /// # Returns
    /// This function should return an AccessKind which describes how to access the preprocessed data.
    ///
    /// It is expected that the preprocessed data is available the moment the function returns.
    ///
    /// # Errors
    /// This function may error whenever it likes.
    async fn preprocess(
        global: Arc<RwLock<Self::GlobalState>>,
        local: Self::LocalState,
        pc: ProgramCounter,
        loc: Location,
        name: DataName,
        preprocess: PreprocessKind,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<AccessKind, Self::PreprocessError>;



    /// A function that executes the given task.
    ///
    /// # Generic arguments
    /// - `E`: The kind of error this function returns. Should, of course, implement `Error`.
    ///
    /// # Arguments
    /// - `global`: The custom global state for keeping track of your own things during execution.
    /// - `local`: The custom local state for keeping track of your own things faster but only local to this (execution) thread.
    /// - `info`: A `TaskInfo` that contains all the information about the to-be-executed task the VM provides you with. **Note**: You have to preprocess the arguments contained within. Be aware that the path describes by the IntermediateResults is relative to some directory you still have to prepend.
    /// - `prof`: A ProfileScopeHandle that can be used to prove additional details about the timings of this function.
    ///
    /// # Returns
    /// This function should return either a FullValue, or None (where None is equivalent to `FullValue::Void`).
    ///
    /// # Errors
    /// This function may error whenever it likes.
    async fn execute(
        global: &Arc<RwLock<Self::GlobalState>>,
        local: &Self::LocalState,
        info: TaskInfo<'_>,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<Option<FullValue>, Self::ExecuteError>;



    /// A function that prints a message to stdout - whatever that may be.
    ///
    /// This function is called whenever BraneScript's `print` or `println` are called.
    ///
    /// # Generic arguments
    /// - `E`: The kind of error this function returns. Should, of course, implement `Error`.
    ///
    /// # Arguments
    /// - `global`: The custom global state for keeping track of your own things during execution.
    /// - `local`: The custom local state for keeping track of your own things faster but only local to this (execution) thread.
    /// - `text`: The text to write to your version of stdout.
    /// - `newline`: Whether or not to print a closing newline after the text (i.e., whether to use `println` or `print`).
    /// - `prof`: A ProfileScopeHandle that can be used to prove additional details about the timings of this function.
    ///
    /// # Errors
    /// This function may error whenever it likes.
    async fn stdout(
        global: &Arc<RwLock<Self::GlobalState>>,
        local: &Self::LocalState,
        text: &str,
        newline: bool,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::StdoutError>;



    /// A function that "publicizes" the given intermediate result.
    ///
    /// This is not really commiting, as it is making the intermediate dataset available upon request. In a distributed/instance setting, this typically means making the registry aware of it.
    ///
    /// # Generic arguments
    /// - `E`: The kind of error this function returns. Should, of course, implement `Error`.
    ///
    /// # Arguments
    /// - `global`: The custom global state for keeping track of your own things during execution.
    /// - `local`: The custom local state for keeping track of your own things faster but only local to this (execution) thread.
    /// - `loc`: The location where the dataset currently lives.
    /// - `name`: The name of the intermediate result to make public.
    /// - `path`: The path where the intermediate result is available. You'll probably want to archive this before continuing. **Note**: Be aware that this path is relative to some directory you still have to prepend.
    /// - `prof`: A ProfileScopeHandle that can be used to prove additional details about the timings of this function.
    ///
    /// # Errors
    /// This function may error whenever it likes.
    async fn publicize(
        global: &Arc<RwLock<Self::GlobalState>>,
        local: &Self::LocalState,
        loc: &Location,
        name: &str,
        path: &Path,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::CommitError>;

    /// A function that commits the given intermediate result by promoting it a Data.
    ///
    /// Typically, this involves saving the data somewhere outside of the results folder and then updating the registry on its existance.
    ///
    /// # Generic arguments
    /// - `E`: The kind of error this function returns. Should, of course, implement `Error`.
    ///
    /// # Arguments
    /// - `global`: The custom global state for keeping track of your own things during execution.
    /// - `local`: The custom local state for keeping track of your own things faster but only local to this (execution) thread.
    /// - `loc`: The location where the dataset currently lives.
    /// - `name`: The name of the intermediate result to promoto (you'll typically use this for debugging only).
    /// - `path`: The path where the intermediate result is available. You'll probably want to archive this somewhere else before continuing. **Note**: Be aware that this path is relative to some directory you still have to prepend.
    /// - `data_name`: The identifier of the dataset once the intermediate result is promoted. If it already exists, you'll probably want to override the old value with the new one.
    /// - `prof`: A ProfileScopeHandle that can be used to prove additional details about the timings of this function.
    ///
    /// # Errors
    /// This function may error whenever it likes.
    async fn commit(
        global: &Arc<RwLock<Self::GlobalState>>,
        local: &Self::LocalState,
        loc: &Location,
        name: &str,
        path: &Path,
        data_name: &str,
        prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::CommitError>;
}



/// Defines whatever we need to remember w.r.t. runtime in between two submission of part of a workflow (i.e., repl-runs).
///
/// # Generic types
/// - `C`: The custom state with which to extend this RunState.
#[derive(Clone, Debug)]
pub struct RunState<G: CustomGlobalState> {
    /// The Variable Register that contains previously defined variables.
    pub fstack: FrameStack,

    /// The custom part of the RunState that is global across all threads in a workflow.
    pub global: Arc<RwLock<G>>,
}

impl<G: CustomGlobalState> RunState<G> {
    /// Constructor for the RunState that initializes it as new.
    ///
    /// # Arguments
    /// - `table`: The initial SymTable that is the global symbol table.
    /// - `global`: The (already initialized) custom thread-global part of the state.
    ///
    /// # Returns
    /// A new RunState instance.
    #[inline]
    pub fn new(table: Arc<SymTable>, global: Arc<RwLock<G>>) -> Self { Self { fstack: FrameStack::new(512, table), global } }
}



/// Defines that which the execute closure needs to know about a task.
#[derive(Clone, Debug)]
pub struct TaskInfo<'a> {
    /// The program counter of the execution (may be used to identify the call to the task itself).
    pub pc:  ProgramCounter,
    /// The identifier of the task definition itself.
    pub def: usize,

    /// The name of the task to execute.
    pub name: &'a str,
    /// The package name of the task to execute.
    pub package_name: &'a str,
    /// The package version of the task to execute.
    pub package_version: &'a Version,
    /// The requirements that the task has.
    pub requirements: &'a HashSet<Capability>,

    /// The arguments that are given for this Task. Note that data & intermediate results have to be resolved before passing this to the function.
    pub args:     HashMap<String, FullValue>,
    /// The planned location for this task.
    pub location: &'a Location,
    /// The list of inputs to the workflow.
    pub input:    HashMap<DataName, AccessKind>,
    /// If this task returns an intermediate result, then this specifies the name it should have.
    pub result:   &'a Option<String>,
}
