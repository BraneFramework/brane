//  DUMMY.rs
//    by Lut99
//
//  Created:
//    13 Sep 2022, 16:43:11
//  Last edited:
//    02 May 2025, 15:11:13
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a Dummy virtual machine for unit test purposes only.
//

use std::collections::HashMap;
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use async_trait::async_trait;
use log::info;
use specifications::data::{AccessKind, AvailabilityKind, DataName};
use specifications::pc::ProgramCounter;
use specifications::profiling::ProfileScopeHandle;
use specifications::wir::data_type::DataType;
use specifications::wir::locations::Location;
use specifications::wir::{Edge, SymTable, Workflow};

pub use crate::errors::DummyVmError as Error;
use crate::errors::VmError;
use crate::spec::{CustomGlobalState, RunState, TaskInfo, VmPlugin};
use crate::value::FullValue;
use crate::vm::Vm;


/***** HELPER FUNCTIONS *****/
/// Returns a default value for the given DataType.
///
/// # Arguments
/// - `data_type`: The DataType to return the default value of.
/// - `workflow`: A Workflow to resolve any reference in (i.e., class references).
/// - `name`: The name of the task for which we are finding the default value. Used for debugging purposes only.
/// - `package_name`: The name of the package in which the task we are finding the default value for lives. Used for debugging purposes only.
///
/// # Returns
/// A FullValue that carries the default value for this type. It is guaranteed that the given FullValue has the same DataType as went in.
///
/// # Panics
/// This function may panic if the data type made no sense for a Task return value.
fn default_return_value(
    data_type: &DataType,
    workflow: &Workflow,
    name: impl AsRef<str>,
    package_name: impl AsRef<str>,
    result: &Option<String>,
) -> FullValue {
    let name: &str = name.as_ref();
    let package_name: &str = package_name.as_ref();
    match data_type {
        DataType::Void => FullValue::Void,

        DataType::Boolean => FullValue::Boolean(false),
        DataType::Integer => FullValue::Integer(0),
        DataType::Real => FullValue::Real(0.0),
        DataType::String => FullValue::String("".into()),

        DataType::Array { .. } => FullValue::Array(vec![]),
        DataType::Class { name } => {
            // Get the definition of the class
            for def in &workflow.table.classes {
                if &def.name == name {
                    // Now initialize all its members with default values
                    let mut props: HashMap<String, FullValue> = HashMap::with_capacity(def.props.len());
                    for p in &def.props {
                        props.insert(p.name.clone(), default_return_value(&p.data_type, workflow, name, package_name, result));
                    }

                    // Return it
                    return FullValue::Instance(name.clone(), props);
                }
            }
            panic!("Unknown class '{name}'");
        },
        DataType::IntermediateResult => FullValue::IntermediateResult(
            result
                .clone()
                .unwrap_or_else(|| panic!("Task {package_name}::{name} does not define it returns an IntermediateResult, and yet it does"))
                .into(),
        ),

        // Invalid types
        DataType::Any
        | DataType::Numeric
        | DataType::Addable
        | DataType::Callable
        | DataType::NonVoid
        | DataType::Semver
        | DataType::Function { .. }
        | DataType::Data => {
            panic!("Task {package_name}::{name} returns an {data_type}, while a task shouldn't");
        },
    }
}





/***** LIBRARY *****/
/// Defines the global, shared state for the DummyVm.
#[derive(Clone, Debug)]
pub struct DummyState {
    /// The workflow we are executing.
    pub workflow: Option<Arc<Workflow>>,
    /// The list of results we previously "planned".
    pub results:  Arc<Mutex<HashMap<String, String>>>,

    /// The text to buffer when writing to stdout.
    ///
    /// It looks overkill to have a mutex here, but this is required in the test of `thread.rs` due to it not using a wrapping VM.
    pub text: Arc<Mutex<String>>,
}
impl CustomGlobalState for DummyState {}



/// The DummyPlugin implements the missing functions for the Dummy VM. As the name implies, these don't do any actual work.
pub struct DummyPlugin;

#[async_trait::async_trait]
impl VmPlugin for DummyPlugin {
    type CommitError = std::convert::Infallible;
    type ExecuteError = std::convert::Infallible;
    type GlobalState = DummyState;
    type LocalState = ();
    type PreprocessError = std::convert::Infallible;
    type StdoutError = std::convert::Infallible;

    async fn preprocess(
        _global: Arc<RwLock<Self::GlobalState>>,
        _local: Self::LocalState,
        pc: ProgramCounter,
        _loc: Location,
        name: DataName,
        _preprocess: specifications::data::PreprocessKind,
        _prof: ProfileScopeHandle<'_>,
    ) -> Result<AccessKind, Self::PreprocessError> {
        info!("Processing dummy `DummyVm::preprocess()` call for intermediate result '{name}' in {pc}");

        // We also accept it with a dummy accesskind
        Ok(AccessKind::File { path: PathBuf::new() })
    }

    async fn execute(
        global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        info: TaskInfo<'_>,
        _prof: ProfileScopeHandle<'_>,
    ) -> Result<Option<FullValue>, Self::ExecuteError> {
        info!(
            "Processing dummy call to '{}'@'{}' with {} in {}[{}]...",
            info.name,
            info.location,
            info.args.iter().map(|(n, v)| format!("{n}={v:?}")).collect::<Vec<String>>().join(","),
            info.package_name,
            info.package_version,
        );

        // Get a lock on the state
        let state: RwLockReadGuard<Self::GlobalState> = global.read().unwrap();

        // Returns default values for the various types a function can have
        let ret: &DataType = &state.workflow.as_ref().unwrap().table.tasks[info.def].func().ret;
        Ok(Some(default_return_value(ret, state.workflow.as_ref().unwrap(), info.name, info.package_name, info.result)))
    }

    async fn stdout(
        global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        text: &str,
        newline: bool,
        _prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::StdoutError> {
        info!("Processing dummy stdout write (newline: {})...", if newline { "yes" } else { "no" },);

        // Get the global state and append the text
        let state: RwLockWriteGuard<DummyState> = global.write().unwrap();
        let mut stext: MutexGuard<String> = state.text.lock().unwrap();
        stext.push_str(&format!("{}{}", text, if newline { "\n" } else { "" }));

        // Done
        Ok(())
    }

    async fn publicize(
        _global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        _loc: &Location,
        name: &str,
        path: &Path,
        _prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::CommitError> {
        info!("Processing dummy publicize for result '{}' @ '{:?}'...", name, path.display(),);

        // We don't really do anything, unfortunately
        Ok(())
    }

    async fn commit(
        _global: &Arc<RwLock<Self::GlobalState>>,
        _local: &Self::LocalState,
        _loc: &Location,
        name: &str,
        path: &Path,
        data_name: &str,
        _prof: ProfileScopeHandle<'_>,
    ) -> Result<(), Self::CommitError> {
        info!("Processing dummy commit for result '{}' @ '{:?}' to '{}'...", name, path.display(), data_name,);

        // We don't really do anything, unfortunately
        Ok(())
    }
}



/// Defines a Dummy planner that simply assigns 'localhost' to every task it can find.
pub struct DummyPlanner;
impl DummyPlanner {
    /// Helper function that plans the given list of edges for the dummy VM.
    ///
    /// This function cannot fail, since it just basically plans anything to have the AST be in a valid state.
    ///
    /// # Arguments
    /// - `table`: The SymbolTable where this edge lives in.
    /// - `edges`: The given list to plan.
    ///
    /// # Returns
    /// Nothing, but does change the given list.
    fn plan_edges(table: &mut SymTable, edges: &mut Vec<Edge>) {
        for e in edges {
            if let Edge::Node { at, input, result, .. } = e {
                // We simply assign all locations to localhost
                *at = Some("localhost".into());

                // For all dataset/intermediate result inputs, we assert they are available on the local location
                for (name, avail) in input {
                    // Just set it as available to _something_, for testing purposes.
                    *avail = Some(AvailabilityKind::Available { how: AccessKind::File { path: PathBuf::from(name.name()) } });
                }

                // Then, we make the intermediate result available at the location where the function is being run (if there is any)
                if let Some(name) = result {
                    // Insert an entry in the list detailling where to access it and how
                    table.results.insert(name.clone(), "localhost".into());
                }
            }
        }

        // Done
    }

    /// Plans the given workflow by assigning `localhost` to every task it can find.
    ///
    /// # Arguments
    /// - `state_results`: A map of addition intermediate results declared in a previous snippet.
    /// - `workflow`: The Workflow to plan.
    ///
    /// # Returns
    /// The same workflow, but now with planned locations.
    ///
    /// # Panics
    /// This function panics if the workflow was malformed somehow.
    pub fn plan(state_results: &mut HashMap<String, String>, workflow: Workflow) -> Workflow {
        let mut workflow: Workflow = workflow;

        // Get the symbol table muteable, so we can... mutate... it
        let mut table: Arc<SymTable> = Arc::new(SymTable::new());
        mem::swap(&mut workflow.table, &mut table);
        let mut table: SymTable = Arc::try_unwrap(table).unwrap();

        // Load any previous results we "planned"
        table.results.extend(state_results.iter().map(|(k, v)| (k.clone(), v.clone())));

        // Do the main edges first
        {
            // Start by getting a list of all the edges
            let mut edges: Arc<Vec<Edge>> = Arc::new(vec![]);
            mem::swap(&mut workflow.graph, &mut edges);
            let mut edges: Vec<Edge> = Arc::try_unwrap(edges).unwrap();

            // Plan them
            Self::plan_edges(&mut table, &mut edges);

            // Move the edges back
            let mut edges: Arc<Vec<Edge>> = Arc::new(edges);
            mem::swap(&mut edges, &mut workflow.graph);
        }

        // Then we do the function edges
        {
            // Start by getting the map
            let mut funcs: Arc<HashMap<usize, Vec<Edge>>> = Arc::new(HashMap::new());
            mem::swap(&mut workflow.funcs, &mut funcs);
            let mut funcs: HashMap<usize, Vec<Edge>> = Arc::try_unwrap(funcs).unwrap();

            // Iterate through all of the edges
            for edges in funcs.values_mut() {
                Self::plan_edges(&mut table, edges);
            }

            // Put the map back
            let mut funcs: Arc<HashMap<usize, Vec<Edge>>> = Arc::new(funcs);
            mem::swap(&mut funcs, &mut workflow.funcs);
        }

        // Write the results to the global state
        state_results.clone_from(&table.results);

        // Then, put the table back
        let mut table: Arc<SymTable> = Arc::new(table);
        mem::swap(&mut table, &mut workflow.table);

        // Done
        workflow
    }
}



/// Defines a Dummy VM that may be used to test.
pub struct DummyVm {
    /// The internal state of the VM in between runs.
    state: RunState<DummyState>,
}

impl DummyVm {
    /// Constructor for the DummyVm that initializes it to an never-used-before-but-ready-for-everything VM.
    ///
    /// # Returns
    /// A new instance of a DummyVm.
    #[inline]
    pub fn new() -> Self {
        Self {
            state: Self::new_state(DummyState {
                workflow: None,
                text:     Arc::new(Mutex::new(String::new())),
                results:  Arc::new(Mutex::new(HashMap::new())),
            }),
        }
    }

    /// Runs the given workflow on this VM.
    ///
    /// There is a bit of ownership awkwardness going on, but that's due to the need for the struct to outlive threads.
    ///
    /// # Arguments
    /// - `workflow`: The Workflow to execute.
    ///
    /// # Returns
    /// The result of the workflow, if any. It also returns `self` again for subsequent runs.
    pub async fn exec(self, workflow: Workflow) -> (Self, Result<FullValue, Error>) {
        let plan: Workflow = {
            let mut state: RwLockWriteGuard<DummyState> = self.state.global.write().unwrap();

            // Step 1: Plan
            let plan: Workflow = DummyPlanner::plan(&mut state.results.lock().unwrap(), workflow);

            // Step 2: Execution
            // Inject the workflow
            state.workflow = Some(Arc::new(plan.clone()));
            plan
        };

        // Now wrap ourselves in a lock so that we can run the internal vm
        let this: Arc<RwLock<Self>> = Arc::new(RwLock::new(self));

        // Run the VM and get self back
        let result: Result<FullValue, VmError> = Self::run::<DummyPlugin>(this.clone(), plan, ProfileScopeHandle::dummy()).await;
        let this: Self = match Arc::try_unwrap(this) {
            Ok(this) => this.into_inner().unwrap(),
            Err(_) => {
                panic!("Could not get self back");
            },
        };



        // Step 3: Result
        // Match the result to potentially error
        let value: FullValue = match result {
            Ok(value) => value,
            Err(source) => {
                return (this, Err(Error::ExecError { source }));
            },
        };

        // Done, return - but because this is a dummy VM, also flush the text buffer
        this.flush_stdout();
        (this, Ok(value))
    }

    /// Prints the buffered text, clearing it again.
    ///
    /// # Returns
    /// Nothing, but does print to stdout.
    pub fn flush_stdout(&self) {
        // Fetch the global state if there is one
        let state: RwLockWriteGuard<DummyState> = self.state.global.write().unwrap();
        let mut text: MutexGuard<String> = state.text.lock().unwrap();
        print!("{text}");
        *text = String::new();
    }
}

impl Default for DummyVm {
    #[inline]
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl Vm for DummyVm {
    type GlobalState = DummyState;
    type LocalState = ();

    /// A function that stores the given runtime state information in the parent struct.
    ///
    /// This is important and will be used later.
    ///
    /// # Arguments
    /// - `state`: The current state of the workflow we have executed.
    ///
    /// # Returns
    /// Nothing, but should change the internals to return this state later upon request.
    ///
    /// # Errors
    /// This function may error for its own reasons.
    #[inline]
    fn store_state(this: &Arc<RwLock<Self>>, state: RunState<Self::GlobalState>) -> Result<(), VmError> {
        // Get a lock and store it
        let mut lock: RwLockWriteGuard<Self> = this.write().unwrap();
        lock.state = state;
        Ok(())
    }

    /// A function that returns the VM's runtime state in the parent struct.
    ///
    /// This is important and will be used later.
    ///
    /// # Returns
    /// The RunState of this application if it exists, or else None.
    ///
    /// # Errors
    /// This function may error for its own reasons.
    #[inline]
    fn load_state(this: &Arc<RwLock<Self>>) -> Result<RunState<Self::GlobalState>, VmError> {
        // Get a lock and read it
        let lock: RwLockReadGuard<Self> = this.read().unwrap();
        Ok(lock.state.clone())
    }
}
