//  STATE.rs
//    by Lut99
//
//  Created:
//    16 Sep 2022, 08:22:47
//  Last edited:
//    14 Nov 2024, 17:47:50
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines and implements various structures to keep track of the
//!   compilation state in between snippet compilation runs.
//

use std::cell::{RefCell, RefMut};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use brane_dsl::ast::Data;
use brane_dsl::data_type::{ClassSignature, FunctionSignature};
use brane_dsl::symbol_table::{ClassEntry, FunctionEntry, SymbolTable, VarEntry};
use brane_dsl::{DataType, TextRange};
use specifications::package::Capability;
use specifications::version::Version;
use specifications::wir::builtins::{BuiltinClasses, BuiltinFunctions};
use specifications::wir::{ClassDef, ComputeTaskDef, Edge, FunctionDef, SymTable, TaskDef, VarDef};
use strum::IntoEnumIterator;

use crate::dsl::{dtype_ast_to_dsl, dtype_dsl_to_ast};


/***** STATICS *****/
lazy_static! {
    /// The empty list referenced when a function or variable in the DataTable does not exist.
    static ref EMPTY_IDS: HashSet<Data> = HashSet::new();
}





/***** LIBRARY *****/
/// Defines a 'TableState', which is the CompileState's notion of a symbol table.
#[derive(Clone, Debug)]
pub struct TableState {
    /// The functions that are kept for next compilation junks
    pub funcs:   Vec<FunctionState>,
    /// The tasks that are kept for next compilation junks
    pub tasks:   Vec<TaskState>,
    /// The functions that are kept for next compilation junks
    pub classes: Vec<ClassState>,
    /// The functions that are kept for next compilation junks
    pub vars:    Vec<VarState>,

    /// The list of results introduced in this workflow.
    pub results: HashMap<String, String>,
}

impl TableState {
    /// Constructor for the TableState which initializes it with the builtin's only.
    ///
    /// We assume this is a toplevel table, so we assume no functions, tasks, classes or variables have been defined that this table needs to be aware of.
    ///
    /// # Returns
    /// A new instance of the TableState.
    pub fn new() -> Self {
        // Construct the TableLists separately.
        let mut funcs: Vec<FunctionState> = BuiltinFunctions::iter().map(|f| f.into()).collect();
        let tasks: Vec<TaskState> = Vec::new();
        let classes: Vec<ClassState> = BuiltinClasses::iter().map(|c| ClassState::from_builtin(c, &mut funcs)).collect();
        let vars: Vec<VarState> = Vec::new();

        // use that to construct the rest
        Self { funcs, tasks, classes, vars, results: HashMap::new() }
    }

    /// Constructor for the TableState that doesn't even initialize it to builtins.
    ///
    /// # Returns
    /// A new, completely empty instance of the TableState.
    #[inline]
    pub fn empty() -> Self {
        Self {
            funcs:   Vec::new(),
            tasks:   Vec::new(),
            classes: Vec::new(),
            vars:    Vec::new(),

            results: HashMap::new(),
        }
    }

    /// Constructor for the TableState that initializes it to not really a valid state (but kinda).
    ///
    /// This is useful if you just need a placeholder for a table but know that the function body in question is never executed anyway (e.g.., builtins or external functions).
    ///
    /// # Returns
    /// A new TableState instance that will keep the compiler happy but will probably result into runtime crashes once used (pay attention to overflows).
    #[inline]
    pub fn none() -> Self {
        Self {
            funcs:   Vec::new(),
            tasks:   Vec::new(),
            classes: Vec::new(),
            vars:    Vec::new(),

            results: HashMap::new(),
        }
    }

    /// Injects the TableState into the given SymbolTable. The entries will already have indices properly resolved.
    ///
    /// Only global definitions are injected. Any nested ones (except for class stuff) is irrelevant due to them never being accessed in future workflow snippets.
    ///
    /// # Arguments
    /// - `st`: The (mutable) borrow to the symbol table where we will inject everything.
    ///
    /// # Returns
    /// Nothing, but does alter the given symbol table to insert everything.
    pub fn inject(&self, st: &mut RefMut<SymbolTable>) {
        // First, inject the functions
        for (i, f) in self.funcs.iter().enumerate() {
            // Create the thingamabob and set the index
            let mut entry: FunctionEntry = f.into();
            entry.index = i;

            // Insert it
            if let Err(err) = st.add_func(entry) {
                panic!("Failed to inject previously defined function in global symbol table: {err}");
            }
        }

        // Do tasks...
        for (i, t) in self.tasks.iter().enumerate() {
            // Create the thingamabob and set the index
            let mut entry: FunctionEntry = t.into();
            entry.index = i;

            // Insert it
            if let Err(err) = st.add_func(entry) {
                panic!("Failed to inject previously defined task in global symbol table: {err}");
            }
        }

        // ...classes...
        for (i, c) in self.classes.iter().enumerate() {
            // Create the thingamabob and set the index
            let mut entry: ClassEntry = c.into_entry(&self.funcs);
            entry.index = i;

            // Insert it
            if let Err(err) = st.add_class(entry) {
                panic!("Failed to inject previously defined class in global symbol table: {err}");
            }
        }

        // ...and, finally, variables
        for (i, v) in self.vars.iter().enumerate() {
            // Create the thingamabob and set the index
            let mut entry: VarEntry = v.into();
            entry.index = i;

            // Insert it
            if let Err(err) = st.add_var(entry) {
                panic!("Failed to inject previously defined variable in global symbol table: {err}");
            }
        }
    }

    /// Returns the function with the given index, if any.
    ///
    /// # Arguments
    /// - `id`: The ID/index of the function to get the compile state of.
    ///
    /// # Returns
    /// A reference to the corresponding [`FunctionState`].
    ///
    /// # Panics
    /// This function may panic if `id` is out-of-bounds.
    #[inline]
    pub fn func(&self, id: usize) -> &FunctionState {
        if id >= self.funcs.len() {
            panic!("Given function ID '{}' is out-of-bounds for TableState with {} functions", id, self.funcs.len());
        }
        &self.funcs[id]
    }

    /// Returns the task with the given index, if any.
    ///
    /// # Arguments
    /// - `id`: The ID/index of the task to get the compile state of.
    ///
    /// # Returns
    /// A reference to the corresponding [`TaskState`].
    ///
    /// # Panics
    /// This function may panic if `id` is out-of-bounds.
    #[inline]
    pub fn task(&self, id: usize) -> &TaskState {
        if id >= self.tasks.len() {
            panic!("Given task ID '{}' is out-of-bounds for TableState with {} tasks", id, self.tasks.len());
        }
        &self.tasks[id]
    }

    /// Returns the class with the given index, if any.
    ///
    /// # Arguments
    /// - `id`: The ID/index of the class to get the compile state of.
    ///
    /// # Returns
    /// A reference to the corresponding [`ClassState`].
    ///
    /// # Panics
    /// This function may panic if `id` is out-of-bounds.
    #[inline]
    pub fn class(&self, id: usize) -> &ClassState {
        if id >= self.classes.len() {
            panic!("Given class ID '{}' is out-of-bounds for TableState with {} classes", id, self.classes.len());
        }
        &self.classes[id]
    }

    /// Returns the variable with the given index, if any.
    ///
    /// # Arguments
    /// - `id`: The ID/index of the variable to get the compile state of.
    ///
    /// # Returns
    /// A reference to the corresponding [`VarState`].
    ///
    /// # Panics
    /// This function may panic if `id` is out-of-bounds.
    #[inline]
    pub fn var(&self, id: usize) -> &VarState {
        if id >= self.vars.len() {
            panic!("Given variable ID '{}' is out-of-bounds for TableState with {} variables", id, self.vars.len());
        }
        &self.vars[id]
    }

    /// Returns the offset for the functions.
    #[inline]
    pub fn n_funcs(&self) -> usize { self.funcs.len() }

    /// Returns the offset for the tasks.
    #[inline]
    pub fn n_tasks(&self) -> usize { self.tasks.len() }

    /// Returns the offset for the classes.
    #[inline]
    pub fn n_classes(&self) -> usize { self.classes.len() }

    /// Returns the offset for the variables.
    #[inline]
    pub fn n_vars(&self) -> usize { self.vars.len() }
}

impl Default for TableState {
    #[inline]
    fn default() -> Self { Self::new() }
}

impl From<TableState> for SymTable {
    fn from(value: TableState) -> Self {
        // Functions
        let mut funcs: Vec<FunctionDef> = Vec::with_capacity(value.funcs.len());
        for f in value.funcs {
            funcs.push(f.into());
        }

        // Tasks
        let mut tasks: Vec<TaskDef> = Vec::with_capacity(value.tasks.len());
        for t in value.tasks {
            tasks.push(t.into());
        }

        // Classes
        let mut classes: Vec<ClassDef> = Vec::with_capacity(value.classes.len());
        for c in value.classes {
            classes.push(c.into());
        }

        // Finally, variables
        let mut vars: Vec<VarDef> = Vec::with_capacity(value.vars.len());
        for v in value.vars {
            vars.push(v.into());
        }

        // Finally finally, the data & resultes
        let results: HashMap<String, String> = value.results;

        // Done; return them as a table
        Self::with(funcs, tasks, classes, vars, results)
    }
}

impl From<&TableState> for SymTable {
    fn from(value: &TableState) -> Self { Self::from(value.clone()) }
}



/// Defines whatever we need to know of a function in between workflow snippet calls.
#[derive(Clone, Debug)]
pub struct FunctionState {
    /// The name of the function.
    pub name:      String,
    /// The signature of the function.
    pub signature: FunctionSignature,

    /// If this function is a method in a class, then the class' name is stored here.
    pub class_name: Option<String>,

    /// The range that links this function back to the source text.
    pub range: TextRange,
}

impl From<BuiltinFunctions> for FunctionState {
    #[inline]
    fn from(value: BuiltinFunctions) -> Self {
        Self {
            name:      value.name().into(),
            signature: FunctionSignature::from(value),

            class_name: None,

            range: TextRange::none(),
        }
    }
}

impl From<&FunctionState> for FunctionEntry {
    #[inline]
    fn from(value: &FunctionState) -> Self {
        Self {
            name:      value.name.clone(),
            signature: value.signature.clone(),
            params:    vec![],

            package_name:    None,
            package_version: None,
            class_name:      value.class_name.clone(),

            arg_names:    vec![],
            requirements: None,

            index: usize::MAX,

            range: value.range.clone(),
        }
    }
}

impl From<FunctionState> for FunctionDef {
    #[inline]
    fn from(value: FunctionState) -> Self {
        FunctionDef {
            name: value.name,
            args: value.signature.args.into_iter().map(dtype_dsl_to_ast).collect(),
            ret:  dtype_dsl_to_ast(value.signature.ret),
        }
    }
}



#[derive(Clone, Debug)]
pub struct TaskState {
    /// The name of the function.
    pub name: String,
    /// The signature of the function.
    pub signature: FunctionSignature,
    /// The names of the arguments. They are mapped by virtue of having the same index as in `signature.args`.
    pub arg_names: Vec<String>,
    /// Any requirements for this function.
    pub requirements: HashSet<Capability>,

    /// The name of the package where this Task is stored.
    pub package_name:    String,
    /// The version of the package where this Task is stored.
    pub package_version: Version,

    /// The range that links this task back to the source text.
    pub range: TextRange,
}

impl From<&TaskState> for FunctionEntry {
    #[inline]
    fn from(value: &TaskState) -> Self {
        Self {
            name:      value.name.clone(),
            signature: value.signature.clone(),
            params:    vec![],

            package_name:    Some(value.package_name.clone()),
            package_version: Some(value.package_version),
            class_name:      None,

            arg_names:    value.arg_names.clone(),
            requirements: Some(value.requirements.clone()),

            index: usize::MAX,

            range: value.range.clone(),
        }
    }
}

impl From<TaskState> for TaskDef {
    #[inline]
    fn from(value: TaskState) -> Self {
        Self::Compute(ComputeTaskDef {
            package: value.package_name,
            version: value.package_version,

            function:     Box::new(FunctionDef {
                name: value.name,
                args: value.signature.args.into_iter().map(dtype_dsl_to_ast).collect(),
                ret:  dtype_dsl_to_ast(value.signature.ret),
            }),
            args_names:   value.arg_names,
            requirements: value.requirements,
        })
    }
}



/// Defines whatever we need to know of a class in between workflow snippet calls.
#[derive(Clone, Debug)]
pub struct ClassState {
    /// The name of the class.
    pub name:    String,
    /// The list of properties in this class.
    pub props:   Vec<VarState>,
    /// The list of methods in this class (as references to the global class list)
    pub methods: Vec<usize>,

    /// If this class is imported from a package, then the package's name is stored here.
    pub package_name:    Option<String>,
    /// If this class is imported from a package, then the package's version is stored here.
    pub package_version: Option<Version>,

    /// The range that links this class back to the source text.
    pub range: TextRange,
}

impl ClassState {
    /// Converts a builtin class to a ClassState.
    ///
    /// # Arguments
    /// - `builtin`: The [`BuiltinClasses`] to convert.
    /// - `funcs`: A list of existing function states to extend with this class'es methods.
    ///
    /// # Returns
    /// A new ClassState representing the builtin one.
    pub fn from_builtin(builtin: BuiltinClasses, funcs: &mut Vec<FunctionState>) -> Self {
        // Collect the properties
        let props: Vec<VarState> = builtin
            .props()
            .iter()
            .map(|(name, dtype)| VarState {
                name: (*name).into(),
                data_type: dtype_ast_to_dsl(dtype.clone()),
                function_name: None,
                class_name: Some(builtin.name().into()),
                range: TextRange::none(),
            })
            .collect();

        // Collect the methods
        let methods: Vec<usize> = builtin
            .methods()
            .iter()
            .enumerate()
            .map(|(i, (name, sig))| {
                funcs.push(FunctionState {
                    name: (*name).into(),
                    signature: FunctionSignature {
                        args: sig.0.iter().map(|dtype| dtype_ast_to_dsl(dtype.clone())).collect(),
                        ret:  dtype_ast_to_dsl(sig.1.clone()),
                    },
                    class_name: Some(builtin.name().into()),
                    range: TextRange::none(),
                });
                i
            })
            .collect();

        // Build the final state
        ClassState { name: builtin.name().into(), props, methods, package_name: None, package_version: None, range: TextRange::none() }
    }

    /// Converts this ClassState into a ClassEntry, using the given list of functions to resolve the internal list.
    ///
    /// # Arguments
    /// - `funcs`: The Vec of functions to resolve indices with.
    ///
    /// # Returns
    /// A new ClassEntry instance.
    pub fn into_entry(&self, funcs: &[FunctionState]) -> ClassEntry {
        // Create the symbol table
        let c_table: Rc<RefCell<SymbolTable>> = SymbolTable::new();
        {
            let mut cst: RefMut<SymbolTable> = c_table.borrow_mut();

            // Add the properties
            for p in &self.props {
                if let Err(err) = cst.add_var(p.into()) {
                    panic!("Failed to insert class property into new class symbol table: {err}");
                }
            }
            // Add the methods
            for m in &self.methods {
                if let Err(err) = cst.add_func((&funcs[*m]).into()) {
                    panic!("Failed to insert class method into new class symbol table: {err}");
                }
            }
        }

        // Create the entry with it
        ClassEntry {
            signature:    ClassSignature::new(self.name.clone()),
            symbol_table: c_table,

            package_name:    self.package_name.clone(),
            package_version: self.package_version,

            index: usize::MAX,

            range: self.range.clone(),
        }
    }
}

impl From<ClassState> for ClassDef {
    #[inline]
    fn from(value: ClassState) -> Self {
        ClassDef {
            name:    value.name,
            props:   value.props.into_iter().map(|v| v.into()).collect(),
            methods: value.methods,

            package: value.package_name,
            version: value.package_version,
        }
    }
}





/// Defines whatever we need to know of a variable in between workflow snippet calls.
#[derive(Clone, Debug)]
pub struct VarState {
    /// The name of the variable.
    pub name:      String,
    /// The data type of this variable.
    pub data_type: DataType,

    /// If this variable is a parameter in a function, then the function's name is stored here.
    pub function_name: Option<String>,
    /// If this variable is a property in a class, then the class' name is stored here.
    pub class_name:    Option<String>,

    /// The range that links this variable back to the source text.
    pub range: TextRange,
}

impl From<&VarState> for VarEntry {
    #[inline]
    fn from(value: &VarState) -> Self {
        Self {
            name:      value.name.clone(),
            data_type: value.data_type.clone(),

            function_name: value.function_name.clone(),
            class_name:    value.class_name.clone(),

            index: usize::MAX,

            range: value.range.clone(),
        }
    }
}

impl From<VarState> for VarDef {
    #[inline]
    fn from(value: VarState) -> Self { Self { name: value.name, data_type: dtype_dsl_to_ast(value.data_type) } }
}



/// Defines a DataState, which is a bit like a symbol table for data identifiers - except that it's temporal (i.e., has a notion of values being overwritten).
#[derive(Clone, Debug)]
pub struct DataState {
    // /// Maps function names (=identifiers) to their current possible list of data identifiers _they return_. Since function bodies are constant, it may be expected the list of possible identifiers is also.
    // funcs : HashMap<*const RefCell<FunctionEntry>, HashSet<Data>>,
    // /// Maps variable names (=identifiers) to their current possible list of data identifiers they may be. An empty set implies it's not a Data or IntermediateResult struct.
    // vars  : HashMap<*const RefCell<VarEntry>, HashSet<Data>>,
    /// Maps function names (=identifiers) to their current possible list of data identifiers _they return_. Since function bodies are constant, it may be expected the list of possible identifiers is also.
    funcs: HashMap<String, HashSet<Data>>,
    /// Maps variable names (=identifiers) to their current possible list of data identifiers they may be. An empty set implies it's not a Data or IntermediateResult struct.
    vars:  HashMap<String, HashSet<Data>>,
}

impl DataState {
    /// Constructor for the DataTable that initializes it to empty.
    ///
    /// # Returns
    /// A new DataTable instance.
    #[inline]
    pub fn new() -> Self { Self { funcs: HashMap::new(), vars: HashMap::new() } }

    // /// Sets a whole list of new possible values for this function, overwriting any existing ones.
    // ///
    // /// # Arguments
    // /// - `f`: The pointer to the function's entry that uniquely identifies it.
    // /// - `new_ids`: The Data/IntermediateResult identifier to add as possible return dataset for this function.
    // #[inline]
    // pub fn set_funcs(&mut self, f: &Rc<RefCell<FunctionEntry>>, new_ids: HashSet<Data>) {
    //     self.funcs.insert(Rc::as_ptr(f), new_ids);
    // }
    /// Sets a whole list of new possible values for this function, overwriting any existing ones.
    ///
    /// # Arguments
    /// - `name`: The name of the function to set the possible datasets for.
    /// - `new_ids`: The Data/IntermediateResult identifier to add as possible return dataset for this function.
    #[inline]
    pub fn set_funcs(&mut self, name: impl Into<String>, new_ids: HashSet<Data>) { self.funcs.insert(name.into(), new_ids); }

    // /// Sets a whole list of new possible values for this variable, overwriting any existing ones.
    // ///
    // /// # Arguments
    // /// - `v`: The pointer to the variable's entry that uniquely identifies it.
    // /// - `id`: The Data/IntermediateResult identifier to add as possible return dataset for this variable.
    // #[inline]
    // pub fn set_vars(&mut self, v: &Rc<RefCell<VarEntry>>, new_ids: HashSet<Data>) {
    //     self.vars.insert(Rc::as_ptr(v), new_ids);
    // }
    /// Sets a whole list of new possible values for this variable, overwriting any existing ones.
    ///
    /// # Arguments
    /// - `name`: The name of the variable to set the possible datasets for.
    /// - `id`: The Data/IntermediateResult identifier to add as possible return dataset for this variable.
    #[inline]
    pub fn set_vars(&mut self, name: impl Into<String>, new_ids: HashSet<Data>) { self.vars.insert(name.into(), new_ids); }

    // /// Returns the list of possible values for the given function. If it does not exist, returns an empty one.
    // ///
    // /// # Arguments
    // /// - `f`: The pointer to the function's entry that uniquely identifies it.
    // ///
    // /// # Returns
    // /// A reference to the list of possible values for the given function.
    // #[inline]
    // pub fn get_func(&self, f: &Rc<RefCell<FunctionEntry>>) -> &HashSet<Data> {
    //     self.funcs.get(&Rc::as_ptr(f)).unwrap_or(&*EMPTY_IDS)
    // }
    /// Returns the list of possible values for the given function. If it does not exist, returns an empty one.
    ///
    /// # Arguments
    /// - `name`: The name of the function to get the possible datasets of.
    ///
    /// # Returns
    /// A reference to the list of possible values for the given function.
    #[inline]
    pub fn get_func(&self, name: impl AsRef<str>) -> &HashSet<Data> { self.funcs.get(name.as_ref()).unwrap_or(&*EMPTY_IDS) }

    // /// Returns the list of possible values for the given variable. If it does not exist, returns an empty one.
    // ///
    // /// # Arguments
    // /// - `v`: The pointer to the variable's entry that uniquely identifies it.
    // ///
    // /// # Returns
    // /// A reference to the list of possible values for the given variable.
    // #[inline]
    // pub fn get_var(&self, v: &Rc<RefCell<VarEntry>>) -> &HashSet<Data> {
    //     self.vars.get(&Rc::as_ptr(v)).unwrap_or(&*EMPTY_IDS)
    // }
    /// Returns the list of possible values for the given variable. If it does not exist, returns an empty one.
    ///
    /// # Arguments
    /// - `name`: The name of the variable to get the possible datasets of.
    ///
    /// # Returns
    /// A reference to the list of possible values for the given variable.
    #[inline]
    pub fn get_var(&self, name: impl AsRef<str>) -> &HashSet<Data> { self.vars.get(name.as_ref()).unwrap_or(&*EMPTY_IDS) }

    /// The extend function extends this table with the given one, i.e., all of the possibilities are merged.
    ///
    /// # Arguments
    /// - `other`: The other table to merge with this one.
    pub fn extend(&mut self, other: Self) {
        // Add each of the functions in other that are missing here
        for (name, ids) in other.funcs {
            if let Some(self_ids) = self.funcs.get_mut(&name) {
                self_ids.extend(ids);
            } else {
                self.funcs.insert(name, ids);
            }
        }

        // Do the same for all variables
        for (name, ids) in other.vars {
            if let Some(self_ids) = self.vars.get_mut(&name) {
                self_ids.extend(ids);
            } else {
                self.vars.insert(name, ids);
            }
        }
    }
}

impl Default for DataState {
    #[inline]
    fn default() -> Self { Self::new() }
}



/// Defines whatever we need to remember w.r.t. compile-time in between two submissions of part of a workflow (i.e., repl-runs).
#[derive(Clone, Debug)]
pub struct CompileState {
    /// Contains the offset (in lines) of this snippet compared to previous snippets in the source text.
    pub offset: usize,

    /// Defines the global table currently in the workflow (which contains the nested function tables).
    pub table:  TableState,
    /// Contains functions, mapped by function name to already very neatly compiled edges.
    pub bodies: HashMap<String, Vec<Edge>>,

    /// Contains functions and variables and the possible datasets they may evaluate to.
    pub data: DataState,
}

impl CompileState {
    /// Constructor for the CompileState that initializes it as new.
    ///
    /// # Returns
    /// A new CompileState instance.
    #[inline]
    pub fn new() -> Self {
        Self {
            offset: 0,

            table:  TableState::new(),
            bodies: HashMap::new(),

            data: DataState::new(),
        }
    }
}

impl Default for CompileState {
    #[inline]
    fn default() -> Self { Self::new() }
}
