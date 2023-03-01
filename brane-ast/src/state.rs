//  STATE.rs
//    by Lut99
// 
//  Created:
//    16 Sep 2022, 08:22:47
//  Last edited:
//    01 Mar 2023, 09:50:25
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines and implements various structures to keep track of the
//!   compilation state in between snippet compilation runs.
// 

use std::cell::{RefCell, RefMut};
use std::collections::{HashMap, HashSet};
use std::ops::{Index, IndexMut};
use std::rc::Rc;

use serde::{Deserialize, Serialize};

use brane_dsl::{DataType, TextRange};
use brane_dsl::data_type::{ClassSignature, FunctionSignature};
use brane_dsl::symbol_table::{ClassEntry, FunctionEntry, SymbolTable, VarEntry};
use brane_dsl::ast::Data;
use specifications::package::Capability;
use specifications::version::Version;

use crate::spec::{BuiltinClasses, BuiltinFunctions};
use crate::ast::{ClassDef, ComputeTaskDef, Edge, FunctionDef, SymTable, TaskDef, VarDef};


/***** STATICS *****/
lazy_static!{
    /// The empty list referenced when a function or variable in the DataTable does not exist.
    static ref EMPTY_IDS: HashSet<Data> = HashSet::new();
}





/***** AUXILLARY *****/
/// A simple wrapper around a struct such that it allows a specific offset to be used when indexing.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TableList<T> {
    /// The internal struct we wrap
    #[serde(rename = "d")]
    pub data   : Vec<T>,
    /// The offset that is applied to all of the indices.
    #[serde(rename = "o")]
    pub offset : usize,
}

impl<T> TableList<T> {
    /// Constructor for the TableList that initializes it to empty.
    /// 
    /// # Arguments
    /// - `offset`: The offset to use when indexing this TableList.
    /// 
    /// # Returns
    /// A new TableList instance.
    #[inline]
    pub fn new(offset: usize) -> Self {
        Self {
            data : Vec::new(),
            offset,
        }
    }

    /// Constructor for the TableList that initializes it with a given capacity (but otherwise still empty).
    /// 
    /// # Arguments
    /// - `offset`: The offset to use when indexing this TableList.
    /// - `capacity`: The initial capacity to initialize the internal vector to.
    /// 
    /// # Returns
    /// A new TableList instance.
    #[inline]
    pub fn with_capacity(offset: usize, capacity: usize) -> Self {
        Self {
            data : Vec::with_capacity(capacity),
            offset,
        }
    }



    /// Pushes the given item to the back of the list.
    /// 
    /// # Arguments
    /// - `elem`: The new element to push.
    /// 
    /// # Returns
    /// The index of the new element for convenience. This is also computable as the offset + the length of the list before this element was added.
    pub fn push(&mut self, elem: T) -> usize {
        let index: usize = self.offset + self.data.len();
        self.data.push(elem);
        index
    }

    /// Appends the elements in the given Vec(tor) to the end of this TableList.
    /// 
    /// Note that the given list will give up ownership of them, i.e., they are transferred to this TableList (leaving the other empty).
    /// 
    /// # Arguments
    /// - `other`: The other vector to take the elements from.
    /// 
    /// # Returns
    /// Nothing, but does add the elements internally (in an optimal way).
    #[inline]
    pub fn append(&mut self, other: &mut Vec<T>) {
        self.data.append(other);
    }



    /// Reserves enough space in the TableList for _at least_ the given number of _additional_ elements.
    /// 
    /// # Arguments
    /// - `extra_capacity`: The additional capacity to at least request space for.
    /// 
    /// # Returns
    /// Nothing, but does allocate the extra space internally.
    #[inline]
    pub fn reserve(&mut self, extra_capacity: usize) {
        self.data.reserve(extra_capacity);
    }



    /// Returns an iterator over the elements in the TableList.
    /// 
    /// Note, though, that if you tend to use `enumerate()` and want accurate indices (instead of those starting with 0), call `enumerate` on this struct directly instead.
    /// 
    /// # Returns
    /// An iterator over the internal vector.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<T> { self.data.iter() }


    /// Returns a(n) (mutable) iterator over the elements in the TableList.
    /// 
    /// Note, though, that if you tend to use `enumerate()` and want accurate indices (instead of those starting with 0), call `enumerate` on this struct directly instead.
    /// 
    /// # Returns
    /// An iterator over the internal vector.
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<T> { self.data.iter_mut() }

    /// Returns an enumerating iterator over the elements in the TableList, but with indices that have a correct offset.
    /// 
    /// # Returns
    /// An iterator over the internal vector that enumerates with offset indices.
    #[inline]
    pub fn enumerate(&self) -> impl Iterator<Item = (usize, &T)> { self.data.iter().enumerate().map(|(i, d)| (self.offset + i, d)) }

    /// Returns a(n) (mutable,) enumerating iterator over the elements in the TableList, but with indices that have a correct offset.
    /// 
    /// # Returns
    /// An iterator over the internal vector that enumerates with offset indices.
    #[inline]
    pub fn enumerate_mut(&mut self) -> impl Iterator<Item = (usize, &mut T)> { self.data.iter_mut().enumerate().map(|(i, d)| (self.offset + i, d)) }



    /// Returns the internal offset in this TableList.
    #[inline]
    pub fn offset(&self) -> usize { self.offset }

    /// Returns the number of elements stored in this TableList.
    #[inline]
    pub fn len(&self) -> usize { self.data.len() }

    /// Returns true iff this TableList has no entries in it (equivalent to `TableList::len() == 0`).
    #[inline]
    pub fn is_empty(&self) -> bool { self.data.is_empty() }

    /// Returns the capacity of the internal vector (i.e., for how many elements it has already reserved space). It is guaranteed that `TableList::capacity() >= TableList::len()`.
    #[inline]
    pub fn capacity(&self) -> usize { self.data.capacity() }
}

impl<T> Index<usize> for TableList<T> {
    type Output = T;

    #[inline]
    fn index(&self, idx: usize) -> &Self::Output {
        if idx < self.offset { panic!("Cannot index a TableList with an index smaller than its offset (i.e., !({} >= {}))", idx, self.offset) }
        if self.data.is_empty() { panic!("Attempted to index empty TableList (index: {} (got: {}))", idx - self.offset, idx); }
        if idx - self.offset >= self.data.len() { panic!("Index {} is out-of-range for TableList with index range {}..{} (i.e., {} is out-of-range for a vector of size {})", idx - self.offset, self.offset, self.offset + self.data.len(), idx, self.data.len()); }
        &self.data[idx - self.offset]
    }
}
impl<T> IndexMut<usize> for TableList<T> {
    #[inline]
    fn index_mut(&mut self, idx: usize) -> &mut Self::Output {
        if idx < self.offset { panic!("Cannot index a TableList with an index smaller than its offset (i.e., !({} >= {}))", idx, self.offset) }
        if self.data.is_empty() { panic!("Attempted to index empty TableList (index: {} (got: {}))", idx - self.offset, idx); }
        if idx - self.offset >= self.data.len() { panic!("Index {} is out-of-range for TableList with index range {}..{} (i.e., {} is out-of-range for a vector of size {})", idx - self.offset, self.offset, self.offset + self.data.len(), idx, self.data.len()); }
        &mut self.data[idx - self.offset]
    }
}

impl<T> IntoIterator for TableList<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}
impl<'a, T> IntoIterator for &'a TableList<T> {
    type Item     = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}
impl<'a, T> IntoIterator for &'a mut TableList<T> {
    type Item     = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.data.iter_mut()
    }
}

impl<T> From<(Vec<T>, usize)> for TableList<T> {
    #[inline]
    fn from(value: (Vec<T>, usize)) -> Self {
        Self {
            data   : value.0,
            offset : value.1,
        }
    }
}
impl<const N: usize, T> From<([T; N], usize)> for TableList<T>
where
    T: Clone,
{
    #[inline]
    fn from(value: ([T; N], usize)) -> Self {
        Self {
            data   : value.0.to_vec(),
            offset : value.1,
        }
    }
}
impl<const N: usize, T> From<(&[T; N], usize)> for TableList<T>
where
    T: Clone,
{
    #[inline]
    fn from(value: (&[T; N], usize)) -> Self {
        Self {
            data   : value.0.to_vec(),
            offset : value.1,
        }
    }
}



/// Defines a shortcut for a VirtualTable over TableStates.
pub type VirtualTableState<'a> = VirtualTable<'a, FunctionState, TaskState, ClassState, VarState>;

/// Defines a shortcut for a VirtualTable over SymTables.
pub type VirtualSymTable<'a> = VirtualTable<'a, FunctionDef, TaskDef, ClassDef, VarDef>;

/// A VirtualTable cleverly (if I say so myself) combines multiple TableLists into one, revealing the actual scope at this point in the AST. It should be used as a stack to keep track of scopes.
#[derive(Clone, Debug)]
pub struct VirtualTable<'a, F, T, C, V> {
    /// The list of scopes that this table current uses. This specific field keeps track of the function namespace.
    f_scopes : Vec<&'a TableList<F>>,
    /// The list of scopes that this table current uses. This specific field keeps track of the task namespace.
    t_scopes : Vec<&'a TableList<T>>,
    /// The list of scopes that this table current uses. This specific field keeps track of the class namespace.
    c_scopes : Vec<&'a TableList<C>>,
    /// The list of scopes that this table current uses. This specific field keeps track of the variable namespace.
    v_scopes : Vec<&'a TableList<V>>,
}

impl<'a> VirtualTable<'a, FunctionState, TaskState, ClassState, VarState> {
    /// Constructor for the VirtualTable that initializes it with the given 'main' TableState.
    /// 
    /// # Arguments
    /// - `table`: The global TableState to start with.
    /// 
    /// # Returns
    /// A new VirtualTable instance with the given global (state) scope.
    pub fn with(table: &'a TableState) -> Self {
        Self {
            f_scopes : vec![ &table.funcs ],
            t_scopes : vec![ &table.tasks ],
            c_scopes : vec![ &table.classes ],
            v_scopes : vec![ &table.vars ],
        }
    }



    /// Pushes the given table's scope on top of the VirtualTable.
    /// 
    /// # Arguments
    /// - `table`: The nested TableState who's scope to add.
    /// 
    /// # Returns
    /// Nothing, but does change the VirtualTable to also contain this scope.
    pub fn push(&mut self, table: &'a TableState) {
        // Simply add references to all scopes
        self.f_scopes.push(&table.funcs);
        self.t_scopes.push(&table.tasks);
        self.c_scopes.push(&table.classes);
        self.v_scopes.push(&table.vars);
    }

    /// Pops the top TableState off the internal scopes.
    /// 
    /// # Returns
    /// Nothing, but does change the VirtualTable to not contain the most nested scope anymore.
    /// 
    /// # Panics
    /// This function may panic if there are no scopes anymore.
    pub fn pop(&mut self) {
        // Simply add references to all scopes
        if self.f_scopes.pop().is_none() { panic!("Attempted to pop function namespace, but no scopes left"); };
        if self.t_scopes.pop().is_none() { panic!("Attempted to pop task namespace, but no scopes left"); };
        if self.c_scopes.pop().is_none() { panic!("Attempted to pop classes namespace, but no scopes left"); };
        if self.v_scopes.pop().is_none() { panic!("Attempted to pop variable namespace, but no scopes left"); };
    }
}

impl<'a> VirtualTable<'a, FunctionDef, TaskDef, ClassDef, VarDef> {
    /// Constructor for the VirtualTable that initializes it with the given 'main' SymTable.
    /// 
    /// # Arguments
    /// - `table`: The global SymTable to start with.
    /// 
    /// # Returns
    /// A new VirtualTable instance with the given global (state) scope.
    pub fn with(table: &'a SymTable) -> Self {
        Self {
            f_scopes : vec![ &table.funcs ],
            t_scopes : vec![ &table.tasks ],
            c_scopes : vec![ &table.classes ],
            v_scopes : vec![ &table.vars ],
        }
    }



    /// Pushes the given table's scope on top of the VirtualTable.
    /// 
    /// # Arguments
    /// - `table`: The nested SymTable who's scope to add.
    /// 
    /// # Returns
    /// Nothing, but does change the VirtualTable to also contain this scope.
    pub fn push(&mut self, table: &'a SymTable) {
        // Simply add references to all scopes
        self.f_scopes.push(&table.funcs);
        self.t_scopes.push(&table.tasks);
        self.c_scopes.push(&table.classes);
        self.v_scopes.push(&table.vars);
    }

    /// Pops the top TableState off the internal scopes.
    /// 
    /// # Returns
    /// Nothing, but does change the VirtualTable to not contain the most nested scope anymore.
    /// 
    /// # Panics
    /// This function may panic if there are no scopes anymore.
    pub fn pop(&mut self) {
        // Simply add references to all scopes
        if self.f_scopes.pop().is_none() { panic!("Attempted to pop function namespace, but no scopes left"); };
        if self.t_scopes.pop().is_none() { panic!("Attempted to pop task namespace, but no scopes left"); };
        if self.c_scopes.pop().is_none() { panic!("Attempted to pop classes namespace, but no scopes left"); };
        if self.v_scopes.pop().is_none() { panic!("Attempted to pop variable namespace, but no scopes left"); };
    }
}

impl<'a, F, T, C, V> VirtualTable<'a, F, T, C, V> {
    /// Retrieves the function with the given index.
    /// 
    /// # Arguments
    /// - `index`: The index to resolve in the current scope.
    /// 
    /// # Returns
    /// A reference to the referenced function.
    /// 
    /// # Panics
    /// This function panics if not function with the given index could be found.
    pub fn func(&self, index: usize) -> &'a F {
        // Find the correct list
        for l in self.f_scopes.iter().rev() {
            if index >= l.offset() {
                return &l[index];
            }
        }

        // Failed to find it
        panic!("Undeclared function '{index}'");
    }

    /// Retrieves the task with the given index.
    /// 
    /// # Arguments
    /// - `index`: The index to resolve in the current scope.
    /// 
    /// # Returns
    /// A reference to the referenced task.
    /// 
    /// # Panics
    /// This function panics if not task with the given index could be found.
    pub fn task(&self, index: usize) -> &'a T {
        // Find the correct list
        for l in self.t_scopes.iter().rev() {
            if index >= l.offset() {
                return &l[index];
            }
        }

        // Failed to find it
        panic!("Undeclared task '{index}'");
    }

    /// Retrieves the class with the given index.
    /// 
    /// # Arguments
    /// - `index`: The index to resolve in the current scope.
    /// 
    /// # Returns
    /// A reference to the referenced class.
    /// 
    /// # Panics
    /// This function panics if not class with the given index could be found.
    pub fn class(&self, index: usize) -> &'a C {
        // Find the correct list
        for l in self.c_scopes.iter().rev() {
            if index >= l.offset() {
                return &l[index];
            }
        }

        // Failed to find it
        panic!("Undeclared class '{index}'");
    }

    /// Retrieves the variable with the given index.
    /// 
    /// # Arguments
    /// - `index`: The index to resolve in the current scope.
    /// 
    /// # Returns
    /// A reference to the referenced variable.
    /// 
    /// # Panics
    /// This function panics if not variable with the given index could be found.
    pub fn var(&self, index: usize) -> &'a V {
        // Find the correct list
        for l in self.v_scopes.iter().rev() {
            if index >= l.offset() {
                return &l[index];
            }
        }

        // Failed to find it
        panic!("Undeclared variable '{index}'");
    }
}





/***** LIBRARY *****/
/// Defines a 'TableState', which is the CompileState's notion of a symbol table.
#[derive(Clone, Debug)]
pub struct TableState {
    /// The functions that are kept for next compilation junks
    pub funcs   : TableList<FunctionState>,
    /// The tasks that are kept for next compilation junks
    pub tasks   : TableList<TaskState>,
    /// The functions that are kept for next compilation junks
    pub classes : TableList<ClassState>,
    /// The functions that are kept for next compilation junks
    pub vars    : TableList<VarState>,

    /// The list of results introduced in this workflow.
    pub results : HashMap<String, String>,
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
        let mut funcs : TableList<FunctionState> = TableList::from((BuiltinFunctions::all_into_state(), 0));
        let tasks     : TableList<TaskState>     = TableList::from(([], 0));
        let classes   : TableList<ClassState>    = TableList::from((BuiltinClasses::all_into_state(&mut funcs), 0));
        let vars      : TableList<VarState>      = TableList::from(([], 0));

        // use that to construct the rest
        Self {
            funcs,
            tasks,
            classes,
            vars,

            results : HashMap::new(),
        }
    }

    /// Constructor for the TableState that doesn't even initialize it to builtins.
    /// 
    /// # Arguments
    /// - `n_funcs`: The number of functions already defined in the parent table(s) by the time this table rolls around.
    /// - `n_tasks`: The number of tasks already defined in the parent table(s) by the time this table rolls around.
    /// - `n_classes`: The number of classes already defined in the parent table(s) by the time this table rolls around.
    /// - `n_vars`: The number of variables already defined in the parent table(s) by the time this table rolls around.
    /// 
    /// # Returns
    /// A new, completely empty instance of the TableState.
    #[inline]
    pub fn empty(n_funcs: usize, n_tasks: usize, n_classes: usize, n_vars: usize) -> Self {
        Self {
            funcs   : TableList::new(n_funcs),
            tasks   : TableList::new(n_tasks),
            classes : TableList::new(n_classes),
            vars    : TableList::new(n_vars),

            results : HashMap::new(),
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
            funcs   : TableList::new(usize::MAX),
            tasks   : TableList::new(usize::MAX),
            classes : TableList::new(usize::MAX),
            vars    : TableList::new(usize::MAX),

            results : HashMap::new(),
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
        for (i, f) in self.funcs.enumerate() {
            // Create the thingamabob and set the index
            let mut entry: FunctionEntry = f.into();
            entry.index = i;

            // Insert it
            if let Err(err) = st.add_func(entry) { panic!("Failed to inject previously defined function in global symbol table: {err}"); }
        }

        // Do tasks...
        for (i, t) in self.tasks.enumerate() {
            // Create the thingamabob and set the index
            let mut entry: FunctionEntry = t.into();
            entry.index = i;

            // Insert it
            if let Err(err) = st.add_func(entry) { panic!("Failed to inject previously defined task in global symbol table: {err}"); }
        }

        // ...classes...
        for (i, c) in self.classes.enumerate() {
            // Create the thingamabob and set the index
            let mut entry: ClassEntry = c.into_entry(&self.funcs);
            entry.index = i;

            // Insert it
            if let Err(err) = st.add_class(entry) { panic!("Failed to inject previously defined class in global symbol table: {err}"); }
        }

        // ...and, finally, variables
        for (i, v) in self.vars.enumerate() {
            // Create the thingamabob and set the index
            let mut entry: VarEntry = v.into();
            entry.index = i;

            // Insert it
            if let Err(err) = st.add_var(entry) { panic!("Failed to inject previously defined variable in global symbol table: {err}"); }
        }
    }



    /// Returns the offset for the functions.
    #[inline]
    pub fn n_funcs(&self) -> usize { self.funcs.offset() + self.funcs.len() }

    /// Returns the offset for the tasks.
    #[inline]
    pub fn n_tasks(&self) -> usize { self.tasks.offset() + self.tasks.len() }

    /// Returns the offset for the classes.
    #[inline]
    pub fn n_classes(&self) -> usize { self.classes.offset() + self.classes.len() }

    /// Returns the offset for the variables.
    #[inline]
    pub fn n_vars(&self) -> usize { self.vars.offset() + self.vars.len() }
}

impl Default for TableState {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl From<TableState> for SymTable {
    fn from(value: TableState) -> Self {
        // Functions
        let funcs_offset: usize = value.funcs.offset();
        let mut funcs: TableList<FunctionDef> = TableList::with_capacity(funcs_offset, value.funcs.len());
        for f in value.funcs { funcs.push(f.into()); }

        // Tasks
        let tasks_offset: usize = value.tasks.offset();
        let mut tasks: TableList<TaskDef> = TableList::with_capacity(tasks_offset, value.tasks.len());
        for t in value.tasks { tasks.push(t.into()); }

        // Classes
        let classes_offset: usize = value.classes.offset();
        let mut classes: TableList<ClassDef> = TableList::with_capacity(classes_offset, value.classes.len());
        for c in value.classes { classes.push(c.into()); }

        // Finally, variables
        let vars_offset: usize = value.vars.offset();
        let mut vars: TableList<VarDef> = TableList::with_capacity(vars_offset, value.vars.len());
        for v in value.vars { vars.push(v.into()); }

        // Finally finally, the data & resultes
        let results : HashMap<String, String> = value.results;

        // Done; return them as a table
        Self::with(funcs, tasks, classes, vars, results)
    }
}

impl From<&TableState> for SymTable {
    fn from(value: &TableState) -> Self {
        Self::from(value.clone())
    }
}



/// Defines whatever we need to know of a function in between workflow snippet calls.
#[derive(Clone, Debug)]
pub struct FunctionState {
    /// The name of the function.
    pub name      : String,
    /// The signature of the function.
    pub signature : FunctionSignature,

    /// If this function is a method in a class, then the class' name is stored here.
    pub class_name : Option<String>,

    /// The TableState that keeps track of the function's scope.
    pub table : TableState,
    /// The range that links this function back to the source text.
    pub range : TextRange,
}

impl From<&FunctionState> for FunctionEntry {
    #[inline]
    fn from(value: &FunctionState) -> Self {
        Self {
            name      : value.name.clone(),
            signature : value.signature.clone(),
            params    : vec![],

            package_name    : None,
            package_version : None,
            class_name      : value.class_name.clone(),

            arg_names    : vec![],
            requirements : None,

            index : usize::MAX,

            range : value.range.clone(),
        }
    }
}

impl From<FunctionState> for FunctionDef {
    #[inline]
    fn from(value: FunctionState) -> Self {
        FunctionDef {
            name : value.name,
            args : value.signature.args.into_iter().map(|d| d.into()).collect(),
            ret  : value.signature.ret.into(),

            table : value.table.into(),
        }
    }
}



#[derive(Clone, Debug)]
pub struct TaskState {
    /// The name of the function.
    pub name         : String,
    /// The signature of the function.
    pub signature    : FunctionSignature,
    /// The names of the arguments. They are mapped by virtue of having the same index as in `signature.args`.
    pub arg_names    : Vec<String>,
    /// Any requirements for this function.
    pub requirements : HashSet<Capability>,

    /// The name of the package where this Task is stored.
    pub package_name    : String,
    /// The version of the package where this Task is stored.
    pub package_version : Version,

    /// The range that links this task back to the source text.
    pub range : TextRange,
}

impl From<&TaskState> for FunctionEntry {
    #[inline]
    fn from(value: &TaskState) -> Self {
        Self {
            name      : value.name.clone(),
            signature : value.signature.clone(),
            params    : vec![],

            package_name    : Some(value.package_name.clone()),
            package_version : Some(value.package_version),
            class_name      : None,

            arg_names    : value.arg_names.clone(),
            requirements : Some(value.requirements.clone()),

            index : usize::MAX,

            range : value.range.clone(),
        }
    }
}

impl From<TaskState> for TaskDef {
    #[inline]
    fn from(value: TaskState) -> Self {
        Self::Compute(ComputeTaskDef {
            package : value.package_name,
            version : value.package_version,

            function : Box::new(FunctionDef {
                name : value.name,
                args : value.signature.args.into_iter().map(|d| d.into()).collect(),
                ret  : value.signature.ret.into(),

                table : SymTable::new(),
            }),
            args_names   : value.arg_names,
            requirements : value.requirements,
        })
    }
}



/// Defines whatever we need to know of a class in between workflow snippet calls.
#[derive(Clone, Debug)]
pub struct ClassState {
    /// The name of the class.
    pub name    : String,
    /// The list of properties in this class.
    pub props   : Vec<VarState>,
    /// The list of methods in this class (as references to the global class list)
    pub methods : Vec<usize>,

    /// If this class is imported from a package, then the package's name is stored here.
    pub package_name    : Option<String>,
    /// If this class is imported from a package, then the package's version is stored here.
    pub package_version : Option<Version>,

    /// The range that links this class back to the source text.
    pub range : TextRange,
}

impl ClassState {
    /// Converts this ClassState into a ClassEntry, using the given list of functions to resolve the internal list.
    /// 
    /// # Arguments
    /// - `funcs`: The TableList of functions to resolve indices with.
    /// 
    /// # Returns
    /// A new ClassEntry instance.
    pub fn into_entry(&self, funcs: &TableList<FunctionState>) -> ClassEntry {
        // Create the symbol table
        let c_table: Rc<RefCell<SymbolTable>> = SymbolTable::new();
        {
            let mut cst: RefMut<SymbolTable> = c_table.borrow_mut();

            // Add the properties
            for p in &self.props {
                if let Err(err) = cst.add_var(p.into()) { panic!("Failed to insert class property into new class symbol table: {err}"); }
            }
            // Add the methods
            for m in &self.methods {
                if let Err(err) = cst.add_func((&funcs[*m]).into()) { panic!("Failed to insert class method into new class symbol table: {err}"); }
            }
        }

        // Create the entry with it
        ClassEntry {
            signature    : ClassSignature::new(self.name.clone()),
            symbol_table : c_table,

            package_name    : self.package_name.clone(),
            package_version : self.package_version,

            index : usize::MAX,

            range : self.range.clone(),
        }
    }
}

impl From<ClassState> for ClassDef {
    #[inline]
    fn from(value: ClassState) -> Self {
        ClassDef {
            name    : value.name,
            props   : value.props.into_iter().map(|v| v.into()).collect(),
            methods : value.methods,

            package : value.package_name,
            version : value.package_version,
        }
    }
}





/// Defines whatever we need to know of a variable in between workflow snippet calls.
#[derive(Clone, Debug)]
pub struct VarState {
    /// The name of the variable.
    pub name      : String,
    /// The data type of this variable.
    pub data_type : DataType,

    /// If this variable is a parameter in a function, then the function's name is stored here.
    pub function_name : Option<String>,
    /// If this variable is a property in a class, then the class' name is stored here.
    pub class_name    : Option<String>,

    /// The range that links this variable back to the source text.
    pub range : TextRange,
}

impl From<&VarState> for VarEntry {
    #[inline]
    fn from(value: &VarState) -> Self {
        Self {
            name      : value.name.clone(),
            data_type : value.data_type.clone(),

            function_name : value.function_name.clone(),
            class_name    : value.class_name.clone(),

            index : usize::MAX,

            range : value.range.clone(),
        }
    }
}

impl From<VarState> for VarDef {
    #[inline]
    fn from(value: VarState) -> Self {
        Self {
            name      : value.name,
            data_type : value.data_type.into(),
        }
    }
}



/// Defines a DataState, which is a bit like a symbol table for data identifiers - except that it's temporal (i.e., has a notion of values being overwritten).
#[derive(Clone, Debug)]
pub struct DataState {
    // /// Maps function names (=identifiers) to their current possible list of data identifiers _they return_. Since function bodies are constant, it may be expected the list of possible identifiers is also.
    // funcs : HashMap<*const RefCell<FunctionEntry>, HashSet<Data>>,
    // /// Maps variable names (=identifiers) to their current possible list of data identifiers they may be. An empty set implies it's not a Data or IntermediateResult struct.
    // vars  : HashMap<*const RefCell<VarEntry>, HashSet<Data>>,

    /// Maps function names (=identifiers) to their current possible list of data identifiers _they return_. Since function bodies are constant, it may be expected the list of possible identifiers is also.
    funcs : HashMap<String, HashSet<Data>>,
    /// Maps variable names (=identifiers) to their current possible list of data identifiers they may be. An empty set implies it's not a Data or IntermediateResult struct.
    vars  : HashMap<String, HashSet<Data>>,
}

impl DataState {
    /// Constructor for the DataTable that initializes it to empty.
    /// 
    /// # Returns
    /// A new DataTable instance.
    #[inline]
    pub fn new() -> Self {
        Self {
            funcs : HashMap::new(),
            vars  : HashMap::new(),
        }
    }



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
    pub fn set_funcs(&mut self, name: impl Into<String>, new_ids: HashSet<Data>) {
        self.funcs.insert(name.into(), new_ids);
    }

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
    pub fn set_vars(&mut self, name: impl Into<String>, new_ids: HashSet<Data>) {
        self.vars.insert(name.into(), new_ids);
    }



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
    pub fn get_func(&self, name: impl AsRef<str>) -> &HashSet<Data> {
        self.funcs.get(name.as_ref()).unwrap_or(&*EMPTY_IDS)
    }

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
    pub fn get_var(&self, name: impl AsRef<str>) -> &HashSet<Data> {
        self.vars.get(name.as_ref()).unwrap_or(&*EMPTY_IDS)
    }



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
    fn default() -> Self {
        Self::new()
    }
}



/// Defines whatever we need to remember w.r.t. compile-time in between two submissions of part of a workflow (i.e., repl-runs).
#[derive(Clone, Debug)]
pub struct CompileState {
    /// Contains the offset (in lines) of this snippet compared to previous snippets in the source text.
    pub offset : usize,

    /// Defines the global table currently in the workflow (which contains the nested function tables).
    pub table  : TableState,
    /// Contains functions, mapped by function name to already very neatly compiled edges.
    pub bodies : HashMap<String, Vec<Edge>>,

    /// Contains functions and variables and the possible datasets they may evaluate to.
    pub data : DataState,
}

impl CompileState {
    /// Constructor for the CompileState that initializes it as new.
    /// 
    /// # Returns
    /// A new CompileState instance.
    #[inline]
    pub fn new() -> Self {
        Self {
            offset : 0,

            table  : TableState::new(),
            bodies : HashMap::new(),

            data : DataState::new(),
        }
    }
}

impl Default for CompileState {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
