//  VTABLE.rs
//    by Lut99
// 
//  Created:
//    24 Oct 2022, 15:42:52
//  Last edited:
//    19 Jan 2023, 15:23:07
//  Auto updated?
//    Yes
// 
//  Description:
//!   Implements the VirtualSymbolTable, which is a struct wrapping
//!   multiple tables but acts like one to be able to transparently handle
//!   scopes at runtime.
// 

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;

use brane_ast::ast::{ClassDef, FunctionDef, SymTable, TaskDef, VarDef};


/***** CONSTANTS *****/
lazy_static::lazy_static!(
    /// A static, empty map we can refer to.
    static ref EMPTY_RESULTS: HashMap<String, String> = HashMap::new();
);





/***** LIBRARY *****/
/// A VirtualTableIterator does some dope iteration over one of the fields of a VirtualSymTable.
#[derive(Debug)]
pub struct VirtualSymTableIterator<'a, T> {
    /// The current scope
    scope_i : usize,
    /// The current index in that scope
    i       : usize,

    /// The list of scopes
    scopes : &'a [Arc<SymTable>],
    /// The phantom type.
    _type  : PhantomData<T>,
}

impl<'a, T> VirtualSymTableIterator<'a, T> {
    /// Private constructor for the VirtualSymTableIterator.
    /// 
    /// # Arguments
    /// - `scopes`: The list of scopes to iterate over.
    /// 
    /// # Returns
    /// A new VirtualSymTableIterator instance, ready for iteration.
    #[inline]
    fn new(scopes: &'a [Arc<SymTable>]) -> Self {
        Self {
            scope_i : 0,
            i       : 0,

            scopes,
            _type : PhantomData::default(),
        }
    }
}

impl<'a> Iterator for VirtualSymTableIterator<'a, ClassDef> {
    type Item = (usize, &'a ClassDef);

    fn next(&mut self) -> Option<Self::Item> {
        // If out-of-range of the scopes, None
        if self.scope_i >= self.scopes.len() { return None; }

        // See if we move to the next scope
        if self.scope_i < self.scopes.len() - 1 && self.i >= self.scopes[self.scope_i + 1].classes.offset() {
            self.scope_i += 1;
        }

        // Return the element (if any)
        if self.scope_i < self.scopes[self.scope_i].classes.offset() + self.scopes[self.scope_i].classes.len() {
            let res = (self.scope_i, &self.scopes[self.scope_i].classes[self.scope_i]);
            self.scope_i += 1;
            Some(res)
        } else {
            None
        }
    }
}



/// A VirtualTable cleverly (if I say so myself) combines multiple TableLists into one, revealing the actual scope at this point in the AST. It should be used as a stack to keep track of scopes.
#[derive(Clone, Debug)]
pub struct VirtualSymTable {
    /// The list of scopes we search every time
    scopes : Vec<Arc<SymTable>>,
}

impl VirtualSymTable {
    /// Constructor for the VirtualTable that initializes it empty (main scope pending).
    /// 
    /// # Returns
    /// A new VirtualTable instance.
    #[inline]
    pub fn new() -> Self {
        Self {
            scopes : vec![],
        }
    }

    /// Constructor for the VirtualTable that initializes it with the given 'main' SymTable.
    /// 
    /// # Arguments
    /// - `table`: The global SymTable to start with.
    /// 
    /// # Returns
    /// A new VirtualTable instance with the given global (state) scope.
    #[inline]
    pub fn with(table: Arc<SymTable>) -> Self {
        Self {
            scopes : vec![ table ],
        }
    }



    /// Pushes the given table's scope on top of the VirtualTable.
    /// 
    /// # Arguments
    /// - `table`: The nested TableState who's scope to add.
    /// 
    /// # Returns
    /// Nothing, but does change the VirtualTable to also contain this scope.
    #[inline]
    pub fn push(&mut self, table: Arc<SymTable>) {
        // Simply add references to all scopes
        self.scopes.push(table);
    }

    /// Pops the top TableState off the internal scopes.
    /// 
    /// # Returns
    /// The popped SymTable that can be used to determine what variable have been declared in this scope.
    /// 
    /// # Panics
    /// This function may panic if there are no scopes anymore.
    #[inline]
    pub fn pop(&mut self) -> Arc<SymTable> {
        // Simply add references to all scopes
        match self.scopes.pop() {
            Some(scope) => scope,
            None        => { panic!("Attempted to pop scope, but no scopes left"); },
        }
    }



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
    pub fn func(&self, index: usize) -> &FunctionDef {
        // Find the correct list
        for s in self.scopes.iter().rev() {
            if index >= s.funcs.offset() {
                return &s.funcs[index];
            }
        }

        // Failed to find it
        panic!("Undeclared function '{}'", index);
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
    pub fn task(&self, index: usize) -> &TaskDef {
        // Find the correct list
        for s in self.scopes.iter().rev() {
            if index >= s.tasks.offset() {
                return &s.tasks[index];
            }
        }

        // Failed to find it
        panic!("Undeclared task '{}'", index);
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
    pub fn class(&self, index: usize) -> &ClassDef {
        // Find the correct list
        for s in self.scopes.iter().rev() {
            if index >= s.classes.offset() {
                return &s.classes[index];
            }
        }

        // Failed to find it
        panic!("Undeclared class '{}'", index);
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
    pub fn var(&self, index: usize) -> &VarDef {
        // Find the correct list
        for s in self.scopes.iter().rev() {
            if index >= s.vars.offset() {
                return &s.vars[index];
            }
        }

        // Failed to find it
        panic!("Undeclared variable '{}'", index);
    }



    /// Flattens the entire virtual symbol table into a single symtable that represents the current accessible scope.
    /// 
    /// # Returns
    /// A new SymTable that is the currently accessible scope in one.
    pub fn flatten(&self) -> SymTable {
        let mut res: SymTable = SymTable::new();
        for i in 0..self.scopes.len() - 1 {
            // Add all definitions in this scope that are not shadowed by the next
            res.funcs.append(&mut self.scopes[i].funcs.enumerate().filter_map(|(i, f)| if i < self.scopes[i + 1].funcs.offset() { Some(f.clone()) } else { None }).collect());
            res.tasks.append(&mut self.scopes[i].tasks.enumerate().filter_map(|(i, t)| if i < self.scopes[i + 1].tasks.offset() { Some(t.clone()) } else { None }).collect());
            res.classes.append(&mut self.scopes[i].classes.enumerate().filter_map(|(i, c)| if i < self.scopes[i + 1].classes.offset() { Some(c.clone()) } else { None }).collect());
            res.vars.append(&mut self.scopes[i].vars.enumerate().filter_map(|(i, v)| if i < self.scopes[i + 1].vars.offset() { Some(v.clone()) } else { None }).collect());
        }

        // The last scope cannot be shadowed
        if !self.scopes.is_empty() {
            res.funcs.append(&mut self.scopes[self.scopes.len() - 1].funcs.iter().cloned().collect());
            res.tasks.append(&mut self.scopes[self.scopes.len() - 1].tasks.iter().cloned().collect());
            res.classes.append(&mut self.scopes[self.scopes.len() - 1].classes.iter().cloned().collect());
            res.vars.append(&mut self.scopes[self.scopes.len() - 1].vars.iter().cloned().collect());
        }

        // Add the list of results for good measure
        if !self.scopes.is_empty() {
            res.results = self.scopes[0].results.clone();
        }

        // Done
        res
    }

    /// Iterates over all classes in scope, in-order.
    #[inline]
    pub fn classes(&self) -> VirtualSymTableIterator<'_, ClassDef> { VirtualSymTableIterator::new(&self.scopes) }

    /// Returns the intermediate results in the scopes.
    #[inline]
    pub fn results(&self) -> &HashMap<String, String> { if !self.scopes.is_empty() { &self.scopes[0].results } else { &EMPTY_RESULTS } }
}

impl Default for VirtualSymTable {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
