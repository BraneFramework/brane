//  FRAME STACK.rs
//    by Lut99
//
//  Created:
//    12 Sep 2022, 10:45:50
//  Last edited:
//    14 Nov 2024, 17:21:53
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the FrameStack, which is a more lightweight stack meant
//!   specifically for pushing return addresses and such.
//

use std::collections::HashMap;
use std::sync::Arc;

use specifications::pc::ProgramCounter;
use specifications::wir::data_type::DataType;
use specifications::wir::func_id::FunctionId;
use specifications::wir::{SymTable, VarDef};

pub use crate::errors::FrameStackError as Error;
use crate::value::Value;


/***** HELPER SRUCTS *****/
/// Defines a single Frame on the FrameStack.
#[derive(Clone, Debug)]
struct Frame {
    /// The function definition of the calling function. If usize::MAX, that means it's the main.
    def:  usize,
    /// The variables that live within this frame, mapped by their definition index.
    vars: HashMap<usize, Option<Value>>,
    /// The return address to return to after returning from this frame.
    ret:  ProgramCounter,
}

impl Frame {
    /// Creates a new(function/normal) frame for the given function.
    ///
    /// # Arguments
    /// - `def`: The function to create a new frame for.
    /// - `ret`: The return address (pair) to return to.
    /// - `table`: The table to resolve the definition in.
    ///
    /// # Returns
    /// A new Frame instance.
    #[inline]
    fn new(def: usize, ret: ProgramCounter) -> Self { Self { def, vars: HashMap::new(), ret } }
}





/***** LIBRARY *****/
/// Implements a FrameStack, which is used to keep track of function calls and their expected return types.
#[derive(Clone, Debug)]
pub struct FrameStack {
    /// The stack itself
    data:  Vec<Frame>,
    /// The virtual table that is also a stack but for scopes.
    table: Arc<SymTable>,
}

impl FrameStack {
    /// Constructor for the FrameStack, which initializes it with the given size.
    ///
    /// # Arguments
    /// - `size`: The size of the FrameStack.
    /// - `table`: The global scope to start with what (and what variables are) is in scope.
    ///
    /// # Returns
    /// A new FrameStack instance.
    #[inline]
    pub fn new(size: usize, table: Arc<SymTable>) -> Self {
        // Prepare the main frame
        let mut data: Vec<Frame> = Vec::with_capacity(size);
        data.push(Frame { def: usize::MAX, vars: HashMap::new(), ret: ProgramCounter::new(FunctionId::Main, usize::MAX) });

        // Run it
        Self { data, table }
    }

    /// Forks the framestack, which copies the existing variables in-scope into a single frame that is the new main.
    ///
    /// # Returns
    /// A new FrameStack instance that can be used in a forked thread.
    pub fn fork(&self) -> Self {
        // Collect all variables into one thingamabob
        let vars: HashMap<usize, Option<Value>> =
            self.table.vars.iter().enumerate().map(|(i, _)| (i, Some(self.get(i).unwrap_or(&Value::Void).clone()))).collect();

        // Now manually create the stack with a custom frame
        let mut data: Vec<Frame> = Vec::with_capacity(self.data.capacity());
        data.push(Frame { def: usize::MAX, vars, ret: ProgramCounter::new(FunctionId::Main, usize::MAX) });
        Self { data, table: self.table.clone() }
    }

    /// Updates the internal table to be the same as the given one.
    ///
    /// This is useful if the workflow is updating its own states.
    ///
    /// # Arguments
    /// - `table`: The new table to use as ground truth.
    ///
    /// # Returns
    /// Nothing, but does update the internal table.
    #[inline]
    pub fn update_table(&mut self, table: Arc<SymTable>) { self.table = table; }

    /// Pushes a new Frame onto the FrameStack.
    ///
    /// # Arguments
    /// - `def`: The function to create a new frame for.
    /// - `ret`: The return address (pair) to return to.
    ///
    /// # Returns
    /// Nothing, but does set it internally.
    ///
    /// # Errors
    /// This function may error if the FrameStack overflows.
    pub fn push(&mut self, def: usize, ret: ProgramCounter) -> Result<(), Error> {
        // Create the new Frame & insert it
        self.data.push(Frame::new(def, ret));
        Ok(())
    }

    /// Pops the top value off of the FrameStack, returning the expected data type and return address.
    ///
    /// # Returns
    /// A [`ProgramCounter`] denoting the return address and expected return type, respectively. If the main was popped, however, then the return address is `(usize::MAX, usize::MAX)`.
    ///
    /// # Errors
    /// This function may error if there was nothing left on the stack.
    #[inline]
    pub fn pop(&mut self) -> Result<(ProgramCounter, DataType), Error> {
        // Attempt to pop
        match self.data.pop() {
            Some(frame) => {
                // Get the return type (if any)
                let ret_type: DataType =
                    if frame.def < usize::MAX { self.table.func(FunctionId::Func(frame.def)).ret.clone() } else { DataType::Any };

                // Return the next pointer after having popped the scope
                Ok((frame.ret, ret_type))
            },
            None => Err(Error::EmptyError),
        }
    }

    /// Declares a variable with the given index.
    ///
    /// # Arguments
    /// - `def`: The variable to declare.
    ///
    /// # Returns
    /// Nothing, but does allow the variable to have a value from this point onwards.
    ///
    /// # Errors
    /// This function may error if the given definition is unknown.
    pub fn declare(&mut self, def: usize) -> Result<(), Error> {
        // Throw a special error if the stack is empty
        if self.data.is_empty() {
            return Err(Error::EmptyError);
        }

        // Add to the recentmost frame
        if let Some(frame) = self.data.last_mut() {
            if frame.vars.insert(def, None).is_some() {
                return Err(Error::DuplicateDeclaration { name: self.table.var(def).name.clone() });
            }
        }

        // Done
        Ok(())
    }

    /// Undclares a variable with the given index, effectively brining it back to uninitialized status.
    ///
    /// # Arguments
    /// - `def`: The variable to undeclare.
    ///
    /// # Returns
    /// Nothing, but does require the variable to be declared before it can be used.
    ///
    /// # Errors
    /// This function may error if the given definition is unknown.
    pub fn undeclare(&mut self, def: usize) -> Result<(), Error> {
        // Throw a special error if the stack is empty
        if self.data.is_empty() {
            return Err(Error::EmptyError);
        }

        // Search the frames (in reverse order)
        if let Some(frame) = self.data.last_mut() {
            if frame.vars.remove(&def).is_none() {
                return Err(Error::UndeclaredUndeclaration { name: self.table.var(def).name.clone() });
            }
        }

        // Done
        Ok(())
    }

    /// Sets the variable with the given index to the given Value.
    ///
    /// # Arguments
    /// - `def`: The variable to set.
    /// - `value`: The new Value to set it to.
    ///
    /// # Returns
    /// Nothing, but does update the given variable's value.
    ///
    /// # Errors
    /// This function may error if there was nothing left on the stack or if the given variable was not declared.
    pub fn set(&mut self, def: usize, value: Value) -> Result<(), Error> {
        // Throw a special error if the stack is empty
        if self.data.is_empty() {
            return Err(Error::EmptyError);
        }

        // Check the data types agree
        let var: &VarDef = self.table.var(def);
        let val_type: DataType = value.data_type(&self.table);
        if !val_type.allowed_by(&var.data_type) {
            return Err(Error::VarTypeError { name: var.name.clone(), got: val_type, expected: var.data_type.clone() });
        }

        // Search the frames (in reverse order)
        for f in self.data.iter_mut().rev() {
            if let Some(v) = f.vars.get_mut(&def) {
                *v = Some(value);
                return Ok(());
            }
        }

        // We never found
        Err(Error::UndeclaredVariable { name: self.table.var(def).name.clone() })
    }

    /// Gets the value of the variable with the given index.
    ///
    /// # Arguments
    /// - `def`: The variable to get.
    ///
    /// # Returns
    /// The current value of the variable.
    ///
    /// # Errors
    /// This function may error if there was nothing left on the stack or if the given variable was not declared.
    pub fn get(&self, def: usize) -> Result<&Value, Error> {
        // Throw a special error if the stack is empty
        if self.data.is_empty() {
            return Err(Error::EmptyError);
        }

        // Search the frames (in reverse order)
        for f in self.data.iter().rev() {
            if let Some(v) = f.vars.get(&def) {
                match v {
                    Some(v) => {
                        return Ok(v);
                    },
                    None => return Err(Error::UninitializedVariable { name: self.table.var(def).name.clone() }),
                }
            }
        }

        // We never found
        Err(Error::UndeclaredVariable { name: self.table.var(def).name.clone() })
    }

    /// Returns the total capacity of the FrameStack. Using any more than this will result in overflows.
    #[inline]
    pub fn capacity(&self) -> usize { self.data.capacity() }

    /// Returns if the framestack is currently empty.
    #[inline]
    pub fn is_empty(&self) -> bool { self.data.is_empty() }

    /// Returns the number of frames currently on the FrameStack.
    #[inline]
    pub fn len(&self) -> usize { self.data.len() }

    /// Returns the internal table.
    #[inline]
    pub fn table(&self) -> &SymTable { &self.table }
}
