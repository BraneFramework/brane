//  VARREG.rs
//    by Lut99
// 
//  Created:
//    09 Sep 2022, 16:35:48
//  Last edited:
//    17 Jan 2023, 15:17:05
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines a VariableRegister, which stored out-of-stack values by
//!   variable index in the workflow table.
// 

use std::collections::HashMap;

use brane_ast::DataType;

pub use crate::errors::VarRegError as Error;
use crate::value::Value;


/***** LIBRARY *****/
/// The VariableRegister maps variable indices in the workflow table to out-of-stack values.
#[derive(Clone, Debug)]
pub struct VariableRegister {
    /// Contains the variables, groups by identifier.
    register : HashMap<usize, (String, DataType, Option<Value>)>,
}

impl VariableRegister {
    /// Constructor for the VariableRegister which initializes it with nothing (except for builtin variables :eyes:)
    /// 
    /// # Returns
    /// A new VariableRegister instance.
    #[inline]
    pub fn new() -> Self {
        Self {
            register : HashMap::with_capacity(16),
        }
    }



    /// Declares a new variable in the variable register.
    /// 
    /// # Generic arguments
    /// - `S`: The String-like type of the variable's `name`.
    /// 
    /// # Arguments
    /// - `id`: The identifier of the variable.
    /// - `name`: The name of the variable to declare. Used for debugging only.
    /// - `data_type`: The type of the variable.
    /// 
    /// # Returns
    /// Nothing, but does add it internally.
    /// 
    /// # Errors
    /// This function errors if the given variable was already declared.
    pub fn declare<S: Into<String>>(&mut self, id: usize, name: S, data_type: DataType) -> Result<(), Error> {
        let name: String = name.into();
        match self.register.insert(id, (name.clone(), data_type.clone(), None)) {
            Some(old) => Err(Error::DuplicateDeclaration { id, old_name: old.0, old_type: old.1, new_name: name, new_type: data_type }),
            None      => Ok(()),
        }
    }

    /// Stores a new value in the given variable.
    /// 
    /// # Arguments
    /// - `id`: The identifier of the variable.
    /// - `value`: The new value to store within.
    /// 
    /// # Errors
    /// This function errors if the given variable was not declared.
    #[inline]
    pub fn store(&mut self, id: usize, value: Value) -> Result<(), Error> {
        match self.register.get_mut(&id) {
            Some((_, _, ref mut var_val)) => { *var_val = Some(value); Ok(()) },
            None                          => Err(Error::UndeclaredVariable{ id }),
        }
    }

    /// Stores the value of the given variable.
    /// 
    /// # Arguments
    /// - `id`: The identifier of the variable.
    /// 
    /// # Returns
    /// The value currently stored in the given variable.
    /// 
    /// # Errors
    /// This function errors if the given variable was not declared.
    #[inline]
    pub fn load(&self, id: usize) -> Result<&Value, Error> {
        match self.register.get(&id) {
            Some((_, _, var_val)) => match var_val {
                Some(val) => Ok(val),
                None      => Err(Error::UninitializedVariable { id }),
            },
            None => Err(Error::UndeclaredVariable{ id }),
        }
    }

    /// Deletes the given variable.
    /// 
    /// # Arguments
    /// - `id`: The identifier of the variable.
    /// 
    /// # Errors
    /// This function errors if the given variable was not declared.
    #[inline]
    pub fn delete(&mut self, id: usize) -> Result<(), Error> {
        match self.register.remove(&id) {
            Some(_) => Ok(()),
            None    => Err(Error::UndeclaredVariable{ id }),
        }
    }



    /// Returns the name of the given variable.
    /// 
    /// # Arguments
    /// - `id`: The variable of which to return the name.
    /// 
    /// # Returns
    /// The name of the variable.
    /// 
    /// # Errors
    /// This function errors if the given variable was not declared.
    #[inline]
    pub fn name(&self, id: usize) -> Result<&str, Error> {
        match self.register.get(&id) {
            Some((name, _, _)) => Ok(name),
            None               => Err(Error::UndeclaredVariable{ id }),
        }
    }

    /// Returns the data type of the given variable.
    /// 
    /// # Arguments
    /// - `id`: The variable of which to return the name.
    /// 
    /// # Returns
    /// The type of the variable.
    /// 
    /// # Errors
    /// This function errors if the given variable was not declared.
    #[inline]
    pub fn data_type(&self, id: usize) -> Result<&DataType, Error> {
        match self.register.get(&id) {
            Some((_, data_type, _)) => Ok(data_type),
            None                    => Err(Error::UndeclaredVariable{ id }),
        }
    }
}

impl Default for VariableRegister {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
