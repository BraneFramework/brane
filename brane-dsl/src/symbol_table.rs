//  SYMBOL TABLE.rs
//    by Lut99
//
//  Created:
//    23 Aug 2022, 18:04:09
//  Last edited:
//    01 Nov 2023, 16:09:22
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a simple SymbolTable struct that we use to keep track of
//!   definitions and their assigned types.
//

use std::cell::{Ref, RefCell};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::mem;
use std::rc::Rc;

use specifications::package::Capability;
use specifications::version::Version;

use crate::data_type::{ClassSignature, DataType, FunctionSignature};
pub use crate::errors::SymbolTableError as Error;
use crate::spec::TextRange;


/// Defines a symbol table entry within the SymbolTable.
#[derive(Clone, Debug)]
pub enum SymbolTableEntry {
    /// Defines a function entry within the SymbolTable.
    FunctionEntry(Rc<RefCell<FunctionEntry>>),
    /// Defines a class entry (i.e., custom type) within the SymbolTable.
    ClassEntry(Rc<RefCell<ClassEntry>>),
    /// Defines a regular variable entry within the SymbolTable.
    VarEntry(Rc<RefCell<VarEntry>>),
}

impl SymbolTableEntry {
    // /// Returns the kind of the entry.
    // #[inline]
    // pub fn kind(&self) -> SymbolTableEntryKind {
    //     use SymbolTableEntry::*;
    //     match self {
    //         FunctionEntry(_) => SymbolTableEntryKind::Function,
    //         ClassEntry(_)    => SymbolTableEntryKind::Class,
    //         VarEntry(_)      => SymbolTableEntryKind::Var,
    //     }
    // }

    // /// Returns the name of the entry.
    // #[inline]
    // pub fn name(&self) -> String {
    //     use SymbolTableEntry::*;
    //     match self {
    //         FunctionEntry(f) => f.borrow().name(),
    //         ClassEntry(c)    => c.borrow().name(),
    //         VarEntry(v)      => v.borrow().name(),
    //     }
    // }

    // /// Returns the range of the entry.
    // #[inline]
    // pub fn range(&self) -> TextRange {
    //     use SymbolTableEntry::*;
    //     match self {
    //         FunctionEntry(f) => f.borrow().range(),
    //         ClassEntry(c)    => c.borrow().range(),
    //         VarEntry(v)      => v.borrow().range(),
    //     }
    // }
}

impl From<Rc<RefCell<FunctionEntry>>> for SymbolTableEntry {
    #[inline]
    fn from(value: Rc<RefCell<FunctionEntry>>) -> Self { SymbolTableEntry::FunctionEntry(value) }
}

impl From<Rc<RefCell<ClassEntry>>> for SymbolTableEntry {
    #[inline]
    fn from(value: Rc<RefCell<ClassEntry>>) -> Self { SymbolTableEntry::ClassEntry(value) }
}

impl From<Rc<RefCell<VarEntry>>> for SymbolTableEntry {
    #[inline]
    fn from(value: Rc<RefCell<VarEntry>>) -> Self { SymbolTableEntry::VarEntry(value) }
}



/// Defines a function entry within the SymbolTable.
#[derive(Clone, Debug)]
pub struct FunctionEntry {
    /// The name of the function entry.
    pub name:      String,
    /// The signature of the function entry.
    pub signature: FunctionSignature,
    /// References to entries that form the Function's parameters.
    pub params:    Vec<Rc<RefCell<VarEntry>>>,

    /// If set to non-zero, then this function is imported from a package with the given name.
    pub package_name:    Option<String>,
    /// If set to non-zero, then this function is imported from a package with the given version.
    pub package_version: Option<Version>,
    /// If set to non-zero, then this function is a method in the class with the given name.
    pub class_name:      Option<String>,

    /// If this function is external (i.e., `package_name` is not None), then this list represents the name of each of the arguments. It will thus always be as long as the number of arguments in that case (and empty otherwise).
    pub arg_names:    Vec<String>,
    /// Any requirements the function has in terms of hardware support. Only ever not-None if an external function.
    pub requirements: Option<HashSet<Capability>>,

    /// The index in the workflow buffer of this function.
    pub index: usize,

    // /// The parent symbol table. Is always safe to unwrap.
    // pub table : Option<Rc<RefCell<SymbolTable>>>,
    /// Points to the entire function definition (or import).
    pub range: TextRange,
}

impl FunctionEntry {
    /// Creates a FunctionEntry as if it was defined as a builtin function.
    ///
    /// # Generic arguments
    /// - `S`: The String-like type of the function's `name`.
    ///
    /// # Arguments
    /// - `name`: The name of the FunctionEntry.
    /// - `signature`: The signature of the FunctionEntry.
    /// - `range`: The TextRange that points to the definition itself.
    ///
    /// # Returns
    /// A new FunctionEntry that has no package or class set, but does have type information populated.
    #[inline]
    pub fn from_builtin<S: Into<String>>(name: S, signature: FunctionSignature, range: TextRange) -> Self {
        Self {
            name: name.into(),
            signature,
            params: vec![],

            package_name: None,
            package_version: None,
            class_name: None,

            arg_names: vec![],
            requirements: None,

            index: usize::MAX,

            range,
        }
    }

    /// Creates a FunctionEntry as if it was defined in the source text.
    ///
    /// # Generic arguments
    /// - `S`: The String-like type of the function's `name`.
    ///
    /// # Arguments
    /// - `name`: The name of the FunctionEntry.
    /// - `range`: The TextRange that points to the definition itself.
    ///
    /// # Returns
    /// A new FunctionEntry that has no package or class set, and not yet any type information populated.
    #[inline]
    pub fn from_def<S: Into<String>>(name: S, range: TextRange) -> Self {
        Self {
            name: name.into(),
            signature: FunctionSignature::default(),
            params: vec![],

            package_name: None,
            package_version: None,
            class_name: None,

            arg_names: vec![],
            requirements: None,

            index: usize::MAX,

            range,
        }
    }

    /// Creates a FunctionEntry as if it was imported by the given package.
    ///
    /// # Generic arguments
    /// - `S1`: The String-like type of the function's `name`.
    /// - `S2`: The String-like type of the `package`.
    ///
    /// # Arguments
    /// - `name`: The name of the FunctionEntry.
    /// - `signature`: The FunctionSignature of this function.
    /// - `package`: The name of the package to which this function belongs.
    /// - `package_version`: The version of the package to which this function belongs.
    /// - `arg_names`: The names of the arguments (corresponds index-wise to the `signature::arg` list).
    /// - `requirements`: The list of hardware requirements (as Capabilities) as defined in the function's package file.
    /// - `range`: The TextRange that points to the definition itself (i.e., the import statement).
    ///
    /// # Returns
    /// A new FunctionEntry that has the given package set, and not yet any type information populated.
    #[inline]
    pub fn from_import<S1: Into<String>, S2: Into<String>>(
        name: S1,
        signature: FunctionSignature,
        package: S2,
        package_version: Version,
        arg_names: Vec<String>,
        requirements: HashSet<Capability>,
        range: TextRange,
    ) -> Self {
        Self {
            name: name.into(),
            signature,
            params: vec![],

            package_name: Some(package.into()),
            package_version: Some(package_version),
            class_name: None,

            arg_names,
            requirements: Some(requirements),

            index: usize::MAX,

            range,
        }
    }

    /// Creates a FunctionEntry as if it was a class method.
    ///
    /// # Generic arguments
    /// - `S1`: The String-like type of the function's `name`.
    /// - `S2`: The String-like type of the `class`.
    ///
    /// # Arguments
    /// - `name`: The name of the FunctionEntry.
    /// - `class`: The name of the Class to which this function belongs.
    /// - `range`: The TextRange that points to the definition itself (i.e., the import statement).
    ///
    /// # Returns
    /// A new FunctionEntry that has the given class set, and not yet any type information populated.
    #[inline]
    pub fn from_method<S1: Into<String>, S2: Into<String>>(name: S1, class: S2, range: TextRange) -> Self {
        Self {
            name: name.into(),
            signature: FunctionSignature::default(),
            params: vec![],

            package_name: None,
            package_version: None,
            class_name: Some(class.into()),

            arg_names: vec![],
            requirements: None,

            index: usize::MAX,

            range,
        }
    }
}



/// Defines a class entry (i.e., custom type) within the SymbolTable.
#[derive(Clone, Debug)]
pub struct ClassEntry {
    /// The signature of the class (i.e., its name).
    pub signature:    ClassSignature,
    /// References the SymbolTable where the nested declarations are present. This is used to resolve projection on the class.
    pub symbol_table: Rc<RefCell<SymbolTable>>,

    /// If populated, then this Class was defined in a package with the given name.
    pub package_name:    Option<String>,
    /// If set to non-zero, then this function is imported from a package with the given version.
    pub package_version: Option<Version>,

    /// The index in the workflow buffer of this class.
    pub index: usize,

    // /// The parent symbol table. Is always safe to unwrap.
    // pub table : Option<Rc<RefCell<SymbolTable>>>,
    /// Points to the entire class definition (or import).
    pub range: TextRange,
}

impl ClassEntry {
    /// Creates a ClassEntry as if it was defined as a builtin type.
    ///
    /// # Arguments
    /// - `signature`: The signature of the ClassEntry (contains its name).
    /// - `symbol_table`: The nested SymbolTable that this Class uses to identify its fields.
    /// - `range`: The TextRange that points to the definition itself.
    ///
    /// # Returns
    /// A new ClassEntry that has no package set, but does have type information populated.
    #[inline]
    pub fn from_builtin(signature: ClassSignature, symbol_table: Rc<RefCell<SymbolTable>>, range: TextRange) -> Self {
        Self { signature, symbol_table, package_name: None, package_version: None, index: usize::MAX, range }
    }

    /// Creates a ClassEntry as if it was defined in the source text.
    ///
    /// # Arguments
    /// - `signature`: The signature of the ClassEntry (contains its name).
    /// - `symbol_table`: The nested SymbolTable that this Class uses to identify its fields.
    /// - `range`: The TextRange that points to the definition itself.
    ///
    /// # Returns
    /// A new ClassEntry that has no package set, but does have type information populated.
    #[inline]
    pub fn from_def(signature: ClassSignature, symbol_table: Rc<RefCell<SymbolTable>>, range: TextRange) -> Self {
        Self { signature, symbol_table, package_name: None, package_version: None, index: usize::MAX, range }
    }

    /// Creates a ClassEntry as if it was imported by the given package.
    ///
    /// # Generic arguments
    /// - `S`: The String-like type of the `package`.
    ///
    /// # Arguments
    /// - `name`: The name of the ClassEntry.
    /// - `symbol_table`: The nested SymbolTable that this Class uses to identify its fields.
    /// - `package`: The name of the package to which this class belongs.
    /// - `package_version`: The version of the package to which this function belongs.
    /// - `range`: The TextRange that points to the definition itself (i.e., the import statement).
    ///
    /// # Returns
    /// A new ClassEntry that has the given package set and is defined as not having methods.
    #[inline]
    pub fn from_import<S: Into<String>>(
        signature: ClassSignature,
        symbol_table: Rc<RefCell<SymbolTable>>,
        package: S,
        package_version: Version,
        range: TextRange,
    ) -> Self {
        Self { signature, symbol_table, package_name: Some(package.into()), package_version: Some(package_version), index: usize::MAX, range }
    }
}



/// Defines a regular variable entry within the SymbolTable.
#[derive(Clone, Debug)]
pub struct VarEntry {
    /// The name/identifier of the variable.
    pub name:      String,
    /// The data type of the variable (i.e., its signature).
    ///
    /// A DataType of `DataType::Any` indicates that the data type may still need to be resolved in the typing phase. After that, though, it means there is not enough information to actually determine the variable's type at compile time.
    pub data_type: DataType,

    /// If this variable is actually a parameter of a function, the this field contains the function's name.
    pub function_name: Option<String>,
    /// If this variable is actually a property of a class, the this field contains the class's name.
    pub class_name:    Option<String>,

    /// The index in the workflow buffer of this variable.
    pub index: usize,

    /// The range that points to the entire definition of the variable entry.
    pub range: TextRange,
}

impl VarEntry {
    /// Creates a VarEntry as if it was defined in the source text.
    ///
    /// # Generic arguments
    /// - `S`: The String-like type of the variable's `name`.
    ///
    /// # Arguments
    /// - `name`: The name of the VarEntry.
    /// - `range`: The TextRange that points to the definition itself.
    ///
    /// # Returns
    /// A new VarEntry that has no function or class set, and not yet any type information populated.
    #[inline]
    pub fn from_def<S: Into<String>>(name: S, range: TextRange) -> Self {
        Self { name: name.into(), data_type: DataType::Any, function_name: None, class_name: None, index: usize::MAX, range }
    }

    /// Creates a VarEntry as if it was a parameter of a function.
    ///
    /// # Generic arguments
    /// - `S1`: The String-like type of the variable's `name`.
    /// - `S2`: The String-like type of the `function`.
    ///
    /// # Arguments
    /// - `name`: The name of the VarEntry.
    /// - `function`: The name of the function to which this variable belongs.
    /// - `range`: The TextRange that points to the definition itself (i.e., the import statement).
    ///
    /// # Returns
    /// A new VarEntry that has the given function set but not yet any type information populated.
    #[inline]
    pub fn from_param<S1: Into<String>, S2: Into<String>>(name: S1, function: S2, range: TextRange) -> Self {
        Self { name: name.into(), data_type: DataType::Any, function_name: Some(function.into()), class_name: None, index: usize::MAX, range }
    }

    /// Creates a VarEntry as if it was a property of a class.
    ///
    /// # Generic arguments
    /// - `S1`: The String-like type of the variable's `name`.
    /// - `D`: The DataType-like type of the `data_type`.
    /// - `S2`: The String-like type of the `class`.
    ///
    /// # Arguments
    /// - `name`: The name of the VarEntry.
    /// - `data_type`: The DataType of this property.
    /// - `class`: The name of the class to which this variable belongs.
    /// - `range`: The TextRange that points to the definition itself (i.e., the import statement).
    ///
    /// # Returns
    /// A new VarEntry that has the given class set but not yet any type information populated.
    #[inline]
    pub fn from_prop<S1: Into<String>, D: Into<DataType>, S2: Into<String>>(name: S1, data_type: D, class: S2, range: TextRange) -> Self {
        Self { name: name.into(), data_type: data_type.into(), function_name: None, class_name: Some(class.into()), index: usize::MAX, range }
    }
}



/// Defines a SymbolTable that contains all definitions of a single scope.
#[derive(Clone, Debug)]
pub struct SymbolTable {
    /// Contains the parent symbol table, if any.
    pub parent: Option<Rc<RefCell<SymbolTable>>>,

    /// Contains all entries that live within the function namespace.
    functions: HashMap<String, Rc<RefCell<FunctionEntry>>>,
    /// Contains all entries that live within the class namespace.
    classes:   HashMap<String, Rc<RefCell<ClassEntry>>>,
    /// Contains all entries that live within the variable namespace.
    variables: HashMap<String, Rc<RefCell<VarEntry>>>,
}

impl SymbolTable {
    /// Constructor for the SymbolTable.
    ///
    /// # Returns
    /// A new SymbolTable that does not have any definitions within it yet. It is already wrapped in an Rc and RefCell for convenience.
    #[inline]
    pub fn new() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self {
            parent: None,

            functions: HashMap::with_capacity(4),
            classes:   HashMap::with_capacity(4),
            variables: HashMap::with_capacity(4),
        }))
    }

    /// Adds the given FunctionEntry to the function namespace in the SymbolTable.
    ///
    /// # Arguments
    /// - `entry`: The new FunctionEntry to add.
    ///
    /// # Returns
    /// The newly created entry (or rather, a reference-counted pointer to it).
    ///
    /// # Errors
    /// This function may error if an entry with this name in this namespace already exists.
    pub fn add_func(&mut self, entry: FunctionEntry) -> Result<Rc<RefCell<FunctionEntry>>, Error> {
        // Extract some properties of the entry we (might) need later
        let name: String = entry.name.clone();
        let range: TextRange = entry.range.clone();

        // Add it to the table (we overwrite any old ones to better support future errors).
        let entry: Rc<RefCell<FunctionEntry>> = Rc::new(RefCell::new(entry));
        let old: Option<Rc<RefCell<FunctionEntry>>> = self.functions.insert(name, entry.clone());

        // Error if there already was one
        if let Some(old) = old {
            let entry: Ref<FunctionEntry> = old.borrow();
            return Err(Error::DuplicateFunction { name: entry.name.clone(), existing: entry.range.clone(), got: range });
        }

        // Otherwise, return the new entry
        Ok(entry)
    }

    /// Adds the given ClassEntry to the class namespace in the SymbolTable.
    ///
    /// # Arguments
    /// - `entry`: The new ClassEntry to add.
    ///
    /// # Returns
    /// The newly created entry (or rather, a reference-counted pointer to it).
    ///
    /// # Errors
    /// This function may error if an entry with this name in this namespace already exists.
    pub fn add_class(&mut self, entry: ClassEntry) -> Result<Rc<RefCell<ClassEntry>>, Error> {
        // Extract some properties of the entry we (might) need later
        let name: String = entry.signature.name.clone();
        let range: TextRange = entry.range.clone();

        // Add it to the table (we overwrite any old ones to better support future errors).
        let entry: Rc<RefCell<ClassEntry>> = Rc::new(RefCell::new(entry));
        let old: Option<Rc<RefCell<ClassEntry>>> = self.classes.insert(name, entry.clone());

        // Error if there already was one
        if let Some(old) = old {
            let entry: Ref<ClassEntry> = old.borrow();
            return Err(Error::DuplicateVariable { name: entry.signature.name.clone(), existing: entry.range.clone(), got: range });
        }

        // Otherwise, return the new entry
        Ok(entry)
    }

    /// Adds the given VarEntry to the variable namespace in the SymbolTable.
    ///
    /// # Arguments
    /// - `entry`: The new VarEntry to add.
    ///
    /// # Returns
    /// The newly created entry (or rather, a reference-counted pointer to it).
    ///
    /// # Errors
    /// This function may error if an entry with this name in this namespace already exists.
    pub fn add_var(&mut self, entry: VarEntry) -> Result<Rc<RefCell<VarEntry>>, Error> {
        // Extract some properties of the entry we (might) need later
        let name: String = entry.name.clone();
        let range: TextRange = entry.range.clone();

        // Add it to the table (we overwrite any old ones to better support future errors).
        let entry: Rc<RefCell<VarEntry>> = Rc::new(RefCell::new(entry));
        let old: Option<Rc<RefCell<VarEntry>>> = self.variables.insert(name, entry.clone());

        // Error if there already was one
        if let Some(old) = old {
            let entry: Ref<VarEntry> = old.borrow();
            return Err(Error::DuplicateVariable { name: entry.name.clone(), existing: entry.range.clone(), got: range });
        }

        // Otherwise, return the new entry
        Ok(entry)
    }

    /// Returns the entry in _all_ namespaces with the given name if it exists.
    ///
    /// This implies that the name is unique across namespaces, so it relies on an external source to make that happen.
    ///
    /// If that somehow fails, returns the first occurrence in the order of functions -> classes -> variables.
    ///
    /// # Generic arguments
    /// - `S`: The &str-like type of the target `name`.
    ///
    /// # Arguments
    /// - `name`: The name of the entry to retrieve.
    ///
    /// # Returns
    /// A reference-counter pointer to the entry if it exists, or else None.
    #[inline]
    pub fn get<S: AsRef<str>>(&self, name: S) -> Option<SymbolTableEntry> {
        // Try the functions first
        match self.get_func(name.as_ref()) {
            Some(entry) => Some(entry.into()),
            None => match self.get_class(name.as_ref()) {
                Some(entry) => Some(entry.into()),
                None => self.get_var(name).map(|entry| entry.into()),
            },
        }
    }

    /// Returns the entry in the function namespace with the given name if it exists.
    ///
    /// # Generic arguments
    /// - `S`: The &str-like type of the target `name`.
    ///
    /// # Arguments
    /// - `name`: The name of the entry to retrieve.
    ///
    /// # Returns
    /// A reference-counter pointer to the entry if it exists, or else None.
    pub fn get_func<S: AsRef<str>>(&self, name: S) -> Option<Rc<RefCell<FunctionEntry>>> {
        // Try ourselves or else the parent
        match self.functions.get(name.as_ref()) {
            Some(entry) => Some(entry.clone()),
            None => match &self.parent {
                Some(parent) => {
                    // Try our parent instead
                    let st: Ref<SymbolTable> = parent.borrow();
                    st.get_func(name)
                },
                None => None,
            },
        }
    }

    /// Returns the entry in the class namespace with the given name if it exists.
    ///
    /// # Generic arguments
    /// - `S`: The &str-like type of the target `name`.
    ///
    /// # Arguments
    /// - `name`: The name of the entry to retrieve.
    ///
    /// # Returns
    /// A reference-counter pointer to the entry if it exists, or else None.
    pub fn get_class<S: AsRef<str>>(&self, name: S) -> Option<Rc<RefCell<ClassEntry>>> {
        // Try ourselves or else the parent
        match self.classes.get(name.as_ref()) {
            Some(entry) => Some(entry.clone()),
            None => match &self.parent {
                Some(parent) => {
                    // Try our parent instead
                    let st: Ref<SymbolTable> = parent.borrow();
                    st.get_class(name)
                },
                None => None,
            },
        }
    }

    /// Returns the entry in the variable namespace with the given name if it exists.
    ///
    /// # Generic arguments
    /// - `S`: The &str-like type of the target `name`.
    ///
    /// # Arguments
    /// - `name`: The name of the entry to retrieve.
    ///
    /// # Returns
    /// A reference-counter pointer to the entry if it exists, or else None.
    pub fn get_var<S: AsRef<str>>(&self, name: S) -> Option<Rc<RefCell<VarEntry>>> {
        // Try ourselves or else the parent
        match self.variables.get(name.as_ref()) {
            Some(entry) => Some(entry.clone()),
            None => match &self.parent {
                Some(parent) => {
                    // Try our parent instead
                    let st: Ref<SymbolTable> = parent.borrow();
                    st.get_var(name)
                },
                None => None,
            },
        }
    }

    /// Returns whether this SymbolTable has any functions defined at all.
    #[inline]
    pub fn has_functions(&self) -> bool { !self.functions.is_empty() }

    /// Returns the number of functions defined in the SymbolTable.
    #[inline]
    pub fn n_functions(&self) -> usize { self.functions.len() }

    /// Returns an iterator over the defined functions (as `(name, entry)` pairs).
    ///
    /// # Returns
    /// The iterator returned by the internal HashMap.
    #[inline]
    pub fn functions(&self) -> std::collections::hash_map::Iter<'_, std::string::String, Rc<RefCell<FunctionEntry>>> { self.functions.iter() }

    /// Returns a muteable iterator over the defined functions (as `(name, entry)` pairs).
    ///
    /// # Returns
    /// The iterator returned by the internal HashMap.
    #[inline]
    pub fn functions_mut(&mut self) -> std::collections::hash_map::IterMut<'_, std::string::String, Rc<RefCell<FunctionEntry>>> {
        self.functions.iter_mut()
    }

    /// Returns a consuming iterator over the defined functions (as `(name, entry)` pairs).
    ///
    /// # Returns
    /// The iterator returned by the internal HashMap.
    pub fn into_functions(&mut self) -> std::collections::hash_map::IntoIter<std::string::String, Rc<RefCell<FunctionEntry>>> {
        // Get the map
        let mut map: HashMap<String, Rc<RefCell<FunctionEntry>>> = HashMap::new();
        mem::swap(&mut self.functions, &mut map);

        // Return the consuming iterator
        map.into_iter()
    }

    /// Returns whether this SymbolTable has any classes defined at all.
    #[inline]
    pub fn has_classes(&self) -> bool { !self.classes.is_empty() }

    /// Returns the number of classes defined in the SymbolTable.
    #[inline]
    pub fn n_classes(&self) -> usize { self.classes.len() }

    /// Returns an iterator over the defined classes (as `(name, entry)` pairs).
    ///
    /// # Returns
    /// The iterator returned by the internal HashMap.
    #[inline]
    pub fn classes(&self) -> std::collections::hash_map::Iter<'_, std::string::String, Rc<RefCell<ClassEntry>>> { self.classes.iter() }

    /// Returns a muteable iterator over the defined classes (as `(name, entry)` pairs).
    ///
    /// # Returns
    /// The iterator returned by the internal HashMap.
    #[inline]
    pub fn classes_mut(&mut self) -> std::collections::hash_map::IterMut<'_, std::string::String, Rc<RefCell<ClassEntry>>> { self.classes.iter_mut() }

    /// Returns a consuming iterator over the defined classes (as `(name, entry)` pairs).
    ///
    /// # Returns
    /// The iterator returned by the internal HashMap.
    pub fn into_classes(&mut self) -> std::collections::hash_map::IntoIter<std::string::String, Rc<RefCell<ClassEntry>>> {
        // Get the map
        let mut map: HashMap<String, Rc<RefCell<ClassEntry>>> = HashMap::new();
        mem::swap(&mut self.classes, &mut map);

        // Return the consuming iterator
        map.into_iter()
    }

    /// Returns whether this SymbolTable has any variables defined at all.
    #[inline]
    pub fn has_variables(&self) -> bool { !self.variables.is_empty() }

    /// Returns the number of variables defined in the SymbolTable.
    #[inline]
    pub fn n_variables(&self) -> usize { self.variables.len() }

    /// Returns an iterator over the defined variables (as `(name, entry)` pairs).
    ///
    /// # Returns
    /// The iterator returned by the internal HashMap.
    #[inline]
    pub fn variables(&self) -> std::collections::hash_map::Iter<'_, std::string::String, Rc<RefCell<VarEntry>>> { self.variables.iter() }

    /// Returns a muteable iterator over the defined variables (as `(name, entry)` pairs).
    ///
    /// # Returns
    /// The iterator returned by the internal HashMap.
    #[inline]
    pub fn variables_mut(&mut self) -> std::collections::hash_map::IterMut<'_, std::string::String, Rc<RefCell<VarEntry>>> {
        self.variables.iter_mut()
    }

    /// Returns a consuming iterator over the defined variables (as `(name, entry)` pairs).
    ///
    /// # Returns
    /// The iterator returned by the internal HashMap.
    pub fn into_variables(&mut self) -> std::collections::hash_map::IntoIter<std::string::String, Rc<RefCell<VarEntry>>> {
        // Get the map
        let mut map: HashMap<String, Rc<RefCell<VarEntry>>> = HashMap::new();
        mem::swap(&mut self.variables, &mut map);

        // Return the consuming iterator
        map.into_iter()
    }
}
