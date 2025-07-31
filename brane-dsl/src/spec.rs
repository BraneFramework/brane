//  SPEC.rs
//    by Lut99
//
//  Created:
//    10 Aug 2022, 14:03:04
//  Last edited:
//    14 Nov 2024, 16:07:35
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains (some of the) common structs and interfaces for the
//!   `brane-dsl` crate.
//

use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::str::FromStr;

use nom::AsBytes;
use nom_locate::LocatedSpan;
use serde::{Deserialize, Serialize};

use crate::errors::LanguageParseError;


/***** LIBRARY *****/
/// Defines a position in the input text.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TextPos {
    /// The y-coordinate of the position (one-indexed)
    #[serde(rename = "l")]
    pub line: usize,
    /// The x-coordinate of the position (one-indexed)
    #[serde(rename = "c")]
    pub col:  usize,
}

impl TextPos {
    /// Constructor for the TextPos.
    ///
    /// # Arguments
    /// - `line`: The line number.
    /// - `col`: The column number.
    ///
    /// # Returns
    /// A new TextPos instance with the given line and column number.
    #[inline]
    pub const fn new(line: usize, col: usize) -> Self { Self { line, col } }

    /// Constructor for the TextPos that initializes it to 'none'.
    ///
    /// # Returns
    /// A new TextPos instance that represents 'no position'.
    #[inline]
    pub const fn none() -> Self { Self { line: usize::MAX, col: usize::MAX } }

    /// Constructor for the TextPos that initializes it to the end of the given Span.
    ///
    /// Concretely, it adds the length of the span to the Span's start location, modulo any newlines ('\n') it finds.
    ///
    /// # Generic types
    /// - `T`: The type stored in the LocatedSpan.
    /// - `X`: Any extra information stored in the span.
    ///
    /// # Arguments
    /// - `span`: The LocatedSpan that contains both the text and position that we will use to compute the end position.
    ///
    /// # Returns
    /// A new TextPos instance that points to the end of the span (inclusive).
    pub fn end_of<T: AsBytes, X>(span: &LocatedSpan<T, X>) -> Self {
        // Get the bytes of the Span's type.
        let bs: &[u8] = span.fragment().as_bytes();

        // Get the position of the last newline and count them while at it
        let mut n_nls: usize = 0;
        let mut last_nl: usize = usize::MAX;
        for (i, b) in bs.iter().enumerate() {
            if *b == b'\n' {
                n_nls += 1;
                last_nl = i;
            }
        }

        // Use those to compute offsets for the lines and columns
        Self {
            line: span.location_line() as usize + n_nls,
            col:  if last_nl < usize::MAX { bs.len() - (last_nl + 1) } else { span.get_column() + bs.len() },
        }
    }

    /// Returns if this TextPos is a position (i.e., does not represent 'no position').
    ///
    /// # Returns
    /// Whether or not this TextPos represents a useable position (true) or if it is 'no position' (false).
    #[inline]
    pub const fn is_some(&self) -> bool { self.line != usize::MAX || self.col != usize::MAX }

    /// Returns if this TextPos is _not_ a position (i.e., represents 'no position').
    ///
    /// # Returns
    /// Whether or not this TextPos represents a useable position (false) or if it is 'no position' (true).
    #[inline]
    pub const fn is_none(&self) -> bool { !self.is_some() }
}

impl Default for TextPos {
    #[inline]
    fn default() -> Self { Self::none() }
}

impl Display for TextPos {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}:{}", self.line, self.col) }
}

impl<T: AsBytes, X> From<LocatedSpan<T, X>> for TextPos {
    #[inline]
    fn from(value: LocatedSpan<T, X>) -> Self {
        // Delegate to the by-reference one
        Self::from(&value)
    }
}

impl<T: AsBytes, X> From<&LocatedSpan<T, X>> for TextPos {
    #[inline]
    fn from(value: &LocatedSpan<T, X>) -> Self { Self { line: value.location_line() as usize, col: value.get_column() } }
}



/// Defines a range (i.e., a span of positions).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TextRange {
    /// The start position (inclusive) in the range.
    #[serde(rename = "s")]
    pub start: TextPos,
    /// The end position (inclusive) in the range.
    #[serde(rename = "e")]
    pub end:   TextPos,
}

impl TextRange {
    /// Constructor for the TextRange.
    ///
    /// # Arguments
    /// - `start`: The start position (inclusive) in the range.
    /// - `end`: The end position (inclusive) in the range.
    ///
    /// # Returns
    /// A new TextRange instance.
    #[inline]
    pub const fn new(start: TextPos, end: TextPos) -> Self { Self { start, end } }

    /// Constructor for the TextRange that initializes it to 'none'.
    ///
    /// # Returns
    /// A new TextRange instance that represents 'no range'.
    #[inline]
    pub const fn none() -> Self { Self { start: TextPos::none(), end: TextPos::none() } }

    /// Returns if this TextRange is a range (i.e., does not represent 'no range').
    ///
    /// # Returns
    /// Whether or not this TextRange represents a useable range (true) or if it is 'no range' (false).
    #[inline]
    pub const fn is_some(&self) -> bool { self.start.is_some() && self.end.is_some() }

    /// Returns if this TextRange is _not_ a range (i.e., represents 'no range').
    ///
    /// # Returns
    /// Whether or not this TextRange represents a useable range (false) or if it is 'no range' (true).
    #[inline]
    pub const fn is_none(&self) -> bool { !self.is_some() }
}

impl Default for TextRange {
    #[inline]
    fn default() -> Self { Self::none() }
}

impl<T: AsBytes, X> From<LocatedSpan<T, X>> for TextRange {
    #[inline]
    fn from(value: LocatedSpan<T, X>) -> Self {
        // Delegate to the by-reference one
        Self::from(&value)
    }
}

impl<T: AsBytes, X> From<&LocatedSpan<T, X>> for TextRange {
    #[inline]
    fn from(value: &LocatedSpan<T, X>) -> Self { Self { start: TextPos::from(value), end: TextPos::end_of(value) } }
}

impl<T1: AsBytes, T2: AsBytes, X1, X2> From<(LocatedSpan<T1, X1>, LocatedSpan<T2, X2>)> for TextRange {
    #[inline]
    fn from(value: (LocatedSpan<T1, X1>, LocatedSpan<T2, X2>)) -> Self { Self::from((&value.0, &value.1)) }
}

impl<T1: AsBytes, T2: AsBytes, X1, X2> From<(&LocatedSpan<T1, X1>, &LocatedSpan<T2, X2>)> for TextRange {
    #[inline]
    fn from(value: (&LocatedSpan<T1, X1>, &LocatedSpan<T2, X2>)) -> Self { Self { start: TextPos::from(value.0), end: TextPos::end_of(value.1) } }
}



/// Defines the languages from which we can compile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Language {
    /// Define BraneScript (more script-like)
    BraneScript,
    /// Define Bakery (more natural-language-like)
    Bakery,
}

impl Display for Language {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Language::*;
        match self {
            BraneScript => write!(f, "BraneScript"),
            Bakery => write!(f, "Bakery"),
        }
    }
}

impl FromStr for Language {
    type Err = LanguageParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "bscript" => Ok(Self::BraneScript),
            "bakery" => Ok(Self::Bakery),
            raw => Err(LanguageParseError::UnknownLanguageId { raw: raw.into() }),
        }
    }
}



// /// Defines the supported data types in BraneScript/Bakery.
// #[derive(Clone, Debug, Eq, PartialEq, Hash)]
// pub enum DataType {
//     /// Special data type that can be thought of as 'type check deferred to runtime'.
//     Any,

//     /// Binary values ('true' or 'false')
//     Boolean,
//     /// Non-decimal numerical values (signed or unsigned)
//     Integer,
//     /// Decimal numerical values
//     Real,
//     /// Text values
//     String,
//     /// Version numbers (as `major.minor.patch`).
//     Semver,

//     ///.It's an Array type.
//     Array(Box<Self>),
//     /// It's a custom Class type.
//     Class(String),

//     /// No type / no value
//     Void,
// }

// impl DataType {
//     /// Returns whether this data type may be casted to the other type.
//     ///
//     /// In other words, expresses some 'returns the same' proprety of a type.
//     ///
//     /// # Generic arguments
//     /// - `D`: The DataType-like type of the `other` datatype.
//     ///
//     /// # Arguments
//     /// - `other`: The other data type to check compatibility with.
//     ///
//     /// # Returns
//     /// Whether or not this type casts to the other type (true) or not (false).
//     pub fn casts_to<D: AsRef<DataType>>(&self, other: D) -> bool {
//         // Match as pairs
//         use DataType::*;
//         match (self, other.as_ref()) {
//             // Specific casts
//             (Integer, Boolean) => true,
//             (Boolean, Integer) => true,
//             (Boolean, Real)    => true,
//             (Integer, Real)    => true,

//             // Array casts
//             (t, Array(b)) => t == &**b,

//             // Always-valid casts
//             (Any, _)    => true,
//             (_, Any)    => true,
//             (_, String) => true,

//             (t1, t2) => {
//                 // Type can always cast to themselves
//                 std::mem::discriminant(t1) == std::mem::discriminant(t2)
//             }
//         }
//     }
// }

// impl AsRef<DataType> for DataType {
//     #[inline]
//     fn as_ref(&self) -> &DataType {
//         self
//     }
// }

// impl From<&str> for DataType {
//     #[inline]
//     fn from(value: &str) -> Self {
//         // Match the str value
//         match value.trim() {
//             "bool" | "boolean" => DataType::Boolean,
//             "int"  | "integer" => DataType::Integer,
//             "real" | "float "  => DataType::Real,
//             "string"           => DataType::String,

//             "[bool]" | "[boolean]" => DataType::Array(Box::new(DataType::Boolean)),
//             "[int]"  | "[integer]" => DataType::Array(Box::new(DataType::Integer)),
//             "[real]" | "[float] "  => DataType::Array(Box::new(DataType::Real)),
//             "[string]"             => DataType::Array(Box::new(DataType::String)),

//             raw => DataType::Class(raw.into()),
//         }
//     }
// }

// impl From<&String> for DataType {
//     #[inline]
//     fn from(value: &String) -> Self {
//         Self::from(value.as_str())
//     }
// }

// impl From<String> for DataType {
//     #[inline]
//     fn from(value: String) -> Self {
//         Self::from(value.as_str())
//     }
// }

// impl Display for DataType {
//     #[inline]
//     fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
//         use DataType::*;
//         match self {
//             Any     => write!(f, "Any"),

//             Boolean => write!(f, "Boolean"),
//             Integer => write!(f, "Integer"),
//             Real    => write!(f, "Real"),
//             String  => write!(f, "String"),
//             Semver  => write!(f, "Semver"),

//             Array(t)    => write!(f, "Array<{}>", t),
//             Class(name) => write!(f, "{}", name),

//             Void => write!(f, "Void"),
//         }
//     }
// }



// /// Defines a symbol table entry for functions.
// ///
// /// Note that the identifier is not stored here, but as a key mapping to this entry.
// #[derive(Clone, Debug)]
// pub struct STFuncEntry {
//     /// The name of the package from which this function originates, if any.
//     pub package : Option<String>,

//     /// Gives both the arguments and their data types as the return type (i.e., the function's signature). `DataType::Void` should not occur in the arguments, but may in the return value.
//     pub signature : Option<(Vec<DataType>, DataType)>,

//     /// The range of the function in the original source text (for debugging).
//     pub range : TextRange,
//     /// A reference to the parent symbol table.
//     pub symbol_table : Rc<RefCell<SymbolTable>>,
// }

// /// Defines a symbol table entry for classes.
// ///
// /// Note that the identifier is not stored here, but as a key mapping to this entry.
// #[derive(Clone, Debug)]
// pub struct STClassEntry {
//     /// The properties in this class entry, mapped as name to its data type.
//     pub props : HashMap<String, DataType>,
//     /// The methods in this class entry, mapped as name to a tuple of its parameters and its return type.
//     pub methods : HashMap<String, Option<(Vec<DataType>, DataType)>>,

//     /// The range of the function in the original source text (for debugging).
//     pub range        : TextRange,
//     /// A reference to the parent symbol table.
//     pub symbol_table : Rc<RefCell<SymbolTable>>,
// }

// /// Defines a symbol table entry for variables.
// ///
// /// Note that the identifier is not stored here, but as a key mapping to this entry.
// #[derive(Clone, Debug)]
// pub struct STVarEntry {
//     /// If this is a parameter, references the name of the function this is a parameter for.
//     pub function : Option<String>,

//     /// The data type of this variable as soon as it is known.
//     pub data_type : Option<DataType>,

//     /// The range of the variable entry in the original source text (for debugging).
//     pub range : TextRange,
//     /// A reference to the parent symbol table.
//     pub symbol_table : Rc<RefCell<SymbolTable>>,
// }

// /// Defines a SymbolTable, which is used by the `brane-ast` crate to keep track of declared variables in their own scopes.
// #[derive(Clone, Debug)]
// pub struct SymbolTable {
//     /// The symbol table in the parent scope, if any. Might be unpopulated at first.
//     pub parent : Option<Rc<RefCell<Self>>>,

//     /// The table for function scopes. Maps identifiers to STFuncEntry.
//     pub func : HashMap<String, Rc<RefCell<SymbolTableEntry>>>,
//     /// The table for class (type) scopes. Maps identifiers to STClassEntry.
//     pub clss : HashMap<String, Rc<RefCell<SymbolTableEntry>>>,
//     /// The table for variable scopes. Maps identifiers to STVarEntry.
//     pub vars : HashMap<String, Rc<RefCell<SymbolTableEntry>>>,
// }

// impl SymbolTable {
//     /// Constructor for the SymbolTable that initializes it uninitializes (i.e., it has yet to be populated).
//     ///
//     /// # Returns
//     /// A new, empty SymbolTable instance that is already pre-wrapped in an Rc and RefCell.
//     #[inline]
//     pub fn empty() -> Rc<RefCell<Self>> {
//         Rc::new(RefCell::new(Self {
//             parent : None,

//             func : HashMap::with_capacity(16),
//             clss : HashMap::with_capacity(16),
//             vars : HashMap::with_capacity(16),
//         }))
//     }



//     /// Adds an STFuncEntry to the SymbolTable as a builtin.
//     ///
//     /// The types of the arguments and return type need to be deduced later during type analysis.
//     ///
//     /// # Arguments
//     /// - `this`: A (smart-)pointer to the symboltable to add the new entry to.
//     /// - `name`: The name/identifier of the function.
//     /// - `signature`: The function's signature (i.e., a list of data types (and thus the number) of arguments and its return type).
//     /// - `range`: The range of the function in the original source text (for debugging).
//     ///
//     /// # Returns
//     /// Nothing, but adds it to the internal list.
//     ///
//     /// # Errors
//     /// This function errors if a function entry with this name already exists.
//     pub fn add_builtin_entry(this: &Rc<RefCell<SymbolTable>>, name: String, signature: (Vec<DataType>, DataType), range : TextRange) -> Result<Rc<RefCell<SymbolTableEntry>>, SymbolTableError> {
//         // Borrow ourselves
//         let mut st: RefMut<SymbolTable> = this.borrow_mut();

//         // Check if it already exists
//         if st.func.contains_key(&name) { return Err(SymbolTableError::DuplicateFunction{ name: name.clone(), existing: st.func.get(&name).unwrap().borrow().range.clone(), got: range }); }

//         // It doesn't, so add it
//         let res: Rc<RefCell<STFuncEntry>> = Rc::new(RefCell::new(STFuncEntry {
//             package : None,

//             signature : Some(signature),

//             range,
//             symbol_table : this.clone(),
//         }));
//         st.func.insert(name, res.clone());

//         // Done
//         Ok(res)
//     }

//     /// Adds an STFuncEntry to the SymbolTable.
//     ///
//     /// The types of the arguments and return type need to be deduced later during type analysis.
//     ///
//     /// # Arguments
//     /// - `this`: A (smart-)pointer to the symboltable to add the new entry to.
//     /// - `name`: The name/identifier of the function.
//     /// - `range`: The range of the function in the original source text (for debugging).
//     ///
//     /// # Returns
//     /// Nothing, but adds it to the internal list.
//     ///
//     /// # Errors
//     /// This function errors if a function entry with this name already exists.
//     pub fn add_func_entry(this: &Rc<RefCell<SymbolTable>>, name: String, range : TextRange) -> Result<Rc<RefCell<SymbolTableEntry>>, SymbolTableError> {
//         // Borrow ourselves
//         let mut st: RefMut<SymbolTable> = this.borrow_mut();

//         // Check if it already exists
//         if st.func.contains_key(&name) { return Err(SymbolTableError::DuplicateFunction{ name: name.clone(), existing: st.func.get(&name).unwrap().borrow().range.clone(), got: range }); }

//         // It doesn't, so add it
//         let res: Rc<RefCell<STFuncEntry>> = Rc::new(RefCell::new(STFuncEntry {
//             package : None,

//             signature : None,

//             range,
//             symbol_table : this.clone(),
//         }));
//         st.func.insert(name, res.clone());

//         // Done
//         Ok(res)
//     }

//     /// Adds an STFuncEntry to the SymbolTable but for a package function.
//     ///
//     /// # Arguments
//     /// - `this`: A (smart-)pointer to the symboltable to add the new entry to.
//     /// - `package_name`: The name/identifier of the package to which this function belongs.
//     /// - `name`: The name/identifier of the function.
//     /// - `signature`: The function's signature (i.e., a list of data types (and thus the number) of arguments and its return type).
//     /// - `range`: The range of the function in the original source text (for debugging).
//     ///
//     /// # Returns
//     /// Nothing, but adds it to the internal list.
//     ///
//     /// # Errors
//     /// This function errors if a function entry with this name already exists.
//     pub fn add_package_func_entry(this: &Rc<RefCell<SymbolTable>>, package_name: String, name: String, signature: (Vec<DataType>, DataType), range : TextRange) -> Result<Rc<RefCell<SymbolTableEntry>>, SymbolTableError> {
//         // Borrow ourselves
//         let mut st: RefMut<SymbolTable> = this.borrow_mut();

//         // Check if it already exists
//         if st.func.contains_key(&name) { return Err(SymbolTableError::DuplicateFunction{ name: name.clone(), existing: st.func.get(&name).unwrap().borrow().range.clone(), got: range }); }

//         // It doesn't, so add it
//         let res: Rc<RefCell<STFuncEntry>> = Rc::new(RefCell::new(STFuncEntry {
//             package : Some(package_name),

//             signature : Some(signature),

//             range,
//             symbol_table : this.clone(),
//         }));
//         st.func.insert(name, res.clone());

//         // Done
//         Ok(res)
//     }

//     /// Adds an STCLassEntry to the SymbolTable.
//     ///
//     /// # Arguments
//     /// - `this`: A (smart-)pointer to the symboltable to add the new entry to.
//     /// - `name`: The name/identifier of the function.
//     /// - `properties`: The map of property names to their respective data types for this class.
//     /// - `methods`: The methods defined within this Class, mapped by name.
//     /// - `range`: The range of the class in the original source text (for debugging).
//     ///
//     /// # Returns
//     /// Nothing, but adds it to the internal list.
//     ///
//     /// # Errors
//     /// This function errors if a class entry with this name already exists.
//     pub fn add_class_entry(this: &Rc<RefCell<SymbolTable>>, name: String, properties: HashMap<String, DataType>, methods: HashMap<String, Option<(Vec<DataType>, DataType)>>, range : TextRange) -> Result<Rc<RefCell<SymbolTableEntry>>, SymbolTableError> {
//         // Borrow ourselves
//         let mut st: RefMut<SymbolTable> = this.borrow_mut();

//         // Check if it already exists
//         if st.clss.contains_key(&name) { return Err(SymbolTableError::DuplicateClass{ name: name.clone(), existing: st.clss.get(&name).unwrap().borrow().range.clone(), got: range }); }

//         // It doesn't, so add it
//         let res: Rc<RefCell<STClassEntry>> = Rc::new(RefCell::new(STClassEntry {
//             props : properties,
//             methods,

//             range,
//             symbol_table : this.clone(),
//         }));
//         st.clss.insert(name, res.clone());

//         // Done
//         Ok(res)
//     }

//     /// Adds a function parameter (i.e., variable) to the SymbolTable.
//     ///
//     /// Its type needs to be deduced later during type analysis.
//     ///
//     /// # Arguments
//     /// - `this`: A (smart-)pointer to the symboltable to add the new entry to.
//     /// - `func_name`: The name of the function for which this variable is a parameter.
//     /// - `name`: The name of the variable.
//     /// - `range`: The range of the variable in the original source text (for debugging).
//     ///
//     /// # Returns
//     /// Nothing, but adds it to the internal list.
//     ///
//     /// # Errors
//     /// This function errors if a variable entry with this name already exists.
//     pub fn add_param_entry(this: &Rc<RefCell<SymbolTable>>, func_name: String, name: String, range: TextRange) -> Result<Rc<RefCell<SymbolTableEntry>>, SymbolTableError> {
//         // Borrow ourselves
//         let mut st: RefMut<SymbolTable> = this.borrow_mut();

//         // Check if it already exists
//         if st.vars.contains_key(&name) { return Err(SymbolTableError::DuplicateParameter{ name: name.clone(), existing: st.vars.get(&name).unwrap().borrow().range.clone(), got: range }); }

//         // It doesn't, so add it
//         let res: Rc<RefCell<STVarEntry>> = Rc::new(RefCell::new(STVarEntry {
//             function : Some(func_name),

//             data_type : None,

//             range,
//             symbol_table : this.clone(),
//         }));
//         st.vars.insert(name, res.clone());

//         // Done
//         Ok(res)
//     }

//     /// Adds a fvariable to the SymbolTable.
//     ///
//     /// Its type needs to be deduced later during type analysis.
//     ///
//     /// # Arguments
//     /// - `this`: A (smart-)pointer to the symboltable to add the new entry to.
//     /// - `name`: The name of the variable.
//     /// - `range`: The range of the variable in the original source text (for debugging).
//     ///
//     /// # Returns
//     /// Nothing, but adds it to the internal list.
//     ///
//     /// # Errors
//     /// This function errors if a variable entry with this name already exists.
//     pub fn add_var_entry(this: &Rc<RefCell<SymbolTable>>, name: String, range: TextRange) -> Result<Rc<RefCell<SymbolTableEntry>>, SymbolTableError> {
//         // Borrow ourselves
//         let mut st: RefMut<SymbolTable> = this.borrow_mut();

//         // Check if it already exists
//         if st.vars.contains_key(&name) { return Err(SymbolTableError::DuplicateVariable{ name: name.clone(), existing: st.vars.get(&name).unwrap().borrow().range.clone(), got: range }); }

//         // It doesn't, so add it
//         let res: Rc<RefCell<STVarEntry>> = Rc::new(RefCell::new(STVarEntry {
//             function : None,

//             data_type : None,

//             range,
//             symbol_table : this.clone(),
//         }));
//         st.vars.insert(name, res.clone());

//         // Done
//         Ok(res)
//     }



//     /// Returns a reference to its entry if the given function exists in this symbol table or any of its parents.
//     ///
//     /// This function stops searching as soon as the first entry is found (walking up the tree), which allows shadowing of variables.
//     ///
//     /// # Generic parameters
//     /// - `S`: The &str-like type of the `name`.
//     ///
//     /// # Arguments
//     /// - `name`: The name/identifier of the function to search for.
//     ///
//     /// # Returns
//     /// The STFuncEntry of this function if it existed, or else None.
//     #[inline]
//     pub fn get_func_entry<S: AsRef<str>>(&self, name: S) -> Option<Rc<RefCell<SymbolTableEntry>>> {
//         // Get it, or if not found, try the parent (if any)
//         match self.func.get(name.as_ref()) {
//             Some(entry) => Some(entry.clone()),
//             None => match &self.parent {
//                 Some(parent) => parent.borrow().get_func_entry(name),
//                 None         => None,
//             }
//         }
//     }

//     /// Returns a reference to its entry if the given class exists in this symbol table or any of its parents.
//     ///
//     /// This function stops searching as soon as the first entry is found (walking up the tree), which allows shadowing of variables.
//     ///
//     /// # Generic parameters
//     /// - `S`: The &str-like type of the `name`.
//     ///
//     /// # Arguments
//     /// - `name`: The name/identifier of the class to search for.
//     ///
//     /// # Returns
//     /// The STClassEntry of this class if it existed, or else None.
//     #[inline]
//     pub fn get_class_entry<S: AsRef<str>>(&self, name: S) -> Option<Rc<RefCell<SymbolTableEntry>>> {
//         // Get it, or if not found, try the parent (if any)
//         match self.clss.get(name.as_ref()) {
//             Some(entry) => Some(entry.clone()),
//             None => match &self.parent {
//                 Some(parent) => parent.borrow().get_class_entry(name),
//                 None         => None,
//             }
//         }
//     }

//     /// Returns a reference to its entry if the given variable exists in this symbol table or any of its parents.
//     ///
//     /// This function stops searching as soon as the first entry is found (walking up the tree), which allows shadowing of variables.
//     ///
//     /// # Generic parameters
//     /// - `S`: The &str-like type of the `name`.
//     ///
//     /// # Arguments
//     /// - `name`: The name/identifier of the variable to search for.
//     ///
//     /// # Returns
//     /// The STFuncEntry of this variable if it existed, or else None.
//     #[inline]
//     pub fn get_var_entry<S: AsRef<str>>(&self, name: S) -> Option<Rc<RefCell<SymbolTableEntry>>> {
//         // Get it, or if not found, try the parent (if any)
//         match self.vars.get(name.as_ref()) {
//             Some(entry) => Some(entry.clone()),
//             None => match &self.parent {
//                 Some(parent) => parent.borrow().get_var_entry(name),
//                 None         => None,
//             }
//         }
//     }
// }
