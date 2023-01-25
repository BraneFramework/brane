//  AST.rs
//    by Lut99
// 
//  Created:
//    10 Aug 2022, 14:00:59
//  Last edited:
//    17 Jan 2023, 15:13:46
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines the AST that the `brane-dsl` parses to.
// 

use std::cell::RefCell;
use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::rc::Rc;
use std::str::FromStr;

use enum_debug::EnumDebug;
use specifications::version::{ParseError, Version};

use crate::spec::{TextPos, TextRange};
use crate::data_type::DataType;
use crate::location::AllowedLocations;
use crate::symbol_table::{ClassEntry, FunctionEntry, SymbolTable, SymbolTableEntry, VarEntry};


/***** STATICS *****/
/// Defines a none-range.
static NONE_RANGE: TextRange = TextRange::none();





/***** LIBRARY TRAITS *****/
/// Defines a general AST node.
pub trait Node: Clone + Debug {
    /// Returns the node's source range.
    fn range(&self) -> &TextRange;

    /// Returns the node's start position.
    #[inline]
    fn start(&self) -> &TextPos { &self.range().start }

    /// Returns the node's end position.
    #[inline]
    fn end(&self) -> &TextPos { &self.range().end }
}





/***** LIBRARY STRUCTS *****/
/// Defines the toplevel Program element.
#[derive(Clone, Debug)]
pub struct Program {
    /// The toplevel program is simply a code block with global variables.
    pub block : Block,
}

impl Node for Program {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange { self.block.range() }
}



/// Defines a code block (i.e., a series of statements).
#[derive(Clone, Debug)]
pub struct Block {
    /// The list of statements in this Block.
    pub stmts : Vec<Stmt>,

    /// The SymbolTable that remembers the scope of this block.
    pub table    : Rc<RefCell<SymbolTable>>,
    /// The return type as found in this block.
    pub ret_type : Option<DataType>,

    /// The range of the block in the source text.
    pub range : TextRange,
}

impl Block {
    /// Constructor for the Block that auto-initializes some auxillary fields.
    /// 
    /// # Arguments
    /// - `stmts`: The statements that live in this block.
    /// - `range`: The TextRange that anchors this block in the source file.
    /// 
    /// # Returns
    /// A new Block instance.
    #[inline]
    pub fn new(stmts: Vec<Stmt>, range: TextRange) -> Self {
        Self {
            stmts,

            table    : SymbolTable::new(),
            ret_type : None,

            range,
        }
    }
}

impl Default for Block {
    #[inline]
    fn default() -> Self {
        Self {
            stmts : vec![],

            table    : SymbolTable::new(),
            ret_type : None,

            range : TextRange::none(),
        }
    }
}

impl Node for Block {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange { &self.range }
}



/// Defines a single statement.
#[derive(Clone, Debug, EnumDebug)]
pub enum Stmt {
    /// Defines a block statement (i.e., `{ ... }`).
    Block {
        /// The actual block it references
        block : Box<Block>,  
    },

    /// Defines a package import.
    Import {
        /// The name of the package that we import.
        name    : Identifier,
        /// The version of the package that we import.
        version : Literal,

        /// Reference to the function symbol table entries that this import generates.
        st_funcs   : Option<Vec<Rc<RefCell<FunctionEntry>>>>,
        /// Reference to the class symbol table entries that this import generates.
        st_classes : Option<Vec<Rc<RefCell<ClassEntry>>>>,

        /// The range of the import statement in the source text.
        range : TextRange,
    },
    /// Defines a function definition.
    FuncDef {
        /// The name of the function, as an identifier.
        ident  : Identifier,
        /// The parameters of the function, as identifiers.
        params : Vec<Identifier>,
        /// The code to execute when running this function.
        code   : Box<Block>,

        /// Reference to the symbol table entry this function generates.
        st_entry : Option<Rc<RefCell<FunctionEntry>>>,

        /// The range of the function definition in the source text.
        range : TextRange,
    },
    /// Defines a class definition.
    ClassDef {
        /// The name of the class, as an identifier.
        ident   : Identifier,
        /// The properties of the class, as (identifier, type) pairs.
        props   : Vec<Property>,
        /// The methods belonging to this class, as a vector of function definitions.
        methods : Vec<Box<Stmt>>,

        /// Reference to the symbol table entry this class generates.
        st_entry     : Option<Rc<RefCell<ClassEntry>>>,
        /// The SymbolTable that hosts the nested declarations. Is also found in the ClassEntry itself to resolve children.
        symbol_table : Rc<RefCell<SymbolTable>>,

        /// The range of the class definition in the source text.
        range : TextRange,
    },
    /// Defines a return statement.
    Return {
        /// The expression to return.
        expr      : Option<Expr>,
        /// The expected return datatype.
        data_type : DataType,

        /// The range of the return statement in the source text.
        range : TextRange,
    },

    /// Defines an if-statement.
    If {
        /// The condition to branch on.
        cond        : Expr,
        /// The block for if the condition was true.
        consequent  : Box<Block>,
        /// The (optional) block for if the condition was false.
        alternative : Option<Box<Block>>,

        /// The range of the if-statement in the source text.
        range : TextRange,
    },
    /// Defines a for-loop.
    For {
        /// The statement that is run at the start of the for-loop.
        initializer : Box<Stmt>,
        /// The expression that has to evaluate to true while running.
        condition   : Expr,
        /// The statement that is run at the end of every iteration.
        increment   : Box<Stmt>,
        /// The block to run every iteration.
        consequent  : Box<Block>,

        /// The range of the for-loop in the source text.
        range : TextRange,
    },
    /// Defines a while-loop.
    While {
        /// The expression that has to evaluate to true while running.
        condition  : Expr,
        /// The block to run every iteration.
        consequent : Box<Block>,

        /// The range of the while-loop in the source text.
        range : TextRange,
    },
    /// Defines an on-block (i.e., code run on a specific location).
    On {
        /// An expression that resolves to the (string) location where to run the code.
        location : Expr,
        /// The block of code that is run on the target location.
        block    : Box<Block>,

        /// The range of the on-statement in the source text.
        range : TextRange,
    },
    /// Defines a parallel block (i.e., multiple branches run in parallel).
    Parallel {
        /// The (optional) identifier to which to write the result of the parallel statement.
        result : Option<Identifier>,
        /// The code blocks to run in parallel. This may either be a Block or an On-statement.
        blocks : Vec<Box<Stmt>>,
        /// The merge-strategy used in the parallel statement.
        merge  : Option<Identifier>,

        /// Reference to the variable to which the Parallel writes.
        st_entry : Option<Rc<RefCell<VarEntry>>>,

        /// The range of the parallel-statement in the source text.
        range : TextRange,
    },

    /// Defines a variable definition (i.e., `let <name> := <expr>`).
    LetAssign {
        /// The name of the variable referenced.
        name  : Identifier,
        /// The expression that gives a value to the assignment.
        value : Expr,

        /// Reference to the variable to which the let-assign writes.
        st_entry : Option<Rc<RefCell<VarEntry>>>,

        /// The range of the let-assign statement in the source text.
        range : TextRange,
    },
    /// Defines an assignment (i.e., `<name> := <expr>`).
    Assign {
        /// The name of the variable referenced.
        name  : Identifier,
        /// The expression that gives a value to the assignment.
        value : Expr,

        /// Reference to the variable to which the assign writes.
        st_entry : Option<Rc<RefCell<VarEntry>>>,

        /// The range of the assignment in the source text.
        range : TextRange,
    },
    /// Defines a loose expression.
    Expr {
        /// The expression to call.
        expr      : Expr,
        /// The data type of this expression. Relevant for popping or not.
        data_type : DataType,

        /// The range of the expression statement in the source text.
        range : TextRange,
    },

    /// A special, compile-time only statement that may be used to `mem::take` statements.
    Empty {},
}

impl Stmt {
    /// Creates a new Import node with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `name`: The name of the package to import (as an identifier).
    /// - `version`: The literal with the package version (i.e., should 'Literal::Semver'). 'latest' should be assumed if the user did not specify it.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Stmt::Import` instance.
    #[inline]
    pub fn new_import(name: Identifier, version: Literal, range: TextRange) -> Self {
        Self::Import {
            name,
            version,

            st_funcs   : None,
            st_classes : None,

            range,
        }
    }

    /// Creates a new FuncDef node with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `ident`: The name of the function, as an identifier.
    /// - `params`: The parameters of the function, as identifiers.
    /// - `code`: The code to execute when running this function.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Stmt::FuncDef` instance.
    #[inline]
    pub fn new_funcdef(ident: Identifier, params: Vec<Identifier>, code: Box<Block>, range: TextRange) -> Self {
        Self::FuncDef {
            ident,
            params,
            code,

            st_entry : None,

            range,
        }
    }

    /// Creates a new ClassDef node with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `ident`: The name of the class, as an identifier.
    /// - `props`: The properties of the class, as (identifier, type) pairs.
    /// - `methods`: The methods belonging to this class, as a vector of function definitions.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Stmt::ClassDef` instance.
    #[inline]
    pub fn new_classdef(ident: Identifier, props : Vec<Property>, methods : Vec<Box<Stmt>>, range: TextRange) -> Self {
        Self::ClassDef {
            ident,
            props,
            methods,

            st_entry     : None,
            symbol_table : SymbolTable::new(),

            range,
        }
    }

    /// Creates a new Return node with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `expr`: An optional expression to return from the function.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Stmt::Return` instance.
    #[inline]
    pub fn new_return(expr: Option<Expr>, range: TextRange) -> Self {
        Self::Return {
            expr,
            data_type : DataType::Any,

            range,
        }
    }

    /// Creates a new Parallel node with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `result`: An optional identifier to which this Parallel may write its result.
    /// - `blocks`: The codeblocks to run in parallel.
    /// - `merge`: The merge strategy to use for this Parallel statement.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Stmt::Parallel` instance.
    #[inline]
    pub fn new_parallel(result: Option<Identifier>, blocks: Vec<Box<Stmt>>, merge: Option<Identifier>, range: TextRange) -> Self {
        Self::Parallel {
            result,
            blocks,
            merge,

            st_entry : None,

            range,
        }
    }

    /// Creates a new LetAssign node with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `name`: The identifier of the variable to write to and initialize.
    /// - `value`: The value to write.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Stmt::LetAssign` instance.
    #[inline]
    pub fn new_letassign(name: Identifier, value: Expr, range: TextRange) -> Self {
        Self::LetAssign {
            name,
            value,

            st_entry : None,

            range,
        }
    }

    /// Creates a new Assign node with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `name`: The identifier of the variable to write to.
    /// - `value`: The value to write.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Stmt::LetAssign` instance.
    #[inline]
    pub fn new_assign(name: Identifier, value: Expr, range: TextRange) -> Self {
        Self::Assign {
            name,
            value,

            st_entry : None,

            range,
        }
    }

    /// Creates a new Expr node with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `expr`: The Expr to wrap.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Stmt::Expr` instance.
    #[inline]
    pub fn new_expr(expr: Expr, range: TextRange) -> Self {
        Self::Expr {
            expr,
            data_type : DataType::Any,

            range,
        }
    }
}

impl Default for Stmt {
    #[inline]
    fn default() -> Self {
        Self::Empty{}
    }
}

impl Node for Stmt {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange {
        use Stmt::*;
        match self {
            Block{ block } => block.range(),

            Import{ range, .. }   => range,
            FuncDef{ range, .. }  => range,
            ClassDef{ range, .. } => range,
            Return{ range, .. }   => range,

            If{ range, .. }       => range,
            For{ range, .. }      => range,
            While{ range, .. }    => range,
            On{ range, .. }       => range,
            Parallel{ range, .. } => range,

            LetAssign{ range, .. } => range,
            Assign{ range, .. }    => range,
            Expr{ range, .. }      => range,

            Empty{} => &NONE_RANGE,
        }
    }
}



/// Defines a (name, type) pair in a class definition.
#[derive(Clone, Debug)]
pub struct Property {
    /// The name of the property.
    pub name      : Identifier,
    /// The type of the property.
    pub data_type : DataType,

    /// Entry that refers to this property.
    pub st_entry : Option<Rc<RefCell<VarEntry>>>,

    /// The range of the property in the source text.
    pub range : TextRange,
}

impl Property {
    /// Constructor for the Property that sets a few auxillary fields to default values.
    /// 
    /// # Arguments
    /// - `name`: The name of the property (as an identifier).
    /// - `data_type`: The DataType of the property.
    /// - `range`: The TextRange that links this node back to the original source text.
    /// 
    /// # Returns
    /// A new Property instance.
    #[inline]
    pub fn new(name: Identifier, data_type: DataType, range: TextRange) -> Self {
        Self {
            name,
            data_type,

            st_entry : None,

            range,
        }
    }
}

impl Node for Property {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange { &self.range }
}



/// Defines an expression.
#[derive(Clone, Debug, EnumDebug)]
pub enum Expr {
    /// Casts between two functions types.
    Cast {
        /// The expression to cast
        expr   : Box<Expr>,
        /// The type to cast to
        target : DataType,

        /// The range of the call-expression in the source text.
        range  : TextRange,
    },

    /// A function call.
    Call {
        /// The thing that we're calling - obviously, this must be something with a function type.
        expr : Box<Expr>,
        /// The list of arguments for this call.
        args : Vec<Box<Expr>>,

        /// Reference to the call's function entry.
        st_entry  : Option<Rc<RefCell<FunctionEntry>>>,
        /// The locations where this Call is allowed to run based on the location of the datasets.
        locations : AllowedLocations,
        /// If this call takes in Data or IntermediateResult, then this field will list their names. Will only ever be the case if this call is an external call.
        input     : Vec<Data>,
        /// The intermediate result that this Call creates, if any. Will only ever be the case if this call is an external call.
        result    : Option<String>,

        /// The range of the call-expression in the source text.
        range  : TextRange,
    },
    /// An array expression.
    Array {
        /// The value in the array.
        values    : Vec<Box<Expr>>,
        /// The type of the Array.
        data_type : DataType,

        /// The range of the array-expression in the source text.
        range  : TextRange,
    },
    /// An ArrayIndex expression.
    ArrayIndex {
        /// The (array) expression that is indexed.
        array     : Box<Expr>,
        /// The indexing expression.
        index     : Box<Expr>,
        /// The type of the returned value.
        data_type : DataType,

        /// The range of the index-expression in the source text.
        range  : TextRange,
    },
    /// Bakery-specific Pattern expression.
    Pattern {
        /// The expressions in this pattern.
        exprs : Vec<Box<Expr>>, 

        /// The range of the pattern-expression in the source text.
        range : TextRange,
    },

    /// A unary operator.
    UnaOp {
        /// The operator to execute.
        op   : UnaOp,
        /// The expression.
        expr : Box<Expr>,

        /// The range of the unary operator in the source text.
        range  : TextRange,
    },
    /// A binary operator.
    BinOp {
        /// The operator to execute.
        op : BinOp,
        /// The lefthandside expression.
        lhs : Box<Expr>,
        /// The righthandside expression.
        rhs : Box<Expr>,

        /// The range of the binary operator-expression in the source text.
        range  : TextRange,
    },
    /// A special case of a binary operator that implements projection.
    Proj {
        /// The lefthandside expression.
        lhs : Box<Expr>,
        /// The righthandside expression.
        rhs : Box<Expr>,

        /// Reference to the entry that this projection points to.
        st_entry : Option<SymbolTableEntry>,

        /// The range of the projection-expression in the source text.
        range  : TextRange,
    },

    /// An instance expression (i.e., `new ...`).
    Instance {
        /// The identifier of the class to instantiate.
        name       : Identifier,
        /// The parameters to instantiate it with, as (parameter_name, value).
        properties : Vec<PropertyExpr>,

        /// The reference to the class we instantiate.
        st_entry   : Option<Rc<RefCell<ClassEntry>>>,

        /// The range of the instance-expression in the source text.
        range  : TextRange,
    },
    /// A variable reference.
    VarRef {
        /// The identifier of the referenced variable.
        name : Identifier,

        /// The entry referring to the variable referred.
        st_entry : Option<Rc<RefCell<VarEntry>>>,
    },
    /// An identifier is like a variable reference but even weaker (i.e., does not expliticly link to anything - just as a placeholder for certain functions).
    Identifier {
        /// The identifier that this expression represents.
        name : Identifier,

        /// The entry referring to the function referred. This only happens when used as identifier in a call expression.
        st_entry : Option<Rc<RefCell<FunctionEntry>>>,
    },
    /// A literal expression.
    Literal {
        /// The nested Literal.
        literal: Literal,
    },

    /// A special, compile-time only expression that may be used to `mem::take` statements.
    Empty {},
}

impl Default for Expr {
    #[inline]
    fn default() -> Self {
        Self::Empty{}
    }
}

impl Expr {
    /// Creates a new Cast expression with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `expr`: The expression to cast.
    /// - `target`: The target type to cast to.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Expr::Cast` instance.
    #[inline]
    pub fn new_cast(expr: Box<Expr>, target: DataType, range: TextRange) -> Self {
        Self::Cast {
            expr,
            target,

            range,
        }
    }



    /// Creates a new Call expression with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `expr`: The expression that produces the object that we call.
    /// - `args`: The arguments to call it with.
    /// - `range`: The TextRange that relates this node to the source text.
    /// - `locations`: The list of locations (as an AllowedLocation) where the call may be executed.
    /// 
    /// # Returns
    /// A new `Expr::Call` instance.
    #[inline]
    pub fn new_call(expr: Box<Expr>, args: Vec<Box<Expr>>, range: TextRange, locations: AllowedLocations) -> Self {
        Self::Call {
            expr,
            args,

            st_entry : None,
            locations,
            input    : vec![],
            result   : None,

            range,
        }
    }



    /// Creates a new Array expression with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `values`: The list of values that make up this Array.
    /// - `range`: The TextRange that links this Array to the source text.
    #[inline]
    pub fn new_array(values: Vec<Box<Expr>>, range: TextRange) -> Self {
        Self::Array {
            values,
            data_type : DataType::Any,

            range,
        }
    }

    /// Creates a new ArrayIndex expression with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `array`: The expression that evaluates to the Array.
    /// - `index`: The expression that evaluates to the Array's index.
    /// - `range`: The TextRange that links this Array to the source text.
    #[inline]
    pub fn new_array_index(array: Box<Expr>, index: Box<Expr>, range: TextRange) -> Self {
        Self::ArrayIndex {
            array,
            index,
            data_type : DataType::Any,

            range,
        }
    }



    /// Creates a new UnaOp expression with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `op`: The unary operator that this expression operates.
    /// - `expr`: The expression to execute the unary operation on.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Expr::UnaOp` instance.
    #[inline]
    pub fn new_unaop(op: UnaOp, expr: Box<Expr>, range: TextRange) -> Self {
        Self::UnaOp {
            op,
            expr,

            range,
        }
    }

    /// Creates a new BinOp expression with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `op`: The binary operator that this expression operates.
    /// - `lhs`: The lefthand-side expression to execute the binary operation on.
    /// - `rhs`: The righthand-side expression to execute the binary operation on.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Expr::BinOp` instance.
    #[inline]
    pub fn new_binop(op: BinOp, lhs: Box<Expr>, rhs: Box<Expr>, range: TextRange) -> Self {
        Self::BinOp {
            op,
            lhs,
            rhs,

            range,
        }
    }

    /// Creates a new Proj expression with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `lhs`: The left-hand side expression containing a nested projection or an identifier.
    /// 
    /// # Returns
    /// A new `Expr::Proj` instance.
    #[inline]
    pub fn new_proj(lhs: Box<Expr>, rhs: Box<Expr>, range: TextRange) -> Self {
        Self::Proj {
            lhs,
            rhs,

            st_entry : None,

            range,
        }
    }



    /// Creates a new Instance expression with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `name`: The name of the class that is being instantiated.
    /// - `properties`: The properties to instantiate it with.
    /// - `range`: The TextRange that relates this node to the source text.
    /// 
    /// # Returns
    /// A new `Expr::Instance` instance.
    #[inline]
    pub fn new_instance(name: Identifier, properties: Vec<PropertyExpr>, range: TextRange) -> Self {
        Self::Instance {
            name,
            properties,

            st_entry : None,

            range,
        }
    }

    /// Creates a new VarRef expression with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `name`: The name of the variable that is being referenced.
    /// 
    /// # Returns
    /// A new `Expr::VarRef` instance.
    #[inline]
    pub fn new_varref(name: Identifier) -> Self {
        Self::VarRef {
            name,

            st_entry : None,
        }
    }

    /// Creates a new Identifier expression with some auxillary fields set to empty.
    /// 
    /// # Arguments
    /// - `name`: The name of the identifier that is being stored here.
    /// 
    /// # Returns
    /// A new `Expr::Identifier` instance.
    #[inline]
    pub fn new_identifier(name: Identifier) -> Self {
        Self::Identifier { 
            name,

            st_entry : None,
        }
    }
}

impl Node for Expr {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange {
        use Expr::*;
        match self {
            Cast{ range, .. } => range,

            Call{ range, .. }       => range,
            Array{ range, .. }      => range,
            ArrayIndex{ range, .. } => range,
            Pattern{ range, .. }    => range,

            UnaOp{ range, .. } => range,
            BinOp{ range, .. } => range,
            Proj{ range, .. }  => range,

            Instance{ range, .. }  => range,
            VarRef{ name, .. }     => name.range(),
            Identifier{ name, .. } => name.range(),
            Literal{ literal }     => literal.range(),

            Empty{} => &NONE_RANGE,
        }
    }
}



/// Defines a simple enum that is either a Data or an IntermediateResult.
#[derive(Clone, Debug, EnumDebug, Eq, Hash, PartialEq)]
pub enum Data {
    /// It's a dataset (with the given name)
    Data(String),
    /// It's an intermediate result (with the given name)
    IntermediateResult(String),
}



/// Defines a common enum for both operator types.
#[derive(Clone, Debug, EnumDebug)]
pub enum Operator {
    /// Defines a unary operator.
    Unary(UnaOp),
    /// Defines a binary operator.
    Binary(BinOp),
}

impl Operator {
    /// Returns the binding power of this operator.
    /// 
    /// A higher power means that it binds stronger (i.e., has higher precedence).
    #[allow(dead_code)]
    #[inline]
    pub fn binding_power(&self) -> (u8, u8) {
        match &self {
            Operator::Unary(o)  => o.binding_power(),
            Operator::Binary(o) => o.binding_power(),
        }
    }
}

impl Node for Operator {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange {
        use Operator::*;
        match self {
            Unary(u)  => u.range(),
            Binary(b) => b.range(),
        }
    }
}

impl Display for Operator {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Operator::*;
        match self {
            Unary(o)  => write!(f, "{}", o),
            Binary(o) => write!(f, "{}", o),
        }
    }
}



/// Defines unary operators for this crate.
#[derive(Clone, Debug, EnumDebug)]
pub enum UnaOp {
    /// The '[' operator (index)
    Idx{ range: TextRange },
    /// The `!` operator (logical inversion)
    Not{ range: TextRange },
    /// The `-` operator (negation)
    Neg{ range: TextRange },
    /// The '(' operator (prioritize)
    Prio{ range: TextRange },
}

impl UnaOp {
    /// Returns the binding power of this operator.
    /// 
    /// A higher power means that it binds stronger (i.e., has higher precedence).
    #[inline]
    pub fn binding_power(&self) -> (u8, u8) {
        use UnaOp::*;
        match &self {
            Not{ .. }  => (0, 11),
            Neg{ .. }  => (0, 11),
            Idx{ .. }  => (11, 0),
            Prio{ .. } => (0, 0), // Handled seperatly by pratt parser.
        }
    }
}

impl Node for UnaOp {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange {
        use UnaOp::*;
        match self {
            Not{ range }  => range,
            Neg{ range }  => range,
            Idx{ range }  => range,
            Prio{ range } => range,
        }
    }
}

impl Display for UnaOp {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use UnaOp::*;
        match self {
            Idx{ .. }  => write!(f, "["),
            Not{ .. }  => write!(f, "!"),
            Neg{ .. }  => write!(f, "-"),
            Prio{ .. } => write!(f, "("),
        }
    }
}



/// Defines binary operators for this crate.
#[derive(Clone, Debug, EnumDebug)]
pub enum BinOp {
    /// The `&&` operator (logical and)
    And{ range: TextRange },
    /// The `||` operator (logical or)
    Or{ range: TextRange },

    /// The `+` operator (addition)
    Add{ range: TextRange },
    /// The `-` operator (subtraction)
    Sub{ range: TextRange },
    /// The `*` operator (multiplication)
    Mul{ range: TextRange },
    /// The `/` operator (division)
    Div{ range: TextRange },
    /// The '%' operator (modulo)
    Mod{ range: TextRange },

    /// The `==` operator (equality)
    Eq{ range: TextRange },
    /// The `!=` operator (not equal to)
    Ne{ range: TextRange },
    /// The `<` operator (less than)
    Lt{ range: TextRange },
    /// The `<=` operator (less than or equal to)
    Le{ range: TextRange },
    /// The `>` operator (greater than)
    Gt{ range: TextRange },
    /// The `>=` operator (greater than or equal to)
    Ge{ range: TextRange },

    // /// The `.` operator (projection)
    // Proj{ range: TextRange },
}

impl BinOp {
    /// Returns the binding power of this operator.
    /// 
    /// A higher power means that it binds stronger (i.e., has higher precedence).
    #[inline]
    pub fn binding_power(&self) -> (u8, u8) {
        match &self {
            BinOp::And{ .. } | BinOp::Or{ .. }                     => (1, 2),   // Conditional
            BinOp::Eq{ .. }  | BinOp::Ne{ .. }                     => (3, 4),   // Equality
            BinOp::Lt{ .. }  | BinOp::Gt{ .. }                     => (5, 6),   // Comparison
            BinOp::Le{ .. }  | BinOp::Ge{ .. }                     => (5, 6),   // Comparison
            BinOp::Add{ .. } | BinOp::Sub{ .. }                    => (7, 8),   // Terms
            BinOp::Mul{ .. } | BinOp::Div{ .. } | BinOp::Mod{ .. } => (9, 10),  // Factors
            // BinOp::Proj{ .. }                                      => (13, 14), // Nesting
        }
    }
}

impl Node for BinOp {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange {
        use BinOp::*;
        match self {
            And{ range } => range,
            Or{ range }  => range,

            Add{ range } => range,
            Sub{ range } => range,
            Mul{ range } => range,
            Div{ range } => range,
            Mod{ range } => range,

            Eq{ range } => range,
            Ne{ range } => range,
            Lt{ range } => range,
            Le{ range } => range,
            Gt{ range } => range,
            Ge{ range } => range,

            // Proj{ range } => range,
        }
    }
}

impl Display for BinOp {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use BinOp::*;
        match self {
            And{ .. } => write!(f, "&&"),
            Or{ .. }  => write!(f, "||"),

            Add{ .. } => write!(f, "+"),
            Sub{ .. } => write!(f, "-"),
            Mul{ .. } => write!(f, "*"),
            Div{ .. } => write!(f, "/"),
            Mod{ .. } => write!(f, "%"),

            Eq{ .. } => write!(f, "=="),
            Ne{ .. } => write!(f, "!="),
            Lt{ .. } => write!(f, "<"),
            Le{ .. } => write!(f, "<="),
            Gt{ .. } => write!(f, ">"),
            Ge{ .. } => write!(f, ">="),

            // Proj{ .. } => write!(f, "."),
        }
    }
}



/// Defines an (identifier, expr) pair.
#[derive(Clone, Debug)]
pub struct PropertyExpr {
    /// The property that is referenced.
    pub name  : Identifier,
    /// The value of the referenced property.
    pub value : Box<Expr>,

    /// The range of the proprety expression in the source text.
    pub range : TextRange,
}

impl Node for PropertyExpr {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange { &self.range }
}



/// Defines an identifier.
#[derive(Clone, Debug)]
pub struct Identifier {
    /// TThe string value of this identifier.
    pub value : String,
    /// The range of the identifier in the source text.
    pub range : TextRange,
}

impl Identifier {
    /// Constructor for the Identifier that pre-initializes it with some things.
    /// 
    /// # Arguments
    /// - `value`: The string value of the identifier.
    /// - `range`: The complete range of the entire identifier.
    /// 
    /// # Returns
    /// A new Identifier instance with the given values.
    #[inline]
    pub fn new(value: String, range: TextRange) -> Self {
        Self {
            value,
            range,
        }
    }
}

impl Node for Identifier {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange { &self.range }
}

// /// Defines an identifier.
// #[derive(Clone, Debug)]
// pub enum Identifier {
//     /// Defines a simple identifier of only one word.
//     Name {
//         /// The value of the identifier itself.
//         value : String,

//         /// The entry to which this variable references.
//         st_entry : Option<Rc<RefCell<STVarEntry>>>,

//         /// The range of the identifier in the source text.
//         range : TextRange,
//     },

//     /// Defines a more complex identifier that is a projection.
//     Proj {
//         /// The value of the lhs of the projection.
//         lhs : Box<Self>,
//         /// The value of the rhs of the projection.
//         rhs : Box<Self>,

//         /// The class to which the left-hand side references.
//         st_entry : Option<Rc<RefCell<STClassEntry>>>,

//         /// The range of the identifier in the source text.
//         range : TextRange,
//     }
// }

// impl Identifier {
//     /// Constructor for the Identifier that initializes some auxillary fields to empty.
//     /// 
//     /// # Arguments
//     /// - `value`: The value (i.e., identifier) of the identifier.
//     /// - `range`: The range of the identifier in the source text.
//     /// 
//     /// # Returns
//     /// A new Identifier instance with the given value and range.
//     #[inline]
//     pub fn new_name(value: String, range: TextRange) -> Self {
//         Self::Name {
//             value,

//             st_entry : None,

//             range,
//         }
//     }

//     /// Constructor for the Identifier that initializes it as a project operator (and sets some auxillary fields to empty).
//     /// 
//     /// # Arguments
//     /// - `lhs`: The left-hand side value of the identifier.
//     /// - `rhs`: The right-hand side value of the identifier.
//     /// - `range`: The range of the identifier in the source text.
//     /// 
//     /// # Returns
//     /// A new Identifier instance with the given value and range.
//     #[inline]
//     pub fn new_proj(lhs: Box<Self>, rhs: Box<Self>, range: TextRange) -> Self {
//         Self::Proj {
//             lhs,
//             rhs,

//             st_entry : None,

//             range,
//         }
//     }



//     /// Sets the st_entry of this Identifier as if this is an `Identifier::Name`.
//     /// 
//     /// # Arguments
//     /// - `entry`: The entry to set.
//     /// 
//     /// # Returns
//     /// Nothing, but does change the internal value.
//     /// 
//     /// # Panics
//     /// This function panics if this was an `Identifier::Proj` instead of an `Identifier::Name`.
//     #[inline]
//     pub fn set_entry(&mut self, entry: Rc<RefCell<STVarEntry>>) {
//         if let Identifier::Name{ ref mut st_entry, .. } = self {
//             *st_entry = Some(entry);
//         } else {
//             panic!("Cannot set entry value of Name identifier (is Proj identifier)");
//         }
//     }

//     /// Builds a complete identifier from the parts.
//     /// 
//     /// # Returns
//     /// Either the normal value if this is an `Identifier::Name`, or else a combination of all nested identifiers separated by dots if it is an `Identifier::Proj`.
//     #[inline]
//     pub fn full_value(&self) -> String {
//         match self {
//             Identifier::Name{ value, .. }    => value.clone(),
//             Identifier::Proj{ lhs, rhs, .. } => format!("{}.{}", lhs.full_value(), rhs.full_value()),
//         }
//     }

//     /// Returns the value of the identifier if this is a Name identifier.
//     /// 
//     /// # Returns
//     /// A string reference to the identifier value.
//     /// 
//     /// # Panics
//     /// This function panics if this was an `Identifier::Proj` instead of an `Identifier::Name`.
//     #[inline]
//     pub fn value(&self) -> &str {
//         if let Identifier::Name{ value, .. } = self {
//             value
//         } else {
//             panic!("Cannot set entry value of Name identifier (is Proj identifier)");
//         }
//     }

//     /// Returns the variable entry of the identifier if this is a Name identifier.
//     /// 
//     /// # Returns
//     /// An STVarEntry that represents the referenced variable.
//     /// 
//     /// # Panics
//     /// This function panics if this was an `Identifier::Proj` instead of an `Identifier::Name`.
//     #[inline]
//     pub fn st_entry(&self) -> &Option<Rc<RefCell<STVarEntry>>> {
//         if let Identifier::Name{ st_entry, .. } = self {
//             st_entry
//         } else {
//             panic!("Cannot get entry value of Name identifier (is Proj identifier)");
//         }
//     }
// }

// impl Node for Identifier {
//     /// Returns the node's source range.
//     #[inline]
//     fn range(&self) -> &TextRange {
//         use Identifier::*;
//         match self {
//             Name{ range, .. } => range,
//             Proj{ range, .. } => range,
//         }
//     }
// }



/// Defines a literal constant.
#[derive(Clone, Debug, EnumDebug)]
pub enum Literal {
    /// Defines the null literal.
    Null{
        /// The range of the boolean in the source text.
        range : TextRange,
    },

    /// Defines a boolean literal.
    Boolean{
        /// The value of the Boolean.
        value : bool,

        /// The range of the boolean in the source text.
        range : TextRange,
    },

    /// Defines an integral literal.
    Integer{
        /// The value of the Integer.
        value : i64,

        /// The range of the integer in the source text.
        range : TextRange,
    },

    /// Defines a floating-point literal.
    Real{
        /// The value of the Real.
        value : f64,

        /// The range of the real in the source text.
        range : TextRange,
    },

    /// Defines a String literal.
    String{
        /// The value of the String.
        value : String,

        /// The range of the string in the source text.
        range : TextRange,
    },

    /// Defines a SemVer literal.
    Semver {
        /// We did not parse the semver _yet_.
        value : String,

        range : TextRange,
    },

    /// Defines a Void literal (no value).
    Void {
        /// The range of the void in the source text.
        range : TextRange,
    }
}

impl Literal {
    /// Returns the value of the Literal as if it is a Boolean.
    /// 
    /// # Returns
    /// The value of this Boolean literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not a Boolean.
    #[inline]
    pub fn as_bool(&self) -> bool {
        use Literal::*;
        if let Boolean{ value, .. } = self {
            *value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'Boolean'", self.data_type());
        }
    }

    /// Returns a reference to the value of the Literal as if it is a Boolean.
    /// 
    /// # Returns
    /// A reference to the value of this Boolean literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not a Boolean.
    #[inline]
    pub fn as_bool_ref(&self) -> &bool {
        use Literal::*;
        if let Boolean{ value, .. } = self {
            value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'Boolean'", self.data_type());
        }
    }

    /// Returns a muteable reference to the value of the Literal as if it is a Boolean.
    /// 
    /// # Returns
    /// A muteable reference to the value of this Boolean literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not a Boolean.
    #[inline]
    pub fn as_bool_mut(&mut self) -> &mut bool {
        use Literal::*;
        if let Boolean{ ref mut value, .. } = self {
            value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'Boolean'", self.data_type());
        }
    }



    /// Returns the value of the Literal as if it is an Integer.
    /// 
    /// # Returns
    /// The value of this Integer literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not an Integer.
    #[inline]
    pub fn as_int(&self) -> i64 {
        use Literal::*;
        if let Integer{ value, .. } = self {
            *value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'Integer'", self.data_type());
        }
    }

    /// Returns a reference to the value of the Literal as if it is an Integer.
    /// 
    /// # Returns
    /// A reference to the value of this Integer literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not an Integer.
    #[inline]
    pub fn as_int_ref(&self) -> &i64 {
        use Literal::*;
        if let Integer{ value, .. } = self {
            value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'Integer'", self.data_type());
        }
    }

    /// Returns a muteable reference to the value of the Literal as if it is an Integer.
    /// 
    /// # Returns
    /// A muteable reference to the value of this Integer literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not an Integer.
    #[inline]
    pub fn as_int_mut(&mut self) -> &mut i64 {
        use Literal::*;
        if let Integer{ ref mut value, .. } = self {
            value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'Integer'", self.data_type());
        }
    }



    /// Returns the value of the Literal as if it is a Real.
    /// 
    /// # Returns
    /// The value of this Real literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not a Real.
    #[inline]
    pub fn as_real(&self) -> f64 {
        use Literal::*;
        if let Real{ value, .. } = self {
            *value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'Real'", self.data_type());
        }
    }

    /// Returns a reference to the value of the Literal as if it is a Real.
    /// 
    /// # Returns
    /// A reference to the value of this Real literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not a Real.
    #[inline]
    pub fn as_real_ref(&self) -> &f64 {
        use Literal::*;
        if let Real{ value, .. } = self {
            value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'Real'", self.data_type());
        }
    }

    /// Returns a muteable reference to the value of the Literal as if it is a Real.
    /// 
    /// # Returns
    /// A muteable reference to the value of this Real literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not a Real.
    #[inline]
    pub fn as_real_mut(&mut self) -> &mut f64 {
        use Literal::*;
        if let Real{ ref mut value, .. } = self {
            value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'Real'", self.data_type());
        }
    }



    /// Returns a reference to the value of the Literal as if it is a String.
    /// 
    /// # Returns
    /// A reference to the value of this String literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not a String.
    #[inline]
    pub fn as_string_ref(&self) -> &str {
        use Literal::*;
        if let String{ value, .. } = self {
            value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'String'", self.data_type());
        }
    }

    /// Returns a muteable reference to the value of the Literal as if it is a String.
    /// 
    /// # Returns
    /// A muteable reference to the value of this String literal.
    /// 
    /// # Panics
    /// This function panics if the Literal is not a String.
    #[inline]
    pub fn as_string_mut(&mut self) -> &mut str {
        use Literal::*;
        if let String{ ref mut value, .. } = self {
            value
        } else {
            panic!("Attempted to get Literal of type '{}' as 'String'", self.data_type());
        }
    }



    /// Returns a (parsed) semantic version from the Literal as if it is a Semver.
    /// 
    /// # Returns
    /// A freshly parsed (i.e., non-trivial retrieval) of a Version.
    /// 
    /// # Errors
    /// This function errors if we could not parse the Semver as a Version.
    /// 
    /// # Panics
    /// This function panics if the Literal is not a Semver.
    #[inline]
    pub fn as_version(&self) -> Result<Version, ParseError> {
        use Literal::*;
        if let Semver{ value, .. } = self {
            Version::from_str(value)
        } else {
            panic!("Attempted to get Literal of type '{}' as 'Semver'", self.data_type());
        }
    }



    /// Returns the data type of this Literal.
    #[inline]
    pub fn data_type(&self) -> DataType {
        use Literal::*;
        match self {
            Null{ .. }    => DataType::Any,
            Boolean{ .. } => DataType::Boolean,
            Integer{ .. } => DataType::Integer,
            Real{ .. }    => DataType::Real,
            String{ .. }  => DataType::String,
            Semver{ .. }  => DataType::Semver,
            Void{ .. }    => DataType::Void,
        }
    }
}

impl Node for Literal {
    /// Returns the node's source range.
    #[inline]
    fn range(&self) -> &TextRange {
        use Literal::*;
        match self {
            Null{ range, .. }    => range,
            Boolean{ range, .. } => range,
            Integer{ range, .. } => range,
            Real{ range, .. }    => range,
            String{ range, .. }  => range,
            Semver{ range, .. }  => range,
            Void{ range, .. }    => range,
        }
    }
}
