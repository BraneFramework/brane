//  AST.rs
//    by Lut99
// 
//  Created:
//    30 Aug 2022, 11:55:49
//  Last edited:
//    23 Jan 2023, 10:42:50
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines the `brane-ast`  AST, which is defined as an acyclic* graph
//!   where the nodes are external, orchestratable and policy-sensitive
//!   tasks (e.g., compute tasks or transfer tasks), and the edges are
//!   'control flow' that are small pieces of BraneScript that decide
//!   which task to compute next. Can be thought of as a graph with
//!   intelligent edges.
// 

use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter, Result as FResult};
use std::sync::Arc;

use enum_debug::EnumDebug;
use serde::{Deserialize, Serialize};
use serde_json_any_key::any_key_map;

use brane_dsl::spec::MergeStrategy;
use specifications::data::AvailabilityKind;
use specifications::package::Capability;
use specifications::version::Version;

use crate::errors::DataNameDeserializeError;
use crate::data_type::DataType;
use crate::locations::{Location, Locations};
use crate::state::TableList;


/***** CONSTANTS *****/
lazy_static!(
    /// A static FunctionDef for the Transfer.
    pub static ref TRANSFER_FUNC: FunctionDef = FunctionDef{ name: "transfer".into(), args: vec![ DataType::Data, DataType::Data ], ret: DataType::Void, table: SymTable::new() };
);





/***** TOPLEVEL *****/
/// Defines a Workflow, which is meant to be an 'executable but reasonable' graph.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Workflow {
    /// The global symbol / definition table. This specific table is also affectionally referred to as the "Workflow table".
    pub table : Arc<SymTable>,

    /// Implements the graph. Note that the ordering of this graph is important, but it will not be executed linearly.
    pub graph : Arc<Vec<Edge>>,
    /// Contains the parts of the graph that are callable.
    pub funcs : Arc<HashMap<usize, Vec<Edge>>>,
}

impl Workflow {
    /// Constructor for the Workflow that initializes it to the given contents.
    /// 
    /// # Arguments
    /// - `table`: The DefTable that contains the definitions in this workflow.
    /// - `graph`: The main edges that compose this Workflow.
    /// - `funcs`: Auxillary edges that provide a kind of function-like paradigm to the edges.
    /// 
    /// # Returns
    /// A new Workflow instance.
    #[inline]
    pub fn new(table: SymTable, graph: Vec<Edge>, funcs: HashMap<usize, Vec<Edge>>) -> Self {
        Self {
            table : Arc::new(table),

            graph : Arc::new(graph),
            funcs : Arc::new(funcs),
        }
    }



    /// Returns the edge pointed to by the given PC.
    /// 
    /// # Arguments
    /// - `pc`: The position of the Edge to return. Given as a pair of `(function index, edge index in that function)`, where a function index of `usize::MAX` means it's the main script function.
    /// 
    /// # Returns
    /// A reference to the Edge pointed to by the given PC.
    /// 
    /// # Panics
    /// This function panics if either part of the `pc` is out-of-bounds _and_ the function index is not `usize::MAX`.
    #[inline]
    pub fn edge(&self, pc: (usize, usize)) -> &Edge {
        if pc.0 == usize::MAX {
            // Main
            if pc.1 >= self.graph.len() { panic!("Edge index {} is out-of-bounds for main function of {} edges", pc.1, self.graph.len()); }
            &self.graph[pc.1]
        } else {
            // It's a function
            match self.funcs.get(&pc.0) {
                Some(graph) => {
                    if pc.1 >= graph.len() { panic!("Edge index {} is out-of-bounds for function '{}' of {} edges", pc.1, self.table.funcs[pc.0].name, graph.len()); }
                    &graph[pc.1]
                },
                None => { panic!("Function index {} is unknown", pc.0); },
            }
        }
    }
}

impl Default for Workflow {
    #[inline]
    fn default() -> Self {
        Self {
            table : Arc::new(SymTable::new()),

            graph : Arc::new(vec![]),
            funcs : Arc::new(HashMap::new()),
        }
    }
}



/// Defines the SymTable, which is like a symbol table (very much so, even) but now specific to Workflowland.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SymTable {
    /// Lists all edge functions used in the Workflow.
    pub funcs   : TableList<FunctionDef>,
    /// Lists all tasks used in the workflow.
    pub tasks   : TableList<TaskDef>,
    /// Lists all classes used in the Workflow.
    pub classes : TableList<ClassDef>,
    /// Lists _only_ toplevel / global variables used in the Workflow. Any in-function variables will be kept in the function itself.
    pub vars    : TableList<VarDef>,

    /// Lists intermediate results defined in this workflow and maps them to where to find them (the name of the location).
    pub results : HashMap<String, String>,
}

impl SymTable {
    /// Constructor for the SymTable that initializes it to empty.
    /// 
    /// # Returns
    /// A new SymTable instance.
    #[inline]
    pub fn new() -> Self {
        Self {
            funcs   : TableList::new(0),
            tasks   : TableList::new(0),
            classes : TableList::new(0),
            vars    : TableList::new(0),

            results : HashMap::new(),
        }
    }

    /// Constructor for the SymTable that takes the given vectors instead.
    /// 
    /// # Arguments
    /// - `funcs`: A vector of `FunctionDef`initions that defines all functions in the table.
    /// - `tasks`: A vector of `TaskDef`initions that defines all _external_ functions in the table.
    /// - `classes`: A vector of `ClassDef`initions that defines all classes in the table.
    /// - `vars`: A vector of `VarDef`initions that defines all variable in the table.
    /// - `results`: A map with the intermediate results (as `String`, `PathBuf` pairs).
    /// 
    /// # Returns
    /// A new SymTable instance with the given definitions already added.
    #[inline]
    pub fn with(funcs: TableList<FunctionDef>, tasks: TableList<TaskDef>, classes: TableList<ClassDef>, vars: TableList<VarDef>, results: HashMap<String, String>) -> Self {
        Self {
            funcs,
            tasks,
            classes,
            vars,

            results,
        }
    }
}

impl Default for SymTable {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}



/// Defines a function that is referenced in the edges.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FunctionDef {
    /// The name of the function.
    #[serde(rename = "n")]
    pub name : String,

    /// The types of the (and the number of) arguments.
    #[serde(rename = "a")]
    pub args : Vec<DataType>,
    /// The return type of the function.
    #[serde(rename = "r")]
    pub ret  : DataType,

    /// A table of definitions that occur within this function.
    #[serde(rename = "t")]
    pub table : SymTable,
}



/// Defines a Task (i.e., a Node) in the Workflow graph.
#[derive(Clone, Debug, Deserialize, EnumDebug, Serialize)]
#[serde(tag = "kind")]
pub enum TaskDef {
    /// Defines a compute task, i.e., a task that is externally called.
    #[serde(rename = "cmp")]
    Compute(ComputeTaskDef),

    /// Defines a transfer task, i.e., a data transfer between two domains.
    #[serde(rename = "trf")]
    Transfer,
}

impl TaskDef {
    /// Returns the name of the TaskDef.
    #[inline]
    pub fn name(&self) -> &str {
        use TaskDef::*;
        match self {
            Compute(def) => &def.function.name,
            Transfer     => &TRANSFER_FUNC.name,
        }
    }

    /// Returns the function definition for this TaskDef.
    #[inline]
    pub fn func(&self) -> &FunctionDef {
        use TaskDef::*;
        match self {
            Compute(def) => &def.function,
            Transfer     => &TRANSFER_FUNC,
        }
    }
}

/// Defines the contents of a compute task.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComputeTaskDef {
    /// The name of the package that this task belongs to.
    #[serde(rename = "p")]
    pub package    : String,
    /// The version of the package that this task belongs to.
    #[serde(rename = "v")]
    pub version    : Version,

    /// The definition of the function that this package implements.
    #[serde(rename = "d")]
    pub function   : Box<FunctionDef>,
    /// A list of names for every argument.
    #[serde(rename = "a")]
    pub args_names : Vec<String>,
    /// Any requirements required for this task.
    #[serde(rename = "r")]
    pub requirements : HashSet<Capability>,
}



/// Defines a class that is referenced in the edges.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClassDef {
    /// The name of the class.
    #[serde(rename = "n")]
    pub name    : String,
    /// If this class was external, the name of the package.
    #[serde(rename = "i")]
    pub package : Option<String>,
    /// The version of the package that this class belongs to.
    #[serde(rename = "v")]
    pub version : Option<Version>,

    /// The properties in this class.
    #[serde(rename = "p")]
    pub props   : Vec<VarDef>,
    /// The methods in this class. Note that these are references, since they are actually defined in the class.
    #[serde(rename = "m")]
    pub methods : Vec<usize>,
}



/// Defines a variable that is referenced in the edges.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VarDef {
    /// The name of the variable.
    #[serde(rename = "n")]
    pub name      : String,
    /// The type of the variable.
    #[serde(rename = "t")]
    pub data_type : DataType,
}





/***** EDGES *****/
/// Defines an Edge (i.e., an intelligent control-flow operation) in the Workflow graph.
/// 
/// Is also referred to as an 'Edge' for historical reasons and because almost all of the elements are edge variants. In fact, the only Node is 'Node', which is why the rest doesn't explicitly mentions it being an edge.
/// 
/// The edges can be thought of as a linked list of statements. However, each statement may secretly group multiple statements (instrucitons) to make reasoning about the graph easier.
/// 
/// Finally, the developers would like to formally apologize for completely butchering the term 'Edge'.
#[derive(Clone, Debug, Deserialize, EnumDebug, Serialize)]
#[serde(tag = "kind")]
pub enum Edge {
    // Linear edges
    /// A Node is an edge that runs a task. It has one input edge and one output edge.
    #[serde(rename = "nod")]
    Node {
        /// The task to call
        #[serde(rename = "t")]
        task   : usize,
        /// An additional list that may or may not restrict locations.
        #[serde(rename = "l")]
        locs   : Locations,
        /// Annotation about where the task will be run. This is not meant to be populated by anyone except the planner.
        #[serde(rename = "s")]
        at     : Option<Location>,
        /// Reference to any input datasets/results that are being input to this node together with how they might be accessed. This latter part is populated during planning.
        #[serde(rename = "i", with = "any_key_map")]
        input  : HashMap<DataName, Option<AvailabilityKind>>,
        /// Reference to the result if this call generates one.
        #[serde(rename = "r")]
        result : Option<String>,
        /// The next edge to execute (usually the next one)
        #[serde(rename = "n")]
        next   : usize,
    },
    /// A Linear edge is simple a series of instructions that are run, after which is goes to one new edge.
    #[serde(rename = "lin")]
    Linear {
        /// The series of instructions to execute.
        #[serde(rename = "i")]
        instrs : Vec<EdgeInstr>,
        /// The next edge to execute (usually the next one)
        #[serde(rename = "n")]
        next : usize,
    },
    /// A Stop is an edge that stops execution.
    #[serde(rename = "stp")]
    Stop {},

    // Branching/joining edges
    /// A Branching edge is an edge that branches into two possible (but disjoint) based on the result of a series of instructions.
    /// 
    /// # Stack layout
    /// - Requires a boolean to be on top of the stack.
    #[serde(rename = "brc")]
    Branch {
        /// The next edge to run if the condition returned 'true'. Is _not_ relative to the current program counter (i.e., if 0 is given, the first branch in the program is executed).
        #[serde(rename = "t")]
        true_next  : usize,
        /// The next edge to run if the condition returned 'false'. Is _not_ relative to the current program counter (i.e., if 0 is given, the first branch in the program is executed).
        #[serde(rename = "f")]
        false_next : Option<usize>,

        /// The location where the branches will join together if the Branch does not fully return. This is only here for analysis purposes; it's not used by the VM.
        #[serde(rename = "m")]
        merge : Option<usize>,
    },
    // Note that we do not have a 'BranchNot'; this is to make reasoning easier.
    /// A Parallel edge is an edge that branches into multiple branches that are all taken simultaneously.
    #[serde(rename = "par")]
    Parallel {
        /// The edges that kickoff each branch. Is _not_ relative to the current program counter (i.e., if 0 is given, then the first branch in the program is executed).
        #[serde(rename = "b")]
        branches : Vec<usize>,

        /// The location where the branches will merge together. This is only here for analysis purposes; it's not used by the VM.
        #[serde(rename = "m")]
        merge : usize,
    },
    /// A Join edge is an edge that joins multiple branches into one, waiting until all have been completed.
    /// 
    /// Note that the execution of the join-edge acts like a fence, so is quite non-trivial.
    #[serde(rename = "join")]
    Join {
        /// Defines the merge strategy of the Join, i.e., how to combine the results of the branches together.
        #[serde(rename = "m")]
        merge    : MergeStrategy,
        /// The next edge to execute (usually the next one)
        #[serde(rename = "n")]
        next     : usize,
    },

    // Looping edges
    /// Repeats a given set of edges indefinitely.
    #[serde(rename = "loop")]
    Loop {
        /// The edges that compute the condition.
        #[serde(rename = "c")]
        cond : usize,
        /// The edges that are repeated for as long as the condition returns 'true'.
        #[serde(rename = "b")]
        body : usize,
        /// The next edge to execute after the loop has been completed (usually the next one). Note, however, that this may be empty if the loop fully returns.
        #[serde(rename = "n")]
        next : Option<usize>,
    },

    // Calling edges
    /// A Calling edge is one that re-uses edges by executing the given edge instead. When done, the 'next' edge is pushed on the frame stack and popped when a Return edge is executed.
    /// 
    /// # Stack layout
    /// - Requires a Function object to be on top of the stack which will be called.
    /// - Requires N arguments of arbitrary type, where N is equal to the function object's arity. The first argument of the function is at the bottom, the last second-to-top on the stack.
    #[serde(rename = "cll")]
    Call {
        /// The next edge to execute (usually the next one)
        #[serde(rename = "n")]
        next   : usize,
    },
    /// A Returning edge is one that returns from a called edge by popping the next from the call stack.
    /// 
    /// # Stack layout
    /// - Optionally requires a value to be on the stack of the called function's return type. Whether or not this is need and which type that value has is determined by the top value on the frame stack.
    #[serde(rename = "ret")]
    Return {},
}



/// Defines an enum that represents either a Data or an IntermediateResult.
#[derive(Clone, Debug, Deserialize, EnumDebug, Eq, Hash, PartialEq, Serialize)]
pub enum DataName {
    /// It's referring a dataset
    Data(String),
    /// It's referring to an intermediate result
    IntermediateResult(String),
}

impl DataName {
    /// Returns whether this is a dataset.
    #[inline]
    pub fn is_data(&self) -> bool { matches!(self, Self::Data(_)) }

    /// Returns whether this is a result.
    #[inline]
    pub fn is_intermediate_result(&self) -> bool { matches!(self, Self::IntermediateResult(_)) }



    /// Returns a reference to the name in this DataName.
    #[inline]
    pub fn name(&self) -> &str {
        use DataName::*;
        match self {
            Data(name)               |
            IntermediateResult(name) => name.as_str(),
        }
    }

    /// Consumes this DataName and returns the inner name.
    #[inline]
    pub fn into_name(self) -> String {
        use DataName::*;
        match self {
            Data(name)               |
            IntermediateResult(name) => name,
        }
    }
}

impl Display for DataName {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use DataName::*;
        match self {
            Data(name)               => write!(f, "Data<{name}>"),
            IntermediateResult(name) => write!(f, "IntermediateResult<{name}>"),
        }
    }
}

impl From<&brane_dsl::ast::Data> for DataName {
    #[inline]
    fn from(value: &brane_dsl::ast::Data) -> Self { Self::from(value.clone()) }
}
impl From<&mut brane_dsl::ast::Data> for DataName {
    #[inline]
    fn from(value: &mut brane_dsl::ast::Data) -> Self {
        Self::from(value.clone())
    }
}
impl From<brane_dsl::ast::Data> for DataName {
    #[inline]
    fn from(value: brane_dsl::ast::Data) -> Self {
        match value {
            brane_dsl::ast::Data::Data(name)               => Self::Data(name),
            brane_dsl::ast::Data::IntermediateResult(name) => Self::IntermediateResult(name),
        }
    }
}

impl From<specifications::working::DataName> for DataName {
    #[inline]
    fn from(value: specifications::working::DataName) -> Self {
        match value {
            specifications::working::DataName::Data(name)               => Self::Data(name),
            specifications::working::DataName::IntermediateResult(name) => Self::IntermediateResult(name),
        }
    }
}
impl From<&specifications::working::DataName> for DataName {
    #[inline]
    fn from(value: &specifications::working::DataName) -> Self {
        Self::from(value.clone())
    }
}
impl From<&mut specifications::working::DataName> for DataName {
    #[inline]
    fn from(value: &mut specifications::working::DataName) -> Self {
        Self::from(value.clone())
    }
}
impl TryFrom<Option<specifications::working::DataName>> for DataName {
    type Error = DataNameDeserializeError;

    #[inline]
    fn try_from(value: Option<specifications::working::DataName>) -> Result<Self, Self::Error> {
        match value {
            Some(specifications::working::DataName::Data(name))               => Ok(Self::Data(name)),
            Some(specifications::working::DataName::IntermediateResult(name)) => Ok(Self::IntermediateResult(name)),
            None                                                              => Err(DataNameDeserializeError::UnknownDataName),
        }
    }
}
impl TryFrom<&Option<specifications::working::DataName>> for DataName {
    type Error = DataNameDeserializeError;

    #[inline]
    fn try_from(value: &Option<specifications::working::DataName>) -> Result<Self, Self::Error> {
        Self::try_from(value.clone())
    }
}
impl TryFrom<&mut Option<specifications::working::DataName>> for DataName {
    type Error = DataNameDeserializeError;

    #[inline]
    fn try_from(value: &mut Option<specifications::working::DataName>) -> Result<Self, Self::Error> {
        Self::try_from(value.clone())
    }
}
impl From<DataName> for specifications::working::DataName {
    #[inline]
    fn from(value: DataName) -> Self {
        match value {
            DataName::Data(name)               => specifications::working::DataName::Data(name),
            DataName::IntermediateResult(name) => specifications::working::DataName::IntermediateResult(name),
        }
    }
}
impl From<&DataName> for specifications::working::DataName {
    #[inline]
    fn from(value: &DataName) -> Self { Self::from(value.clone()) }
}
impl From<&mut DataName> for specifications::working::DataName {
    #[inline]
    fn from(value: &mut DataName) -> Self { Self::from(value.clone()) }
}



/// Defines an instruction for use within edges, which performs some computation in BraneScriptland (i.e., the edges).
#[derive(Clone, Debug, Deserialize, EnumDebug, Serialize)]
#[enum_debug(name)]
#[serde(tag = "kind")]
pub enum EdgeInstr {
    // Stack operations
    /// Casts the top value on the stack to another data type.
    /// 
    /// # Stack layout
    /// - A value with a datatype casteable to the target on top of the stack.
    #[serde(rename = "cst")]
    Cast {
        /// The target type to cast to.
        #[serde(rename = "t")]
        res_type : DataType,
    },
    /// Pops the top value of the stack without doing anything with it.
    /// 
    /// # Stack layout
    /// - At least one value of any type on top of the stack.
    #[serde(rename = "pop")]
    Pop {},
    /// Pushes a special, so-called PopMarker onto the stack. This is used to pop dynamically in the case expression return types are unresolved.
    #[serde(rename = "mpp")]
    PopMarker {},
    /// A _special_ pop that attempts to pop intelligently based on the stack. This is required for unresolved function return values, where we don't know how if the function produced a value to remove.
    /// 
    /// Use `EdgeInstr::PopMarker` to push the marker onto the stack. It will be invisible for other operations.
    /// 
    /// # Stack layout
    /// - At least one `PopMarker` value _somewhere_ on the stack. Anything up to there is popped.
    #[serde(rename = "dpp")]
    DynamicPop {},

    // Optimized control-flow instructions
    /// A branch instruction takes a branch if the top value on the stack is true.
    /// 
    /// # Stack layout
    /// - A boolean value on top of the stack.
    #[serde(rename = "brc")]
    Branch {
        /// The index of the flowstep where we jump to. Note that this address is actually relative to the _current_ (i.e., the branch's) program counter.
        #[serde(rename = "n")]
        next : i64,
    },
    /// The same as a branch, but now if the top value of the stack is false.
    /// 
    /// # Stack layout
    /// - A boolean value on top of the stack.
    #[serde(rename = "brn")]
    BranchNot {
        /// The index of the flowstep where we jump to. Note that this address is actually relative to the _current_ (i.e., the branch's) program counter.
        #[serde(rename = "n")]
        next : i64,
    },

    // Unary operators
    /// The `!` operator (logical inversion)
    /// 
    /// # Stack layout
    /// - A boolean value on top of the stack.
    #[serde(rename = "not")]
    Not {},
    /// The `-` operator (negation)
    /// 
    /// # Stack layout
    /// - A numeric (i.e., integral or real) value on top of the stack.
    #[serde(rename = "neg")]
    Neg {},

    // Binary operators
    /// The `&&` operator (logical and)
    #[serde(rename = "and")]
    And {},
    /// The `||` operator (logical or)
    #[serde(rename = "or")]
    Or {},

    /// The `+` operator (addition)
    /// 
    /// # Stack layout
    /// - A numeric (i.e., integral or real) value on top of the stack as the righthand-side.
    /// - Another numeric value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "add")]
    Add {},
    /// The `-` operator (subtraction)
    /// 
    /// # Stack layout
    /// - A numeric (i.e., integral or real) value on top of the stack as the righthand-side.
    /// - Another numeric value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "sub")]
    Sub {},
    /// The `*` operator (multiplication)
    /// 
    /// # Stack layout
    /// - A numeric (i.e., integral or real) value on top of the stack as the righthand-side.
    /// - Another numeric value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "mul")]
    Mul {},
    /// The `/` operator (division)
    /// 
    /// # Stack layout
    /// - A numeric (i.e., integral or real) value on top of the stack as the righthand-side.
    /// - Another numeric value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "div")]
    Div {},
    /// The '%' operator (modulo)
    /// 
    /// # Stack layout
    /// - An integral value on top of the stack as the righthand-side.
    /// - Another integral value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "mod")]
    Mod {},

    /// The `==` operator (equality)
    /// 
    /// # Stack layout
    /// - An arbitrary value on top of the stack as the righthand-side.
    /// - Another arbitrary value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "eq")]
    Eq {},
    /// The `!=` operator (not equal to)
    /// 
    /// # Stack layout
    /// - An arbitrary value on top of the stack as the righthand-side.
    /// - Another arbitrary value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "ne")]
    Ne {},
    /// The `<` operator (less than)
    /// 
    /// # Stack layout
    /// - A numeric (i.e., integral or real) value on top of the stack as the righthand-side.
    /// - Another numeric value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "lt")]
    Lt {},
    /// The `<=` operator (less than or equal to)
    /// 
    /// # Stack layout
    /// - A numeric (i.e., integral or real) value on top of the stack as the righthand-side.
    /// - Another numeric value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "le")]
    Le {},
    /// The `>` operator (greater than)
    /// 
    /// # Stack layout
    /// - A numeric (i.e., integral or real) value on top of the stack as the righthand-side.
    /// - Another numeric value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "gt")]
    Gt {},
    /// The `>=` operator (greater than or equal to)
    /// 
    /// # Stack layout
    /// - A numeric (i.e., integral or real) value on top of the stack as the righthand-side.
    /// - Another numeric value on second-to-top of the stack as the lefthand-side.
    #[serde(rename = "ge")]
    Ge {},

    /// Groups the previous N values on the stack into an Array.
    /// 
    /// # Stack layout
    /// - N elements on top of the stack of the same data type (stored in the Array instruction itself).
    #[serde(rename = "arr")]
    Array {
        /// The number of elements.
        #[serde(rename = "l")]
        length   : usize,
        /// The data type of this Array ('Array' included)
        #[serde(rename = "t")]
        res_type : DataType,
    },
    /// Gets the i'th element of the top element on the stack (as an Array). Note that the array itself should be on the second-to-top value on the stack, and the index the top one.
    /// 
    /// # Stack layout
    /// - An integral value on top of the stack that is the index.
    /// - An array value on second-to-top of the stack that is indexed.
    #[serde(rename = "arx")]
    ArrayIndex {
        /// The data type of this index expression
        #[serde(rename = "t")]
        res_type : DataType,
    },
    /// Pushes a new instance onto the stack. It uses the previous elements on there in reverse order.
    /// 
    /// # Stack layout
    /// - N values of heterogeneous types on top of the stack that form the properties. They should be sorted alphabetically, with the most a-ish property on the bottom and the most z-ish property on the top.
    #[serde(rename = "ins")]
    Instance {
        /// The signature of the instance we create.
        #[serde(rename = "d")]
        def : usize,
    },
    /// Projects/'indexes' the given instance with a certain field.
    /// 
    /// # Stack layout
    /// - An instance-value to project on top of the stack.
    #[serde(rename = "prj")]
    Proj {
        /// The name of the field to project.
        #[serde(rename = "f")]
        field : String,
    },

    /// Declares the given variable in the framestack.
    /// 
    /// It is a bit of an artificial instruction, mainly used to keep track of initialization status at runtime.
    #[serde(rename = "vrd")]
    VarDec {
        /// The identifier of the variable to declare.
        #[serde(rename = "d")]
        def : usize,
    },
    /// Undeclares the given variable in the framestack.
    /// 
    /// It's a bit of an artificial instruction, mainly used to keep track of initialization status at runtime.
    #[serde(rename = "vru")]
    VarUndec {
        /// The identifier of the variable to undeclare.
        #[serde(rename = "d")]
        def : usize,
    },
    /// Puts the value of the given variable on top of the stack.
    /// 
    /// # Stack layout
    /// - A value on top of the stack of the same type as the variable referenced.
    #[serde(rename = "vrg")]
    VarGet {
        /// The identifier of the variable.
        #[serde(rename = "d")]
        def : usize,
    },
    /// Pops the value on top of the stack to the given variable.
    #[serde(rename = "vrs")]
    VarSet {
        /// The identifier of the variable.
        #[serde(rename = "d")]
        def : usize,
    },

    // Literals
    /// Pushes a boolean value onto the stack.
    #[serde(rename = "bol")]
    Boolean {
        /// The value of the Bbolean.
        #[serde(rename = "v")]
        value : bool,
    },
    /// Pushes an integral value onto the stack.
    #[serde(rename = "int")]
    Integer {
        /// The value of the integer.
        #[serde(rename = "v")]
        value : i64,
    },
    /// Pushes a boolean value onto the stack.
    #[serde(rename = "rel")]
    Real {
        /// The value of the real.
        #[serde(rename = "v")]
        value : f64,
    },
    /// Pushes a boolean value onto the stack.
    #[serde(rename = "str")]
    String {
        /// The value of the string.
        #[serde(rename = "v")]
        value : String,
    },
    /// Pushes a function reference onto the stack.
    #[serde(rename = "fnc")]
    Function {
        /// The reference to the function that is pushed on top of it.
        #[serde(rename = "d")]
        def : usize,
    },
}

impl Display for EdgeInstr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use EdgeInstr::*;
        match self {
            Cast{ .. }       => write!(f, ".cast"),
            Pop{ .. }        => write!(f, ".pop"),
            PopMarker{ .. }  => write!(f, ".pop_marker"),
            DynamicPop{ .. } => write!(f, ".dpop"),

            Branch{ .. }    => write!(f, ".brch"),
            BranchNot{ .. } => write!(f, ".nbrch"),

            Not{ .. } => write!(f, ".not"),
            Neg{ .. } => write!(f, ".neg"),

            And{ .. } => write!(f, ".and"),
            Or{ .. }  => write!(f, ".or"),

            Add{ .. } => write!(f, ".add"),
            Sub{ .. } => write!(f, ".sub"),
            Mul{ .. } => write!(f, ".mul"),
            Div{ .. } => write!(f, ".div"),
            Mod{ .. } => write!(f, ".mod"),

            Eq{ .. } => write!(f, ".eq"),
            Ne{ .. } => write!(f, ".ne"),
            Lt{ .. } => write!(f, ".lt"),
            Le{ .. } => write!(f, ".le"),
            Gt{ .. } => write!(f, ".gt"),
            Ge{ .. } => write!(f, ".ge"),

            Array{ .. }      => write!(f, ".arr"),
            ArrayIndex{ .. } => write!(f, ".arr_idx"),
            Instance{ .. }   => write!(f, ".inst"),
            Proj{ .. }       => write!(f, ".proj"),

            VarDec { .. }   => write!(f, ".dec"),
            VarUndec { .. } => write!(f, ".undec"),
            VarGet { .. }   => write!(f, ".get"),
            VarSet { .. }   => write!(f, ".set"),

            Boolean{ .. }  => write!(f, ".bool"),
            Integer{ .. }  => write!(f, ".int"),
            Real{ .. }     => write!(f, ".real"),
            String{ .. }   => write!(f, ".str"),
            Function{ .. } => write!(f, ".func"),
        }
    }
}
