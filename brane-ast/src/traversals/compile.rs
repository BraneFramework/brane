//  COMPILE.rs
//    by Lut99
//
//  Created:
//    31 Aug 2022, 11:32:04
//  Last edited:
//    31 Jan 2024, 11:35:39
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the traversal in which the `brane-dsl` AST is finally
//!   converted to the `brane-ast` AST (i.e., BraneScript is compiled to a
//!   Workflow).
//

use std::cell::{Ref, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use brane_dsl::ast as dsl;
use brane_dsl::spec::MergeStrategy;
use brane_dsl::symbol_table::{FunctionEntry, VarEntry};
use enum_debug::EnumDebug as _;
use log::warn;
use specifications::data::DataName;

use crate::ast;
use crate::ast_unresolved::UnresolvedWorkflow;
use crate::edgebuffer::EdgeBuffer;
use crate::errors::AstError;
use crate::state::{CompileState, TableState};
use crate::warnings::AstWarning;
pub use crate::warnings::CompileWarning as Warning;

/***** COMPILATION FUNCTIONS *****/
/// Compiles a function's body to the given edge buffer.
///
/// # Arguments
/// - `index`: The index of the function in the workflow table.
/// - `args`: The arguments of the function, in-order.
/// - `code`: The function's body as a `Block`.
/// - `f_edges`: The map to generate new function bodies in.
/// - `table`: The TableState that we use to resolve definitions against.
/// - `warnings`: A list that will be used to catch warnings be thrown by the compiler.
///
/// # Returns
/// Nothing, but does extend the function map with a new edge buffer containing the compiled edges from the given body.
///
/// # Panics
/// This function panics if the given statement is _not_ a `Stmt::FuncDef`.
fn compile_func_def(
    index: usize,
    args: Vec<Rc<RefCell<VarEntry>>>,
    code: dsl::Block,
    f_edges: &mut HashMap<usize, EdgeBuffer>,
    table: &TableState,
    warnings: &mut Vec<Warning>,
) {
    // We compile to a separate list that will become the function (it will already have return junk)
    let mut func_edges: EdgeBuffer = EdgeBuffer::new();

    // Note, important: first write the arguments on the stack to its respective variables (we go back-to-front)
    for a in args.into_iter().rev() {
        let def: usize = a.borrow().index;
        func_edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::VarDec { def }, ast::EdgeInstr::VarSet { def }], next: usize::MAX });
    }

    // Compile the function itself
    pass_block(code, &mut func_edges, f_edges, table, warnings);

    // Add the list to the function map
    f_edges.insert(index, func_edges);

    // Done
}





/***** TRAVERSAL FUNCTIONS *****/
// /// Writes all of the definitions in the current block to the given unresolved workflow, and then also that of all nested blocks.
// ///
// /// # Arguments
// /// - `state`: The CompileState that we use to generate unique identifiers for the variables.
// /// - `block`: The Block to traverse.
// /// - `workflow`: The UnresolvedWorkflow to define everything in.
// ///
// /// # Returns
// /// Nothing, but does define all symbol table entries in the workflow's toplevel table.
// fn define_block(state: &mut CompileState, block: &dsl::Block, workflow: &mut UnresolvedWorkflow) {
//     // Define everything in this block
//     {
//         let st: Ref<SymbolTable> = block.table.borrow();

//         // Add the function entries
//         workflow.funcs.reserve(st.n_functions() / 2);
//         workflow.tasks.reserve(st.n_functions() / 2);
//         for (_, f) in st.functions() {
//             // Get a muteable borrow of the entry and set its inde
//             let mut f: RefMut<FunctionEntry> = f.borrow_mut();

//             // Split on function or task
//             match f.package_name.clone() {
//                 Some(package_name) => {
//                     // Compute task
//                     f.index = workflow.tasks.len();
//                     workflow.tasks.push(ast::TaskDef::Compute{
//                         package : package_name.clone(),
//                         version : f.package_version.clone().unwrap(),

//                         function   : ast::FunctionDef {
//                             name : f.name.clone(),
//                             args : f.signature.args.iter().map(|a| a.into()).collect(),
//                             ret  : (&f.signature.ret).into(),
//                         },
//                         args_names : f.arg_names.clone(),
//                     });
//                 },
//                 None => {
//                     // Local function
//                     f.index = workflow.funcs.len();
//                     workflow.funcs.push(ast::FunctionDef{
//                         name : f.name.clone(),
//                         args : f.signature.args.iter().map(|a| a.into()).collect(),
//                         ret  : (&f.signature.ret).into(),
//                     });
//                 },
//             }
//         }

//         // Add the class entries
//         workflow.classes.reserve(st.n_classes());
//         for (_, c) in st.classes() {
//             // Get a muteable borrow of the entry and set its inde
//             let mut c: RefMut<ClassEntry> = c.borrow_mut();
//             c.index = workflow.classes.len();

//             // Get the properties in alphabetical order
//             let cst: Ref<SymbolTable> = c.symbol_table.borrow();
//             let mut props: Vec<VarDef> = cst.variables().map(|v| ast::VarDef{ name: v.0.clone(), data_type: (&v.1.borrow().data_type).into() }).collect();
//             props.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

//             // Add any class methods first
//             workflow.funcs.reserve(st.n_functions());
//             for (_, f) in cst.functions() {
//                 // Get a muteable borrow of the entry and set its inde
//                 let mut f: RefMut<FunctionEntry> = f.borrow_mut();
//                 f.index = workflow.funcs.len();

//                 // Panic if package name
//                 if f.package_name.is_some() { panic!("Encountered task as class method; this should never happen!"); }

//                 // Add the function
//                 workflow.funcs.push(ast::FunctionDef{
//                     name : f.name.clone(),
//                     args : f.signature.args.iter().map(|a| a.into()).collect(),
//                     ret  : (&f.signature.ret).into(),
//                 });
//             }

//             // Add the entry as a ClassEntry
//             workflow.classes.push(ast::ClassDef{
//                 name    : c.signature.name.clone(),
//                 package : c.package_name.clone(),
//                 version : c.package_version.clone(),

//                 props,
//                 methods : cst.functions().map(|f| {
//                     let f: Ref<FunctionEntry> = f.1.borrow();
//                     f.index
//                 }).collect(),
//             });
//         }

//         // // Add the variable entries
//         // workflow.vars.reserve(st.n_variables());
//         // for (_, v) in st.variables() {
//         //     // Get a muteable borrow of the entry and set its inde
//         //     let mut v: RefMut<VarEntry> = v.borrow_mut();
//         //     v.index = workflow.vars.len();

//         //     // Skip if it's a class variable (those are used for definition only, but cannot carry values as they are duplicate for every instance of the class).
//         //     if v.class_name.is_some() { continue; }

//         //     // Add the entry as a VarEntry
//         //     workflow.vars.push(ast::VarDef{
//         //         name : v.name.clone(),
//         //         data_type : (&v.data_type).into(),
//         //     });
//         // }
//         // We don't have to add the variable entries to the table, but we can give them an identifier.
//         for (_, v) in st.variables() {
//             // Get a muteable borrow of the entry and set its inde
//             let mut v: RefMut<VarEntry> = v.borrow_mut();
//             v.index = state.var_id;
//             state.var_id += 1;
//         }
//     }

//     // Now iterate through the statements to find all other blocks
//     for s in &block.stmts {
//         use dsl::Stmt::*;
//         match s {
//             Block { block, .. } => {
//                 define_block(state, block, workflow);
//             },

//             FuncDef{ code, .. } => {
//                 define_block(state, code, workflow);
//             },
//             ClassDef{ methods, .. } => {
//                 // We recurse to compile the function bodies (not the functions themselves, since they have already been added).
//                 for m in methods {
//                     // Compile the function's body to a new function buffer in the function map
//                     if let FuncDef{ code, .. } = &**m {
//                         define_block(state, code, workflow);
//                     } else {
//                         panic!("Class method is not a FuncDef; this should never happen!");
//                     }
//                 }
//             },

//             If { consequent, alternative, .. } => {
//                 define_block(state, consequent, workflow);
//                 if let Some(alternative) = alternative {
//                     define_block(state, alternative, workflow);
//                 }
//             },
//             While{ consequent, .. } => {
//                 define_block(state, consequent, workflow);
//             },
//             On{ block, .. } => {
//                 define_block(state, block, workflow);
//             },
//             Parallel{ blocks, .. } => {
//                 // Write the branches to separate buffers
//                 for b in blocks {
//                     match &**b {
//                         Block{ block, .. } => { define_block(state, block, workflow); },
//                         On{ block, .. }    => { define_block(state, block, workflow); },
//                         _                  => { panic!("Found non-Block, non-On statement as a Parallel block"); }
//                     }
//                 }
//             },

//             // We don't care about the rest (or it does not occur anymore)
//             _ => {},
//         }
//     }
// }

/// Traverses Blocks, which are compiled to a series of edges implementing it.
///
/// # Arguments
/// - `block`: The Block to traverse.
/// - `edges`: The current list of edges to which we compile. Will probably reference one of the edges in the workflow.
/// - `f_edges`: The map to generate new function bodies in.
/// - `table`: The TableState that we use to resolve definitions against.
/// - `warnings`: A list that will be used to catch warnings be thrown by the compiler.
///
/// # Returns
/// Nothing, but does add the edges in the 'edges' and `workflow` structures.
fn pass_block(block: dsl::Block, edges: &mut EdgeBuffer, f_edges: &mut HashMap<usize, EdgeBuffer>, table: &TableState, warnings: &mut Vec<Warning>) {
    // Just compile the statements in the block.
    let mut decs: Vec<usize> = vec![];
    for s in block.stmts {
        // Before we pass the statement, check if it's a variable we should think about undeclaring
        match &s {
            dsl::Stmt::LetAssign { st_entry, .. } => {
                let entry: Ref<VarEntry> = st_entry.as_ref().unwrap().borrow();
                decs.push(entry.index);
            },
            dsl::Stmt::Parallel { st_entry: Some(st_entry), .. } => {
                let entry: Ref<VarEntry> = st_entry.borrow();
                decs.push(entry.index);
            },

            // The rest doesn't declare
            _ => {},
        }

        // Pass the statement to compile it
        pass_stmt(s, edges, f_edges, table, warnings);
    }

    // HOWEVER, also write out-of-scope functions for all variables declared within
    // Note, though, we don't do main to be friendly to snippet execution
    if block.table.borrow().parent.is_some() {
        for def in decs {
            // Write its undeclare
            edges.insert_at_end(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::VarUndec { def }], next: usize::MAX });
        }
    }

    // Done
}

/// Traveres Stmts, which are compiled to one or mutiple edges implementing it.
///
/// # Arguments
/// - `stmt`: The Stmt to traverse.
/// - `edges`: The current list of edges to which we compile. Will probably reference one of the edges in the workflow.
/// - `f_edges`: The map to generate new function bodies in.
/// - `table`: The TableState that we use to resolve definitions against.
/// - `warnings`: A list that will be used to catch warnings be thrown by the compiler.
///
/// # Returns
/// Nothing, but does add the edges in the 'edges' and `workflow` structures.
fn pass_stmt(stmt: dsl::Stmt, edges: &mut EdgeBuffer, f_edges: &mut HashMap<usize, EdgeBuffer>, table: &TableState, warnings: &mut Vec<Warning>) {
    // Match on the stmt itself
    use dsl::Stmt::*;
    match stmt {
        Block { block, .. } => {
            // Simply recurse the block
            pass_block(*block, edges, f_edges, table, warnings);
        },

        FuncDef { code, st_entry, .. } => {
            // Get the index of the definition (and its parameters)
            let (index, args): (usize, Vec<Rc<RefCell<VarEntry>>>) = {
                let entry: Ref<FunctionEntry> = st_entry.as_ref().unwrap().borrow();
                (entry.index, entry.params.clone())
            };

            // Compile the function's body to a new function buffer in the function ma
            compile_func_def(index, args, *code, f_edges, table, warnings);
        },
        ClassDef { methods, .. } => {
            // We recurse to compile the function bodies (not the functions themselves, since they have already been added).
            for m in methods {
                // Compile the function's body to a new function buffer in the function map
                if let FuncDef { code, st_entry, .. } = *m {
                    // Get the index of the definition (and its parameters)
                    let (index, args): (usize, Vec<Rc<RefCell<VarEntry>>>) = {
                        let entry: Ref<FunctionEntry> = st_entry.as_ref().unwrap().borrow();
                        (entry.index, entry.params.clone())
                    };

                    // Compile the function's body to a new function buffer in the function map
                    compile_func_def(index, args, *code, f_edges, table, warnings);
                } else {
                    panic!("Class method is not a FuncDef; this should never happen!");
                }
            }
        },
        Return { expr, output, .. } => {
            // Compile the expression first as separate edges
            if let Some(expr) = expr {
                pass_expr(expr, edges, table);
            }

            // End the branch instead of writing a Return
            edges.write_stop(ast::Edge::Return { result: output.iter().map(|data| DataName::from(data.clone())).collect() });
        },

        If { cond, consequent, alternative, .. } => {
            // First, prepare the stack by running the condition
            pass_expr(cond, edges, table);

            // Next, compile the consequent and alternative to separate (new) EdgeBuffers.
            let mut cons_edges: EdgeBuffer = EdgeBuffer::new();
            pass_block(*consequent, &mut cons_edges, f_edges, table, warnings);
            if !cons_edges.fully_returns() {
                cons_edges.write_end();
            }
            let alt_edges: Option<EdgeBuffer> = alternative.map(|a| {
                let mut res: EdgeBuffer = EdgeBuffer::new();
                pass_block(*a, &mut res, f_edges, table, warnings);
                if !res.fully_returns() {
                    res.write_end();
                }
                res
            });

            // Write it as a branch to the main list
            edges.write_branch(Some(cons_edges), alt_edges);
        },
        While { condition, consequent, .. } => {
            // Write the condition as a 'mini-function' that ends in a Return
            let mut cond_edges: EdgeBuffer = EdgeBuffer::new();
            pass_expr(condition, &mut cond_edges, table);
            if !cond_edges.fully_returns() {
                cond_edges.write_end();
            }

            // Write the consequence to a separate buffer
            let mut cons_edges: EdgeBuffer = EdgeBuffer::new();
            pass_block(*consequent, &mut cons_edges, f_edges, table, warnings);
            if !cons_edges.fully_returns() {
                cons_edges.write_end();
            }

            // Write them both a loop in the edges list
            edges.write_loop(cond_edges, cons_edges);
        },
        Parallel { blocks, merge, st_entry, .. } => {
            // Write the branches to separate buffers
            let mut branches: Vec<EdgeBuffer> = Vec::with_capacity(blocks.len());
            for b in blocks {
                let mut b_edges: EdgeBuffer = EdgeBuffer::new();
                pass_block(b, &mut b_edges, f_edges, table, warnings);
                if !b_edges.fully_returns() {
                    b_edges.write_stop(ast::Edge::Return { result: HashSet::new() });
                }
                branches.push(b_edges);
            }

            // Add that as a parallel statement
            edges.write_parallel(branches, merge.map(|m| MergeStrategy::from(m.value)).unwrap_or(MergeStrategy::None));

            // If required, add a variable set afterwards
            if let Some(st_entry) = st_entry {
                // Get the index of the definition
                let index: usize = st_entry.borrow().index;

                // Write the edge setting its value
                edges.write(ast::Edge::Linear {
                    instrs: vec![ast::EdgeInstr::VarDec { def: index }, ast::EdgeInstr::VarSet { def: index }],
                    next:   usize::MAX,
                });
            }
        },

        // Run let assigns as assigns, since the actual variable creation and removal is done at runtime
        LetAssign { value, st_entry, .. } => {
            let def: usize = st_entry.unwrap().borrow().index;

            // We always write a declare instruction first
            edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::VarDec { def }], next: usize::MAX });

            // If there is a non-null value, write a set immediately after
            if let dsl::Expr::Literal { literal: dsl::Literal::Null { .. } } = value {
                /* Do nothing */
            } else {
                // Prepare the stack by writing the expression
                pass_expr(value, edges, table);
                // Write the instruction
                edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::VarSet { def }], next: usize::MAX });
            }
        },
        Assign { value, st_entry, .. } => {
            // Prepare the stack by writing the expression
            pass_expr(value, edges, table);
            // Write the instruction
            edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::VarSet { def: st_entry.unwrap().borrow().index }], next: usize::MAX });
        },
        Expr { expr, data_type, .. } => {
            // If the expression's type is any, push the dynamic marker
            if let brane_dsl::DataType::Any = &data_type {
                edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::PopMarker {}], next: usize::MAX });
            }

            // Simply write the expression edges + a pop if required by the data type
            pass_expr(expr, edges, table);
            match data_type {
                // Write nothing if the statement does not return
                brane_dsl::DataType::Void => {},
                // Write the other half of the dynamic pop
                brane_dsl::DataType::Any => {
                    edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::DynamicPop {}], next: usize::MAX });
                },
                // Otherwise, write a static pop
                _ => {
                    edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Pop {}], next: usize::MAX });
                },
            }
        },

        // We don't care about the rest (or it does not occur anymore)
        Import { .. } | Empty {} => {},
        Attribute(_) | AttributeInner(_) | For { .. } => panic!("Encountered {:?} in compile traversal", stmt.variant()),
    }
}

/// Traveres Expr, which are compiled to one or mutiple edges implementing it.
///
/// Typically, this is a `Edge::Linear` (unless we encounter an external function call).
///
/// # Arguments
/// - `expr`: The Expr to traverse.
/// - `edges`: The current list of edges to which we compile. Will probably reference one of the edges in the workflow.
/// - `table`: The TableState to resolve class references in.
///
/// # Returns
/// Nothing, but does add the edges in the `edges` structure.
fn pass_expr(expr: dsl::Expr, edges: &mut EdgeBuffer, _table: &TableState) {
    // Switch on the type of expression
    use dsl::Expr::*;
    #[allow(clippy::collapsible_match)]
    match expr {
        Cast { expr, target, .. } => {
            // Write the expression first
            pass_expr(*expr, edges, _table);

            // Insert a linear edge with the cast instruction
            edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Cast { res_type: (&target).into() }], next: usize::MAX });
        },

        Call { expr, args, st_entry, locations, input, result, metadata, range: _ } => {
            // First, write the arguments followed by the call expression
            for a in args {
                pass_expr(*a, edges, _table);
            }
            pass_expr(*expr, edges, _table);

            // We now switch depending on the type of function called
            #[allow(clippy::unnecessary_unwrap)]
            if st_entry.is_some() && st_entry.as_ref().unwrap().borrow().package_name.is_some() {
                // Assert that the result is an intermediate result
                if result.len() > 1 {
                    panic!("Found external call with more than one results as output");
                }
                let result: Option<String> = result.iter().next().map(|result| {
                    if let dsl::Data::IntermediateResult(result) = result {
                        result.clone()
                    } else {
                        panic!("Found Data as output of task; this should never happen!");
                    }
                });

                // It's an external call; replace with a Node edge (so sorry everyone)
                edges.write(ast::Edge::Node {
                    task: st_entry.unwrap().borrow().index,
                    locs: locations.into(),
                    at: None,
                    input: input.into_iter().map(|d| (d.into(), None)).collect(),
                    result,
                    metadata: metadata.into_iter().map(|md| ast::Metadata { owner: md.owner, tag: md.tag, signature: None }).collect(),
                    next: usize::MAX,
                });
            } else {
                // It's a local call; replace with a Call edge
                edges.write(ast::Edge::Call {
                    input:  input.into_iter().map(|d| d.into()).collect(),
                    result: result.iter().map(|data| DataName::from(data.clone())).collect(),
                    next:   usize::MAX,
                });
            }
        },
        Array { values, data_type, .. } => {
            // Compute all of the expressions first
            let values_len: usize = values.len();
            for v in values {
                pass_expr(*v, edges, _table);
            }

            // Now add the Array instruction in a linear edge
            edges.write(ast::Edge::Linear {
                instrs: vec![ast::EdgeInstr::Array { length: values_len, res_type: (&data_type).into() }],
                next:   usize::MAX,
            });
        },
        ArrayIndex { array, index, data_type, .. } => {
            // Write the array, then the index
            pass_expr(*array, edges, _table);
            pass_expr(*index, edges, _table);

            // Write the index instruction in a linear edge
            edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::ArrayIndex { res_type: (&data_type).into() }], next: usize::MAX });
        },

        UnaOp { op, expr, .. } => {
            // We can always write the expression first
            pass_expr(*expr, edges, _table);

            // Match on the operator to write the proper instruction
            match op {
                dsl::UnaOp::Neg { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Neg {}], next: usize::MAX }),
                dsl::UnaOp::Not { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Not {}], next: usize::MAX }),

                // The rest should occur anymore
                op => {
                    warn!("Encountered operation '{:?}' that shouldn't occur anymore", op);
                },
            };
        },
        BinOp { op, lhs, rhs, .. } => {
            // We can always write the lefthand-side followed by the righthand-side first
            pass_expr(*lhs, edges, _table);
            pass_expr(*rhs, edges, _table);

            // Match the operator to write the proper instruction
            match op {
                dsl::BinOp::And { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::And {}], next: usize::MAX }),
                dsl::BinOp::Or { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Or {}], next: usize::MAX }),

                dsl::BinOp::Add { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Add {}], next: usize::MAX }),
                dsl::BinOp::Sub { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Sub {}], next: usize::MAX }),
                dsl::BinOp::Mul { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Mul {}], next: usize::MAX }),
                dsl::BinOp::Div { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Div {}], next: usize::MAX }),
                dsl::BinOp::Mod { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Mod {}], next: usize::MAX }),

                dsl::BinOp::Eq { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Eq {}], next: usize::MAX }),
                dsl::BinOp::Ne { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Ne {}], next: usize::MAX }),
                dsl::BinOp::Gt { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Gt {}], next: usize::MAX }),
                dsl::BinOp::Ge { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Ge {}], next: usize::MAX }),
                dsl::BinOp::Lt { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Lt {}], next: usize::MAX }),
                dsl::BinOp::Le { .. } => edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Le {}], next: usize::MAX }),
            };
        },
        Proj { lhs, rhs, .. } => {
            // We resolve at runtime; push the lefthand-side...
            pass_expr(*lhs, edges, _table);

            // ...get the name in the righthand-side...
            let field: String = if let dsl::Expr::Identifier { name, .. } = *rhs {
                name.value
            } else {
                panic!("Encountered a non-Identifier righthand-side of project expression");
            };

            // ...and write the project instruction
            edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Proj { field }], next: usize::MAX });
        },

        Instance { mut properties, st_entry, .. } => {
            // We always order the properties alphabetically to push them
            properties.sort_by(|p1, p2| p1.name.value.to_lowercase().cmp(&p2.name.value.to_lowercase()));
            for p in properties {
                pass_expr(*p.value, edges, _table);
            }

            // Bundle them in the instance
            edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Instance { def: st_entry.unwrap().borrow().index }], next: usize::MAX });
        },
        VarRef { st_entry, .. } => {
            // Push a simple var get
            edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::VarGet { def: st_entry.unwrap().borrow().index }], next: usize::MAX });
        },
        Identifier { st_entry, .. } => {
            // Dump the function if it has one
            if let Some(entry) = st_entry {
                // Push a Function onto the stack if it's not a task (otherwise, the node will properly reference it)
                let e: Ref<FunctionEntry> = entry.borrow();
                if e.package_name.is_none() {
                    // It's a local function
                    edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Function { def: e.index }], next: usize::MAX });
                }
            }
        },
        Literal { literal, .. } => {
            // Match the literal itself
            match literal {
                dsl::Literal::Null { .. } => panic!("A Literal::Null should not be compiled directly"),
                dsl::Literal::Boolean { value, .. } => {
                    edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Boolean { value }], next: usize::MAX })
                },
                dsl::Literal::Integer { value, .. } => {
                    edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Integer { value }], next: usize::MAX })
                },
                dsl::Literal::Real { value, .. } => {
                    edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::Real { value }], next: usize::MAX })
                },
                dsl::Literal::String { value, .. } => {
                    edges.write(ast::Edge::Linear { instrs: vec![ast::EdgeInstr::String { value }], next: usize::MAX })
                },

                // The rest is not relevant
                dsl::Literal::Semver { .. } | dsl::Literal::Void { .. } => {},
            };
        },

        // The rest either never occurs or we don't care about
        _ => {},
    }
}





/***** LIBRARY *****/
/// Compiles the given `brane-dsl` AST into a `brane-ast` AST.
///
/// Note that the symbol tables must already have been constructed, as well as type analysis and location analysis.
///
/// # Arguments
/// - `root`: The root node of the tree on which this compiler pass will be done.
/// - `warnings`: A list that will collect any warnings during compilation. If it's empty, then it may be assumed for warnings occurred.
///
/// # Returns
/// A new Workflow that contains the compiled program. However, its inter-edge links will still have to be resolved.
///
/// # Errors
/// This pass doesn't error, but might return one for convention purposes.
///
/// # Panics
/// This function may panic if any of the previous passes did not do its job, and the given Program is still ill-formed.
pub fn do_traversal(state: &CompileState, root: dsl::Program, warnings: &mut Vec<AstWarning>) -> Result<UnresolvedWorkflow, Vec<AstError>> {
    let mut warns: Vec<Warning> = vec![];

    // Then we can compile the program block to a series of edges
    let mut edges: EdgeBuffer = EdgeBuffer::new();
    let mut f_edges: HashMap<usize, EdgeBuffer> = HashMap::new();
    pass_block(root.block, &mut edges, &mut f_edges, &state.table, &mut warns);

    // Add a Stop edge to the main workflow
    if !edges.fully_returns() {
        edges.write_stop(ast::Edge::Stop {});
    }
    // Verify all functions fully return
    for (i, f) in &f_edges {
        if !f.fully_returns() {
            panic!("Function {} ({})'s edge stream does not fully return", *i, state.table.funcs[*i].name);
        }
    }

    // TODO: Optimize program size and reasonability by joining edges as much as possible.
    // -> see `workflow_optimize.rs`

    // [TODO]: Add optimization pass that groups as many edges together as possible, possibly even calling upong well-defined meta-edges that are easier to reason about.
    // -> see also `workflow_optimize.rs`??

    // Now build a new workflow and done
    let mut wf: UnresolvedWorkflow = UnresolvedWorkflow::new(edges, f_edges);
    wf.metadata = Arc::new(root.metadata.into_iter().map(|md| ast::Metadata { owner: md.owner, tag: md.tag, signature: None }).collect());
    warnings.append(&mut warns.into_iter().map(|w| w.into()).collect::<Vec<AstWarning>>());
    Ok(wf)
}

/***** TESTS *****/
#[cfg(test)]
mod tests {
    use brane_dsl::ParserOptions;
    use brane_shr::utilities::{create_data_index, create_package_index, test_on_dsl_files};
    use specifications::data::DataIndex;
    use specifications::package::PackageIndex;

    use super::super::print::ast_unresolved;
    use super::*;
    use crate::{CompileResult, CompileStage, compile_snippet_to};


    /// Tests the traversal by generating symbol tables for every file.
    #[test]
    fn test_compile() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Start by the name to always know which file this is
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            // Run up to this traversal
            let mut state: CompileState = CompileState::new();
            let workflow: UnresolvedWorkflow =
                match compile_snippet_to(&mut state, code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Compile) {
                    CompileResult::Unresolved(wf, warns) => {
                        // Print warnings if any
                        for w in warns {
                            w.prettyprint(path.to_string_lossy(), &code);
                        }
                        wf
                    },
                    CompileResult::Eof(err) => {
                        // Print the error
                        err.prettyprint(path.to_string_lossy(), &code);
                        panic!("Failed to compile to workflow (see output above)");
                    },
                    CompileResult::Err(errs) => {
                        // Print the errors
                        for e in errs {
                            e.prettyprint(path.to_string_lossy(), &code);
                        }
                        panic!("Failed to compile to workflow (see output above)");
                    },

                    _ => {
                        unreachable!();
                    },
                };

            // Now print the file for prettyness
            ast_unresolved::do_traversal(&state, workflow, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
