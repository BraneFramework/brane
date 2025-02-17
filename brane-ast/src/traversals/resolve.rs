//  SYMBOLS.rs
//    by Lut99
//
//  Created:
//    18 Aug 2022, 15:24:54
//  Last edited:
//    12 Dec 2023, 17:13:11
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a traversal that builds symbol tables for the `brane-dsl`
//!   AST.
//

use std::cell::{Ref, RefCell, RefMut};
use std::collections::HashMap;
use std::rc::Rc;

use brane_dsl::ast::{Block, Expr, Identifier, Node, Program, Stmt};
use brane_dsl::data_type::{ClassSignature, FunctionSignature};
use brane_dsl::spec::MergeStrategy;
use brane_dsl::symbol_table::{ClassEntry, FunctionEntry, SymbolTableEntry, VarEntry};
use brane_dsl::{DataType, SymbolTable, TextRange};
use enum_debug::EnumDebug as _;
use log::trace;
use specifications::data::DataIndex;
use specifications::package::{PackageIndex, PackageInfo};
use specifications::version::Version;

use crate::errors::AstError;
pub use crate::errors::ResolveError as Error;
use crate::spec::{BuiltinClasses, BuiltinFunctions};
use crate::state::CompileState;


/***** HELPER FUNCTIONS ******/
/// Defines the arguments of the given FuncDef in the given symbol table.
///
/// # Arguments
/// - `entry`: The FunctionEntry that defines most of the desired FuncDef.
/// - `params`: The Identifiers that define this function's parameters.
/// - `table`: The SymbolTable to define the function's arguments in.
/// - `errors`: A vector to collect any errors in that occur.
///
/// # Returns
/// Nothing, but does generate new entries in the given symbol table and updates the given entry accordingly.
///
/// # Errors
/// This function may error if the given symbol table already existed.
///
/// If such an error occurred, then it is added to the given `errors` list. Some arguments may be undefined in that case.
fn define_func(entry: &mut FunctionEntry, params: &mut [Identifier], symbol_table: &Rc<RefCell<SymbolTable>>, errors: &mut Vec<Error>) {
    // Iterate to add them
    {
        let mut st: RefMut<SymbolTable> = symbol_table.borrow_mut();
        for p in params.iter_mut() {
            match st.add_var(VarEntry::from_param(&p.value, &entry.name, p.range().clone())) {
                Ok(e) => {
                    entry.params.push(e);
                },
                Err(err) => {
                    errors.push(Error::ParameterDefineError { func_name: entry.name.clone(), name: p.value.clone(), err, range: p.range().clone() });
                    continue;
                },
            };
        }
    }

    // Update the argument count in the function's symbol table entry
    entry.signature = FunctionSignature::new(vec![DataType::Any; params.len()], DataType::Any);

    // Done
}





/***** TRAVERSAL FUNCTIONS *****/
/// Attempts to resolve the symbol table for a given block.
///
/// # Arguments
/// - `state`: The CompileState that contains the TextRange offset to apply to all errors and such.
/// - `package_index`: The PackageIndex which we use to resolve external function calls.
/// - `data_index`: The DataIndex which we use to resolve external data assets.
/// - `block`: The Block to traverse.
/// - `parent`: The parent symbol table of the parent scope.
/// - `errors`: A list that we use to keep track of any errors that occur during this pass.
///
/// # Errors
/// This function may error if there were semantic problems while building the table for this statement (if any).
///
/// # Returns
/// Nothing, but does add entries to the symbol table and references them in nodes.
///
/// If an error occurred, then it is appended to the `errors` list and the function returns early.
fn pass_block(
    state: &CompileState,
    package_index: &PackageIndex,
    data_index: &DataIndex,
    block: &mut Block,
    parent: Option<Rc<RefCell<SymbolTable>>>,
    errors: &mut Vec<Error>,
) {
    // Set the parent for this block's symbol table
    {
        let mut st: RefMut<SymbolTable> = block.table.borrow_mut();
        st.parent = parent;
    }

    // Go over the statements and attempt to (further) populate this symbol table
    for s in block.stmts.iter_mut() {
        pass_stmt(state, package_index, data_index, s, &block.table, errors);
    }

    // The table should now be populated for this block
}

/// Attempts to resolve this statement in the given symbol table if it is a function or variable reference.
///
/// If this statement contains a block, that block will be resolved too.
///
/// # Arguments
/// - `state`: The CompileState that contains the TextRange offset to apply to all errors and such.
/// - `package_index`: The PackageIndex which we use to resolve external function calls.
/// - `data_index`: The DataIndex which we use to resolve external data assets.
/// - `stmt`: The Stmt to traverse.
/// - `symbol_table`: The SymbolTable to populate.
/// - `errors`: A list that we use to keep track of any errors that occur during this pass.
///
/// # Returns
/// Nothing, but does add entries to the symbol table and references them in nodes.
///
/// # Errors
/// This function may error if there were semantic problems while building the table for this statement (if any).
///
/// If an error occurred, then it is appended to the `errors` list and the function returns early.
fn pass_stmt(
    state: &CompileState,
    package_index: &PackageIndex,
    data_index: &DataIndex,
    stmt: &mut Stmt,
    symbol_table: &Rc<RefCell<SymbolTable>>,
    errors: &mut Vec<Error>,
) {
    // Match on the exact statement
    use Stmt::*;
    match stmt {
        Block { block } => {
            // Blocks require renewed evaluation
            pass_block(state, package_index, data_index, block, Some(symbol_table.clone()), errors);
        },

        Import { name, version, st_funcs, st_classes, attrs: _, range } => {
            // First: parse the version
            let semver: Version = match version.as_version() {
                Ok(version) => version,
                Err(err) => {
                    errors.push(Error::VersionParseError { err, range: version.range().clone() });
                    return;
                },
            };

            // Attempt to resolve this (name, version) pair in the package index.
            let info: &PackageInfo = match package_index.get(&name.value, if !semver.is_latest() { Some(&semver) } else { None }) {
                Some(info) => info,
                None => {
                    errors.push(Error::UnknownPackageError { name: name.value.clone(), version: semver, range: range.clone() });
                    return;
                },
            };

            // If it did, then we can generate global symbol table entries in this scope for all its functions and types
            let mut st: RefMut<SymbolTable> = symbol_table.borrow_mut();
            let mut funcs = vec![];
            for (name, f) in info.functions.iter() {
                // Collect the types that make the signature for this function.
                let arg_names: Vec<String> = f.parameters.iter().map(|p| p.name.clone()).collect();
                let arg_types: Vec<DataType> = f.parameters.iter().map(|p| DataType::from(&p.data_type)).collect();
                let ret_type: DataType = DataType::from(&f.return_type);

                // Wrap it in a function entry and add it to the list
                match st.add_func(FunctionEntry::from_import(
                    name,
                    FunctionSignature::new(arg_types, ret_type),
                    &info.name,
                    info.version,
                    arg_names,
                    f.requirements.clone().unwrap_or_default(),
                    TextRange::none(),
                )) {
                    Ok(entry) => {
                        funcs.push(entry);
                    },
                    Err(err) => {
                        errors.push(Error::FunctionImportError { package_name: info.name.clone(), name: name.into(), err, range: range.clone() });
                        return;
                    },
                }
            }
            let mut classes = vec![];
            for (name, c) in info.types.iter() {
                // Create a map of property names to types.
                let properties: HashMap<String, DataType> = c.properties.iter().map(|p| (p.name.clone(), DataType::from(&p.data_type))).collect();

                // Construct a symbol table with it
                let c_symbol_table: Rc<RefCell<SymbolTable>> = {
                    let c_symbol_table: Rc<RefCell<SymbolTable>> = SymbolTable::new();
                    {
                        let mut cst: RefMut<SymbolTable> = c_symbol_table.borrow_mut();
                        for p in properties.iter() {
                            match cst.add_var(VarEntry::from_prop(p.0, p.1, name, range.clone())) {
                                Ok(_) => {},
                                Err(err) => {
                                    errors.push(Error::VariableDefineError { name: p.0.clone(), err, range: range.clone() });
                                    return;
                                },
                            }
                        }
                    }
                    c_symbol_table
                };

                // Insert it (plus an empty method map) as a ClassEntry
                match st.add_class(ClassEntry::from_import(
                    ClassSignature { name: name.clone() },
                    c_symbol_table,
                    &info.name,
                    info.version,
                    TextRange::none(),
                )) {
                    Ok(entry) => {
                        classes.push(entry);
                    },
                    Err(err) => {
                        errors.push(Error::ClassImportError { package_name: info.name.clone(), name: name.into(), err, range: range.clone() });
                        return;
                    },
                }
            }

            // As a final thing, update the entry reference in the import itself
            *st_funcs = Some(funcs);
            *st_classes = Some(classes);
        },
        FuncDef { ident, params, code, st_entry, attrs: _, range } => {
            // Prepare the entry
            let mut entry: FunctionEntry = FunctionEntry::from_def(&ident.value, range.clone());
            define_func(&mut entry, params, &code.table, errors);

            // We can then add the function definition to the given symbol table
            {
                let mut st: RefMut<SymbolTable> = symbol_table.borrow_mut();
                match st.add_func(entry) {
                    Ok(entry) => {
                        *st_entry = Some(entry);
                    },
                    Err(err) => {
                        errors.push(Error::FunctionDefineError { name: ident.value.clone(), err, range: ident.range().clone() });
                        return;
                    },
                }
            }

            // Now go and populate the rest of its symbol table in the function body.
            pass_block(state, package_index, data_index, code, Some(symbol_table.clone()), errors);
        },
        ClassDef { ident, props, methods, st_entry, symbol_table: c_symbol_table, attrs: _, range } => {
            // First, we generate the class entry as complete as we can
            // 1. Prepare the class' symbol table
            {
                let mut cst: RefMut<SymbolTable> = c_symbol_table.borrow_mut();

                // Set the correct parent scope
                cst.parent = Some(symbol_table.clone());

                // Add each of the properties in this class
                let st: Ref<SymbolTable> = symbol_table.borrow();
                for p in props.iter_mut() {
                    // Check if the data type exists if it references another class
                    if let DataType::Class(c_name) = &p.data_type {
                        if st.get_class(c_name).is_none() {
                            errors.push(Error::UndefinedClass { ident: c_name.clone(), range: p.range().clone() });
                            return;
                        }
                    }

                    // Generate an entry for it
                    match cst.add_var(VarEntry::from_prop(&p.name.value, &p.data_type, &ident.value, p.range().clone())) {
                        Ok(entry) => {
                            p.st_entry = Some(entry);
                        },
                        Err(err) => {
                            errors.push(Error::VariableDefineError { name: ident.value.clone(), err, range: range.clone() });
                            return;
                        },
                    }
                }

                // Add definitions for each of its functions
                for m in methods.iter_mut() {
                    if let Stmt::FuncDef { ident: m_ident, params: m_params, code: m_code, st_entry: m_st_entry, range: m_range, .. } = &mut **m {
                        // First, check if its name does not overlap with a property (i.e., we want one namespace for a class)
                        if let Some(p) = cst.get_var(&m_ident.value) {
                            errors.push(Error::DuplicateMethodAndProperty {
                                c_name: ident.value.clone(),
                                name: m_ident.value.clone(),
                                new_range: m_ident.range.clone(),
                                existing_range: p.borrow().range.clone(),
                            });
                            return;
                        }

                        // Then, check if it has a 'self' parameter
                        if let Some((i, _)) = m_params.iter().enumerate().find(|(_, p)| &p.value == "self") {
                            if i != 0 {
                                errors.push(Error::IllegalSelf {
                                    c_name: ident.value.clone(),
                                    name:   m_ident.value.clone(),
                                    arg:    i,
                                    range:  m_ident.range.clone(),
                                });
                            }
                        } else {
                            errors.push(Error::MissingSelf {
                                c_name: ident.value.clone(),
                                name:   m_ident.value.clone(),
                                range:  m_ident.range.clone(),
                            });
                        }

                        // If it passes those checks, we create an entry for it
                        let mut entry: FunctionEntry = FunctionEntry::from_method(m_ident.value.clone(), &ident.value, m_range.clone());
                        define_func(&mut entry, m_params, &m_code.table, errors);
                        m_code.table.borrow_mut().parent = Some(symbol_table.clone());

                        // Add it to the class' table
                        match cst.add_func(entry) {
                            Ok(entry) => {
                                *m_st_entry = Some(entry);
                            },
                            Err(err) => {
                                errors.push(Error::FunctionDefineError { name: m_ident.value.clone(), err, range: m_range.clone() });
                                return;
                            },
                        }
                    } else {
                        panic!("Class method stmt is not a FuncDef");
                    }
                }
            }

            // 2. Create a proper class entry with that table
            {
                let mut st: RefMut<SymbolTable> = symbol_table.borrow_mut();
                match st.add_class(ClassEntry::from_def(ClassSignature::new(&ident.value), c_symbol_table.clone(), range.clone())) {
                    Ok(entry) => {
                        *st_entry = Some(entry);
                    },
                    Err(err) => {
                        errors.push(Error::ClassDefineError { name: ident.value.clone(), err, range: range.clone() });
                        return;
                    },
                }
            }

            // 3. Recurse into the function bodies to resolve there
            for m in methods.iter_mut() {
                if let Stmt::FuncDef { code: m_code, .. } = &mut **m {
                    for s in &mut m_code.stmts {
                        pass_stmt(state, package_index, data_index, s, &m_code.table, errors);
                    }
                } else {
                    unreachable!();
                }
            }

            // Done; we added a full class entry and recursed
        },
        Return { expr, data_type: _, output: _, attrs: _, range: _ } => {
            // Traverse the expression to resolve any references (by the time we reach it, the symbol table should already be sufficiently populated)
            if let Some(expr) = expr {
                pass_expr(state, data_index, expr, symbol_table, errors);
            }
        },

        If { cond, consequent, alternative, attrs: _, range: _ } => {
            // Recurse into the condition
            pass_expr(state, data_index, cond, symbol_table, errors);

            // Recurse into the codeblocks
            pass_block(state, package_index, data_index, consequent, Some(symbol_table.clone()), errors);
            if let Some(alternative) = alternative {
                pass_block(state, package_index, data_index, alternative, Some(symbol_table.clone()), errors);
            }
        },
        For { initializer, condition, increment, consequent, attrs: _, range: _ } => {
            // Set the parent for the nested block's symbol table
            {
                let mut st: RefMut<SymbolTable> = consequent.table.borrow_mut();
                st.parent = Some(symbol_table.clone());
            }

            // Recurse into the three for-parts first
            pass_stmt(state, package_index, data_index, initializer, &consequent.table, errors);
            pass_expr(state, data_index, condition, &consequent.table, errors);
            pass_stmt(state, package_index, data_index, increment, &consequent.table, errors);

            // Recurse into the block
            for s in consequent.stmts.iter_mut() {
                pass_stmt(state, package_index, data_index, s, &consequent.table, errors);
            }
        },
        While { condition, consequent, attrs: _, range: _ } => {
            // Recurse into the while-part first
            pass_expr(state, data_index, condition, symbol_table, errors);
            // Recurse into the block
            pass_block(state, package_index, data_index, consequent, Some(symbol_table.clone()), errors);
        },
        Parallel { result, blocks, merge, st_entry, attrs: _, range } => {
            // First, very silly, but double-check the merge is parseable
            if let Some(merge) = merge {
                if let MergeStrategy::None = MergeStrategy::from(&merge.value) {
                    errors.push(Error::UnknownMergeStrategy { raw: merge.value.clone(), range: merge.range.clone() });
                }
            }

            // Now recurse into the codeblocks to resolve their references too
            for b in blocks {
                pass_block(state, package_index, data_index, b, Some(symbol_table.clone()), errors);
            }

            // If present, declare the result as last
            if let Some(result) = result {
                // Attempt to declare the identifier
                let mut st: RefMut<SymbolTable> = symbol_table.borrow_mut();
                match st.add_var(VarEntry::from_def(&result.value, range.clone())) {
                    Ok(entry) => {
                        *st_entry = Some(entry);
                    },
                    Err(err) => {
                        errors.push(Error::VariableDefineError { name: result.value.clone(), err, range: result.range().clone() });
                    },
                }
            }
        },

        LetAssign { name, value, st_entry, attrs: _, range } => {
            // Recursestate,  into the expression to resolve any reference there
            pass_expr(state, data_index, value, symbol_table, errors);

            // Attempt to declare the identifier
            let mut st: RefMut<SymbolTable> = symbol_table.borrow_mut();
            match st.add_var(VarEntry::from_def(&name.value, range.clone())) {
                Ok(entry) => {
                    *st_entry = Some(entry);
                },
                Err(err) => {
                    errors.push(Error::VariableDefineError { name: name.value.clone(), err, range: name.range().clone() });
                },
            }
        },
        Assign { name, value, st_entry, attrs: _, range: _ } => {
            // Recurse into the expression to resolve any reference there
            pass_expr(state, data_index, value, symbol_table, errors);

            // Attempt to resolve the identifier
            let st: Ref<SymbolTable> = symbol_table.borrow();
            match st.get_var(&name.value) {
                Some(entry) => {
                    *st_entry = Some(entry);
                },
                None => {
                    errors.push(Error::UndefinedVariable { ident: name.value.clone(), range: name.range().clone() });
                },
            }
        },
        Expr { expr, data_type: _, attrs: _, range: _ } => {
            // Simply recurse
            pass_expr(state, data_index, expr, symbol_table, errors);
        },

        // We ignore the rest
        Empty {} => {},
        Attribute(_) | AttributeInner(_) => panic!("Encountered {:?} in resolve traversal", stmt.variant()),
    }

    // We're done here
}

/// Attempts to resolve this expression by linking variable (or other) references to already defined values in the given symbol table and its parents.
///
/// # Arguments
/// - `state`: The CompileState that contains the TextRange offset to apply to all errors and such.
/// - `data_index`: The DataIndex which we use to resolve external data assets.
/// - `expr`: The Expr to traverse.
/// - `symbol_table`: The SymbolTable to check reference in.
/// - `errors`: A list that we use to keep track of any errors that occur during this pass.
///
/// # Returns
/// Nothing, but does reference symbol table entries in nodes.
///
/// # Errors
/// This function may error if there were semantic problems while checking the table for this statement (if any).
///
/// If an error occurred, then it is appended to the `errors` list and the function returns early.
fn pass_expr(state: &CompileState, data_index: &DataIndex, expr: &mut Expr, symbol_table: &Rc<RefCell<SymbolTable>>, errors: &mut Vec<Error>) {
    // Match on the exact expression
    use Expr::*;
    match expr {
        Cast { expr, target: _, range: _ } => {
            pass_expr(state, data_index, expr, symbol_table, errors);
        },

        Call { expr, args, st_entry: _, locations: _, input: _, result: _, metadata: _, range: _ } => {
            // Simply recurse the called expression
            pass_expr(state, data_index, expr, symbol_table, errors);
            // If it's an identifier, set its entry to which function it is referring
            if let brane_dsl::ast::Expr::Identifier { name, st_entry, .. } = &mut **expr {
                // Search the name
                let st: Ref<SymbolTable> = symbol_table.borrow();
                match st.get_func(&name.value) {
                    Some(entry) => {
                        *st_entry = Some(entry);
                    },
                    None => {
                        errors.push(Error::UndefinedFunction { ident: name.value.clone(), range: name.range.clone() });
                        return;
                    },
                }

                // Assertion that is at the incorrect place but jeeeeeez this sucks to place anywhere; if this is a commit, is the name a literal string?
                if name.value == BuiltinFunctions::CommitResult.name() {
                    if let Some(first_arg) = args.iter().next() {
                        if !matches!(&**first_arg, Expr::Literal { literal: brane_dsl::ast::Literal::String { .. } }) {
                            errors.push(Error::CommitResultIncorrectExpr { range: first_arg.range().clone() });
                        }
                    }
                }
            }

            // Then do the arguments
            for a in args {
                pass_expr(state, data_index, a, symbol_table, errors);
            }
        },
        Array { values, data_type: _, range: _ } => {
            // Simply recurse
            for v in values {
                pass_expr(state, data_index, v, symbol_table, errors);
            }
        },
        ArrayIndex { array, index, data_type: _, range: _ } => {
            // Simply recurse
            pass_expr(state, data_index, array, symbol_table, errors);
            pass_expr(state, data_index, index, symbol_table, errors);
        },
        Pattern { exprs, range: _ } => {
            // Simply recurse
            for e in exprs {
                pass_expr(state, data_index, e, symbol_table, errors);
            }
        },

        UnaOp { op: _, expr, range: _ } => {
            // Simply recurse
            pass_expr(state, data_index, expr, symbol_table, errors);
        },
        BinOp { op: _, lhs, rhs, range: _ } => {
            // Simply recurse
            pass_expr(state, data_index, lhs, symbol_table, errors);
            pass_expr(state, data_index, rhs, symbol_table, errors);
        },
        Proj { lhs, rhs, st_entry, range: _ } => {
            // By design, the lhs is only Expr::VarRef or Expr::Proj
            // The rhs is only Expr::Identifier

            // Recurse into the left-hand side first
            pass_expr(state, data_index, lhs, symbol_table, errors);
            // Then the righthand-side (not necessary, but just in case we ever do need recursion for identifiers)
            pass_expr(state, data_index, rhs, symbol_table, errors);

            // Get the rhs identifier
            let rhs_ident: &brane_dsl::ast::Identifier = if let Expr::Identifier { name, .. } = &**rhs {
                name
            } else {
                panic!("Encountered non-Identifier expression on righthand-side of projection expression");
            };

            // With the type evaluated, get the symbol table that contains the class' fields referenced by the LHS
            let (var_name, c_entry): (String, Rc<RefCell<ClassEntry>>) = {
                // Get a borrow to the underlying variable entry first
                let var_entry: Rc<RefCell<VarEntry>> = match &**lhs {
                    Expr::Proj { st_entry, .. } => {
                        // Get the class symbol table as simply the parent table of the variable entry
                        if let Some(entry) = st_entry.as_ref() {
                            match entry {
                                SymbolTableEntry::VarEntry(v) => v.clone(),
                                SymbolTableEntry::FunctionEntry(f) => {
                                    let entry: Ref<FunctionEntry> = f.borrow();
                                    errors.push(Error::NonClassProjection {
                                        name:  rhs_ident.value.clone(),
                                        got:   DataType::Function(Box::new(entry.signature.clone())),
                                        range: lhs.range().clone(),
                                    });
                                    return;
                                },
                                _ => {
                                    panic!("Got non-Var, non-Method SymbolTableEntry in a projection");
                                },
                            }
                        } else {
                            // Otherwise, the LHS was not resolveable at this moment; try again later
                            trace!("Projection LHS not yet resolvable");
                            return;
                        }
                    },
                    Expr::VarRef { name, st_entry, .. } => {
                        // If the VarRef is not given, then something went wrong (e.g., unknown argument)
                        if st_entry.is_none() {
                            trace!("No entry set for '{}'", name.value);
                            return;
                        }

                        // Always a variable entry
                        trace!(
                            "Entry set for '{}' (pointing to '{}' ({}))",
                            name.value,
                            st_entry.as_ref().unwrap().borrow().name,
                            st_entry.as_ref().unwrap().borrow().data_type
                        );
                        st_entry.as_ref().unwrap().clone()
                    },

                    _ => {
                        panic!("Got non-Proj, non-VarRef expression on lefthand-side of projection expression");
                    },
                };

                // Get the type behind that entry as a ClassType
                let entry: Ref<VarEntry> = var_entry.borrow();
                let c_name: &str = match &entry.data_type {
                    DataType::Class(c_name) => c_name,
                    // For Any, we have no choice but to assume it's fine and leave it until runtime
                    DataType::Any => {
                        return;
                    },
                    entry_type => {
                        errors.push(Error::NonClassProjection {
                            name:  rhs_ident.value.clone(),
                            got:   entry_type.clone(),
                            range: lhs.range().clone(),
                        });
                        return;
                    },
                };

                // Attempt to resolve that name in the symbol table
                let st: Ref<SymbolTable> = symbol_table.borrow();
                (entry.name.clone(), st.get_class(c_name).unwrap())
            };

            // After that whole ordeal, we can now see if the rhs identifier is actually a field in the class
            let ce: Ref<ClassEntry> = c_entry.borrow();
            let cst: Ref<SymbolTable> = ce.symbol_table.borrow();
            if let Some(f_entry) = cst.get(&rhs_ident.value) {
                // It's a field! Link the projection operator to it.
                trace!("Projection of {} onto {} points to class {}", rhs_ident.value, var_name, match &f_entry {
                    SymbolTableEntry::FunctionEntry(f) => format!("method '{}'", f.borrow().name),
                    SymbolTableEntry::ClassEntry(c) => format!("class '{}'", c.borrow().signature.name),
                    SymbolTableEntry::VarEntry(v) => format!("property '{}' ({})", v.borrow().name, v.borrow().data_type),
                });
                *st_entry = Some(f_entry);
            } else {
                errors.push(Error::UnknownField {
                    class_name: ce.signature.name.clone(),
                    name: rhs_ident.value.clone(),
                    range: rhs_ident.range.clone(),
                });
            }
        },

        Instance { name, properties, st_entry, range: _ } => {
            // First, attempt to resolve the class name
            {
                let st: Ref<SymbolTable> = symbol_table.borrow();
                match st.get_class(&name.value) {
                    Some(entry) => {
                        *st_entry = Some(entry);
                    },
                    None => {
                        errors.push(Error::UndefinedClass { ident: name.value.clone(), range: name.range().clone() });
                        return;
                    },
                }
            }

            // Next, iterate over the properties to resolve those expressions
            let entry: Ref<ClassEntry> = st_entry.as_ref().unwrap().borrow();
            for p in properties.iter_mut() {
                // But first, double-check this property is actually present in the type (since this type resolving does not require extra type checking)
                if entry.symbol_table.borrow().get_var(&p.name.value).is_none() {
                    errors.push(Error::UnknownField { class_name: name.value.clone(), name: p.name.value.clone(), range: p.name.range().clone() });
                    return;
                }

                // Now traverse
                pass_expr(state, data_index, &mut p.value, symbol_table, errors);
            }

            // Finally, check if this dataset exists
            if entry.signature.name == BuiltinClasses::Data.name() {
                // Get the identifier stored within
                let name: &Expr = properties
                    .iter()
                    .find_map(|p| if &p.name.value == "name" { Some(&p.value) } else { None })
                    .expect("Builtin class Data has no field 'name' (seems like that's not been properly updated)");
                let sname: &str = match name {
                    Literal { literal: brane_dsl::ast::Literal::String { value, .. } } => value,
                    name => {
                        errors.push(Error::DataIncorrectExpr { range: name.range().clone() });
                        return;
                    },
                };

                // Attempt to find it in the data index
                // let info: &DataInfo = match data_index.get(sname) {
                //     Some(info) => info,
                //     None       => {
                //         errors.push(Error::UnknownDataError{ name: sname.into(), range: name.range().clone() });
                //         return;
                //     }
                // };
                if data_index.get(sname).is_none() {
                    errors.push(Error::UnknownDataError { name: sname.into(), range: name.range().clone() });
                }

                // With the dataset resolved, we rest easy
            }
        },
        Identifier { name, st_entry: _ } => {
            // Update the expr's range
            name.range.start.line += state.offset;
            name.range.end.line += state.offset;
        },
        VarRef { name, st_entry } => {
            // Update the expr's range
            name.range.start.line += state.offset;
            name.range.end.line += state.offset;

            // Resolve the variable reference as a classic, well, variable
            let st: Ref<SymbolTable> = symbol_table.borrow();
            match st.get_var(&name.value) {
                Some(entry) => {
                    *st_entry = Some(entry);
                },
                None => {
                    errors.push(Error::UndefinedVariable { ident: name.value.clone(), range: name.range.clone() });
                },
            }
        },

        // The rest is irrelevant for resolving the symbol tables
        Literal { literal: _ } | Empty {} => {},
    }

    // We're done here
}





/***** LIBRARY *****/
/// Builds symbol tables for the given `brane-dsl` AST.
///
/// This effectively resolves variable references.
///
/// # Arguments
/// - `state`: The CompileState that we can use to remember definitions in between runs.
/// - `package_index`: The PackageIndex which we use to resolve external function calls.
/// - `data_index`: The DataIndex which we use to resolve external data assets.
/// - `root`: The root node of the tree on which this compiler pass will be done.
///
/// # Returns
/// The same nodes as went in, but now with non-empty symbol tables.
///
/// # Errors
/// TThis pass may throw `AstError::ResolveError`s if the user made mistakes with their variable references.
pub fn do_traversal(state: &mut CompileState, package_index: &PackageIndex, data_index: &DataIndex, root: Program) -> Result<Program, Vec<AstError>> {
    let mut root = root;

    // Inject the state into the global symbol table
    {
        let mut st: RefMut<SymbolTable> = root.block.table.borrow_mut();
        state.table.inject(&mut st);
    }

    // Iterate over all statements to build their symbol tables (if relevant)
    let mut errors: Vec<Error> = vec![];
    pass_block(state, package_index, data_index, &mut root.block, None, &mut errors);

    // Done
    if errors.is_empty() { Ok(root) } else { Err(errors.into_iter().map(AstError::from).collect()) }
}


/***** TESTS *****/
#[cfg(test)]
pub mod tests {
    use brane_dsl::ParserOptions;
    use brane_shr::utilities::{create_data_index, create_package_index, test_on_dsl_files};
    use specifications::package::PackageIndex;

    use super::super::print::symbol_tables;
    use super::*;
    use crate::{CompileResult, CompileStage, compile_program_to};


    /// Tests the traversal by generating symbol tables for every file.
    #[test]
    fn test_resolve() {
        test_on_dsl_files("BraneScript", |path, code| {
            // Always print the header
            println!("{}", (0..80).map(|_| '-').collect::<String>());
            println!("File '{}' gave us:", path.display());

            // Load the package index
            let pindex: PackageIndex = create_package_index();
            let dindex: DataIndex = create_data_index();

            // Run up to this traversal
            let program: Program = match compile_program_to(code.as_bytes(), &pindex, &dindex, &ParserOptions::bscript(), CompileStage::Resolve) {
                CompileResult::Program(p, warns) => {
                    // Print warnings if any
                    for w in warns {
                        w.prettyprint(path.to_string_lossy(), &code);
                    }
                    p
                },
                CompileResult::Eof(err) => {
                    // Print the error
                    err.prettyprint(path.to_string_lossy(), &code);
                    panic!("Failed to resolve symbol tables (see output above)");
                },
                CompileResult::Err(errs) => {
                    // Print the errors
                    for e in errs {
                        e.prettyprint(path.to_string_lossy(), &code);
                    }
                    panic!("Failed to resolve symbol tables (see output above)");
                },

                _ => {
                    unreachable!();
                },
            };

            // Now print the symbol tables for prettyness
            symbol_tables::do_traversal(program, std::io::stdout()).unwrap();
            println!("{}\n\n", (0..80).map(|_| '-').collect::<String>());
        });
    }
}
