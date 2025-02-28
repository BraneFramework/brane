//  STATE.rs
//    by Lut99
//
//  Created:
//    17 Oct 2024, 16:10:59
//  Last edited:
//    27 Feb 2025, 17:33:08
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the Brane's checker's state.
//

use std::convert::Infallible;

use eflint_json::spec::{ConstructorInput, Expression, ExpressionConstructorApp, ExpressionPrimitive, Phrase, PhraseBooleanQuery, PhraseCreate};
use policy_reasoner::reasoners::eflint_json::spec::EFlintable;
use policy_reasoner::workflow::{Elem, ElemBranch, ElemCall, ElemLoop, ElemParallel, Workflow};
use serde::{Deserialize, Serialize};


/***** HELPER MACROS *****/
/// Shortcut for creating an eFLINT JSON Specification [`Phrase::Create`].
///
/// # Arguments
/// - `inst`: A single eFLINT [`Expression`] that is an instance expression determining what to create; i.e., `foo(Amy, Bob)` in `+foo(Amy, Bob).`.
///
/// # Returns
/// A new [`Phrase::Create`] (or rather, the Rust code to create it).
macro_rules! create {
    ($inst:expr) => {
        Phrase::Create(PhraseCreate { operand: $inst })
    };
}

/// Shortcut for creating an eFLINT JSON Specification [`Expression::ConstructorApp`].
///
/// # Arguments
/// - _array syntax_
///   - `id`: The (string) identifier of the relation to construct; i.e., `foo` in `foo(Amy, Bob)`.
///   - `args...`: Zero or more addinitional [`Expression`]s that make up the arguments of the constructor application; i.e., `Amy` or `Bob` in `foo(Amy, Bob)`.
///
/// # Returns
/// A new [`Expression::ConstructorApp`] (or rather, the Rust code to create it).
macro_rules! constr_app {
    ($id:expr $(, $args:expr)* $(,)?) => {
        Expression::ConstructorApp(ExpressionConstructorApp {
            identifier: ($id).into(),
            operands:   ConstructorInput::ArraySyntax(vec![ $($args),* ]),
        })
    };
}

/// Shortcut for creating an eFLINT JSON Specification [`Expression::Primitive(ExpressionPrimitive::String)`].
///
/// # Arguments
/// - `val`: The string value to put in the string primitive. Note that this is automatically `into()`d; so passing a `&str` will work, for example.
///
/// # Returns
/// A new [`Expression::Primitive(ExpressionPrimitive::String)`] (or rather, the Rust code to create it).
macro_rules! str_lit {
    ($val:expr) => {
        Expression::Primitive(ExpressionPrimitive::String(($val).into()))
    };
}





/***** HELPER FUNCTIONS *****/
/// Serializes a workflow to a bunch of eFLINT phrases.
///
/// # Arguments
/// - `workflow`: The [`Workflow`] to serialize.
/// - `phrases`: The list of phrases to compile to.
fn workflow_to_eflint(wf: &Workflow, phrases: &mut Vec<Phrase>) {
    let mut users: Vec<String> = Vec::new();

    // Make the workflow itself known
    // +workflow(#wf.id)
    let workflow: Expression = constr_app!("workflow", str_lit!(wf.id.clone()));
    phrases.push(create!(workflow.clone()));

    // Done
}



/// Serializes a element to a bunch of eFLINT phrases.
///
/// # Arguments
/// - `workflow`: A representation of `workflow(#id)` in eFLINT.
/// - `elem`: An [`Elem`] to serialize.
/// - `phrases`: The list of phrases to compile to.
fn elem_to_eflint(workflow: &Expression, elem: &Elem, phrases: &mut Vec<Phrase>) {
    match elem {
        Elem::Branch(b) => elem_branch_to_eflint(workflow, b, phrases),
        Elem::Call(c) => elem_call_to_eflint(workflow, c, phrases),
        Elem::Loop(l) => elem_loop_to_eflint(workflow, l, phrases),
        Elem::Parallel(p) => elem_parallel_to_eflint(workflow, p, phrases),
        Elem::Next => return,
        Elem::Stop => return,
    }
}

/// Serializes a branch to a bunch of eFLINT phrases.
///
/// # Arguments
/// - `workflow`: A representation of `workflow(#id)` in eFLINT.
/// - `elem`: An [`ElemBranch`] to serialize.
/// - `phrases`: The list of phrases to compile to.
fn elem_branch_to_eflint(workflow: &Expression, elem: &ElemBranch, phrases: &mut Vec<Phrase>) {
    for e in &elem.branches {
        elem_to_eflint(workflow, e, phrases);
    }
    elem_to_eflint(workflow, &elem.next, phrases);
}

/// Serializes a call to a bunch eFLINT phrases.
///
/// # Arguments
/// - `workflow`: A representation of `workflow(#id)` in eFLINT.
/// - `elem`: An [`ElemCall`] to serialize.
/// - `phrases`: The list of phrases to compile to.
fn elem_call_to_eflint(workflow: &Expression, elem: &ElemCall, assets: &mut Vec<Expression>, phrases: &mut Vec<Phrase>) {
    // Declare the node
    // +node(workflow(#wf.id), #node.id)
    phrases.push(create!(constr_app!("node", workflow.clone(), str_lit!(&elem.id))));

    // Declare all the node's inputs
    for input in &elem.input {
        // The input itself
        let asset = constr_app!("asset", str_lit!(&input.id));
    }
}

/// Serializes a loop to a bunch of eFLINT phrases.
///
/// # Arguments
/// - `workflow`: A representation of `workflow(#id)` in eFLINT.
/// - `elem`: An [`ElemLoop`] to serialize.
/// - `phrases`: The list of phrases to compile to.
fn elem_loop_to_eflint(workflow: &Expression, elem: &ElemLoop, phrases: &mut Vec<Phrase>) { todo!() }

/// Serializes a parallel to a bunch of eFLINT phrases.
///
/// # Arguments
/// - `workflow`: A representation of `workflow(#id)` in eFLINT.
/// - `elem`: An [`ElemParallel`] to serialize.
/// - `phrases`: The list of phrases to compile to.
fn elem_parallel_to_eflint(workflow: &Expression, elem: &ElemParallel, phrases: &mut Vec<Phrase>) {
    for e in &elem.branches {
        elem_to_eflint(workflow, e, phrases);
    }
    elem_to_eflint(workflow, &elem.next, phrases);
}





/***** LIBRARY *****/
/// Defines the question (=request specific input) for the Brane reasoner.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Question {
    /// Checks if this domain agrees with the workflow as a whole.
    ValidateWorkflow {
        /// The workflow that we want to validate.
        workflow: Workflow,
    },
    /// Checks if this domain agrees with executing the given task in the given workflow.
    ExecuteTask {
        /// The workflow that we want to validate.
        workflow: Workflow,
        /// The task that we specifically want to validate within that workflow.
        task:     String,
    },
    /// Checks if this domain agrees with providing the given input to the given task in the given workflow.
    TransferInput {
        /// The workflow that we want to validate.
        workflow: Workflow,
        /// The task that we specifically want to validate within that workflow.
        task:     String,
        /// The input to that task that we want to validate.
        input:    String,
    },
}
impl EFlintable for Question {
    type Error = Infallible;

    #[inline]
    fn to_eflint(&self) -> Result<Vec<Phrase>, Self::Error> {
        match self {
            Self::ValidateWorkflow { workflow } => {
                let mut phrases = workflow_to_eflint(workflow);
                phrases.push(Phrase::BooleanQuery(PhraseBooleanQuery {
                    expression: Expression::ConstructorApp(ExpressionConstructorApp {
                        identifier: "workflow-to-execute".into(),
                        operands:   ConstructorInput::ArraySyntax(vec![Expression::ConstructorApp(ExpressionConstructorApp {
                            identifier: "workflow".into(),
                            operands:   ConstructorInput::ArraySyntax(vec![Expression::Primitive(ExpressionPrimitive::String(workflow.id.clone()))]),
                        })]),
                    }),
                }));
                Ok(phrases)
            },
            Self::ExecuteTask { workflow, task } => {
                let mut phrases = workflow_to_eflint(workflow);
                phrases.push(Phrase::BooleanQuery(PhraseBooleanQuery {
                    expression: Expression::ConstructorApp(ExpressionConstructorApp {
                        identifier: "task-to-execute".into(),
                        operands:   ConstructorInput::ArraySyntax(vec![Expression::ConstructorApp(ExpressionConstructorApp {
                            identifier: "task".into(),
                            operands:   ConstructorInput::ArraySyntax(vec![Expression::ConstructorApp(ExpressionConstructorApp {
                                identifier: "node".into(),
                                operands:   ConstructorInput::ArraySyntax(vec![
                                    Expression::ConstructorApp(ExpressionConstructorApp {
                                        identifier: "workflow".into(),
                                        operands:   ConstructorInput::ArraySyntax(vec![Expression::Primitive(ExpressionPrimitive::String(
                                            workflow.id.clone(),
                                        ))]),
                                    }),
                                    Expression::Primitive(ExpressionPrimitive::String(task.clone())),
                                ]),
                            })]),
                        })]),
                    }),
                }));
                Ok(phrases)
            },
            Self::TransferInput { workflow, task, input } => {
                let mut phrases = workflow_to_eflint(workflow);
                phrases.push(Phrase::BooleanQuery(PhraseBooleanQuery {
                    expression: Expression::ConstructorApp(ExpressionConstructorApp {
                        identifier: "dataset-to-transfer".into(),
                        operands:   ConstructorInput::ArraySyntax(vec![Expression::ConstructorApp(ExpressionConstructorApp {
                            identifier: "node-input".into(),
                            operands:   ConstructorInput::ArraySyntax(vec![
                                Expression::ConstructorApp(ExpressionConstructorApp {
                                    identifier: "node".into(),
                                    operands:   ConstructorInput::ArraySyntax(vec![
                                        Expression::ConstructorApp(ExpressionConstructorApp {
                                            identifier: "workflow".into(),
                                            operands:   ConstructorInput::ArraySyntax(vec![Expression::Primitive(ExpressionPrimitive::String(
                                                workflow.id.clone(),
                                            ))]),
                                        }),
                                        Expression::Primitive(ExpressionPrimitive::String(task.clone())),
                                    ]),
                                }),
                                Expression::ConstructorApp(ExpressionConstructorApp {
                                    identifier: "asset".into(),
                                    operands:   ConstructorInput::ArraySyntax(vec![Expression::Primitive(ExpressionPrimitive::String(
                                        input.clone(),
                                    ))]),
                                }),
                            ]),
                        })]),
                    }),
                }));
                Ok(phrases)
            },
        }
    }
}
