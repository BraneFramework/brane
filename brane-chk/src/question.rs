//  STATE.rs
//    by Lut99
//
//  Created:
//    17 Oct 2024, 16:10:59
//  Last edited:
//    07 Feb 2025, 16:29:43
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the Brane's checker's state.
//

use std::convert::Infallible;

use eflint_json::spec::{ConstructorInput, Expression, ExpressionConstructorApp, ExpressionPrimitive, Phrase, PhraseBooleanQuery};
use policy_reasoner::reasoners::eflint_json::spec::EFlintable;
use policy_reasoner::workflow::Workflow;
use serde::{Deserialize, Serialize};


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
            Self::ValidateWorkflow { workflow } => Ok(vec![Phrase::BooleanQuery(PhraseBooleanQuery {
                expression: Expression::ConstructorApp(ExpressionConstructorApp {
                    identifier: "workflow-to-execute".into(),
                    operands:   ConstructorInput::ArraySyntax(vec![Expression::ConstructorApp(ExpressionConstructorApp {
                        identifier: "workflow".into(),
                        operands:   ConstructorInput::ArraySyntax(vec![Expression::Primitive(ExpressionPrimitive::String(workflow.id.clone()))]),
                    })]),
                }),
            })]),
            Self::ExecuteTask { workflow, task } => Ok(vec![Phrase::BooleanQuery(PhraseBooleanQuery {
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
            })]),
            Self::TransferInput { workflow, task, input } => Ok(vec![Phrase::BooleanQuery(PhraseBooleanQuery {
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
                                operands:   ConstructorInput::ArraySyntax(vec![Expression::Primitive(ExpressionPrimitive::String(input.clone()))]),
                            }),
                        ]),
                    })]),
                }),
            })]),
        }
    }
}
