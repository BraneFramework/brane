//  STATE.rs
//    by Lut99
//
//  Created:
//    17 Oct 2024, 16:10:59
//  Last edited:
//    02 May 2025, 14:59:38
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the Brane's checker's state.
//

use std::fmt::{Formatter, Result as FResult};

use policy_reasoner::reasoners::eflint_haskell::spec::EFlintable;
use policy_reasoner::workflow::{Entity, Workflow};
use serde::{Deserialize, Serialize};

use crate::workflow;


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
    /// Checks if a domain agrees with providing the given result to the end user of the workflow.
    TransferResult {
        /// The workflow that we want to validate.
        workflow: Workflow,
        /// The input to that task that we want to validate.
        result:   String,
    },
}
impl EFlintable for Question {
    #[inline]
    fn eflint_fmt(&self, f: &mut Formatter) -> FResult {
        match self {
            Self::ValidateWorkflow { workflow } => {
                workflow::eflint_fmt(workflow, f)?;
                writeln!(f, "?workflow-to-execute(workflow({:?}))", workflow.id)?;
                Ok(())
            },
            Self::ExecuteTask { workflow, task } => {
                workflow::eflint_fmt(workflow, f)?;
                writeln!(f, "?task-to-execute(task(node(workflow({:?}), {:?})))", workflow.id, task)?;
                Ok(())
            },
            Self::TransferInput { workflow, task, input } => {
                workflow::eflint_fmt(workflow, f)?;
                writeln!(f, "?dataset-to-transfer(node-input(node(workflow({:?}), {:?}), asset({:?})))", workflow.id, task, input)?;
                Ok(())
            },
            Self::TransferResult { workflow, result } => {
                workflow::eflint_fmt(workflow, f)?;
                let user: &Entity = workflow.user.as_ref().unwrap_or_else(|| panic!("Cannot ask for a transfer result without a user in workflow"));
                writeln!(
                    f,
                    "?result-to-transfer(workflow-result-recipient(workflow-result(workflow({:?}), asset({:?})), user({:?})))",
                    workflow.id, result, user.id
                )?;
                Ok(())
            },
        }
    }
}
