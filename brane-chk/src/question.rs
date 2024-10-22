//  STATE.rs
//    by Lut99
//
//  Created:
//    17 Oct 2024, 16:10:59
//  Last edited:
//    22 Oct 2024, 11:52:38
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the Brane's checker's state.
//

use std::convert::Infallible;

use policy_reasoner::reasoners::eflint_json::spec::EFlintable;
use policy_reasoner::workflow::Workflow;


/***** LIBRARY *****/
/// Defines the question (=request specific input) for the Brane reasoner.
#[derive(Clone, Debug)]
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
    fn to_eflint(&self) -> Result<Vec<eflint_json::spec::Phrase>, Self::Error> { todo!() }
}
