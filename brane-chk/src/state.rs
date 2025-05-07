//  STATE.rs
//    by Lut99
//
//  Created:
//    17 Oct 2024, 16:10:59
//  Last edited:
//    17 Oct 2024, 16:26:51
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the Brane's checker's state.
//

use std::collections::HashMap;

use policy_reasoner::workflow::Entity;


/***** LIBRARY *****/
/// Defines the state (=request independent input) for the Brane reasoner.
#[derive(Clone, Debug)]
pub struct State {
    /// A list of where datasets mentioned in a workflow are currently residing.
    pub datasets: HashMap<String, Entity>,
}



/// Defines the question (=request specific input) for the Brane reasoner.
#[derive(Clone, Copy, Debug)]
pub enum Question {
    /// Checks if this domain agrees with the workflow as a whole.
    ValidateWorkflow,
    /// Checks if this domain agrees with executing the given task in the given workflow.
    ExecuteTask,
    /// Checks if this domain agrees with providing the given input to the given task in the given workflow.
    TransferInput,
}
