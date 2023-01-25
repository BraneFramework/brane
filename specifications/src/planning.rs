//  NETWORK.rs
//    by Lut99
// 
//  Created:
//    28 Sep 2022, 10:33:37
//  Last edited:
//    15 Jan 2023, 16:10:40
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines Kafka network messages used by `brane-drv` <-> `brane-job`
//!   <-> `brane-plr` interaction.
// 

use prost::{Enumeration, Message};


/***** NETWORKING *****/
/// Defines a message that carries an _unplanned_ workflow. It is destined to be intercepted by the planner.
#[derive(Clone, Message)]
pub struct PlanningCommand {
    /// Defines the correlation ID of the workflow to which this planning thing belongs.
    #[prost(tag = "1", string)]
    pub id   : String,
    /// The raw workflow, as JSON, that is sent around. It may be expected that there is usually at least one task that does not have a location annotated.
    #[prost(tag = "2", string)]
    pub workflow : String,
}



/// Defines the current status of planning (and thus also its result).
#[derive(Clone, Copy, Debug, Enumeration)]
pub enum PlanningStatusKind {
    /// A planner has picked up the request.
    Started = 0,

    /// The plan has succeeded
    Success = 1,
    /// Planning has failed due to not being able to find a plan that brings everyone consent.
    Failed  = 2,
    /// Planning has failed because some error has occurred.
    Error   = 3,
}

/// Defines whatever we need to know about the planning result.
#[derive(Clone, Message)]
pub struct PlanningUpdate {
    /// Defines the current state of the planning.
    #[prost(tag = "1", enumeration = "PlanningStatusKind")]
    pub kind : i32,
    /// Defines the correlation ID of the workflow to which this planning thing belongs.
    #[prost(tag = "2", string)]
    pub id   : String,

    /// Defines an additional string that provides additional information. Specifically, if the `kind` is:
    /// - `PlanningStatusKind::Started`, then this _may_ contains the address (or name, or some other identifier) of the planner that started planning the workflow.
    /// - `PlanningStatusKind::Success`, then this contains a Workflow that is guaranteed to have every task annotated with a location.
    /// - `PlanningStatusKind::Failed`, then this _may_ contain some yet-to-be-specified information to help formulating new plans (or with some reason - idk yet).
    /// - `PlanningStatusKind::Error`, then this string describes what went wrong.
    /// For any other value, this field is ignored.
    #[prost(tag = "3", optional, string)]
    pub result : Option<String>,
}





/***** STORAGE *****/
/// Defines a more convienient way of interacting with the last-updated status of a planner.
#[derive(Clone, Debug)]
pub enum PlanningStatus {
    /// Planning has not happened yet.
    None,

    /// Planning has started by the (optionally specified) planner.
    Started(Option<String>),

    /// Planning has completed successfully, and this contains the (unparsed) Workflow result.
    Success(String),
    /// Planning has failed due to no valid plan being possible. A possible reason for failure may be given.
    Failed(Option<String>),
    /// Planning has failed due to a (given) error.
    Error(String),
}
