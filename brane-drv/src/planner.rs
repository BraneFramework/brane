//  PLANNER.rs
//    by Lut99
//
//  Created:
//    25 Oct 2022, 11:35:00
//  Last edited:
//    14 Nov 2024, 18:08:25
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a planner for the instance use-case.
//


/***** LIBRARY *****/
use brane_tsk::errors::PlanError;
use brane_tsk::spec::{AppId, TaskId};
use log::debug;
use reqwest::{Client, Request, Response, StatusCode};
use serde_json::Value;
use specifications::address::Address;
use specifications::planning::{PlanningDeniedReply, PlanningReply, PlanningRequest};
use specifications::profiling::ProfileScopeHandle;
use specifications::wir::Workflow;


/***** LIBRARY *****/
/// The planner is in charge of assigning locations to tasks in a workflow. This one defers planning to the `brane-plr` service.
pub struct InstancePlanner;
impl InstancePlanner {
    /// Plans the given workflow.
    ///
    /// Will populate the planning timings in the given profile struct if the planner reports them.
    ///
    /// # Arguments
    /// - `plr`: The address of the remote planner to connect to.
    /// - `app_id`: The session ID for this workflow.
    /// - `workflow`: The Workflow to plan.
    /// - `prof`: The ProfileScope that can be used to provide additional information about the timings of the planning (driver-side).
    ///
    /// # Returns
    /// The same workflow as given, but now with all tasks and data transfers planned.
    pub async fn plan(plr: &Address, app_id: AppId, workflow: Workflow, prof: ProfileScopeHandle<'_>) -> Result<Workflow, PlanError> {
        // Generate the ID
        let task_id: String = format!("{}", TaskId::generate());

        // Serialize the workflow
        debug!("Serializing request...");
        let ser = prof.time(format!("workflow {app_id}:{task_id} serialization"));
        let vwf: Value = match serde_json::to_value(&workflow) {
            Ok(vwf) => vwf,
            Err(err) => {
                return Err(PlanError::WorkflowSerialize { id: workflow.id, err });
            },
        };

        // Create a serialized request with it
        let sreq: String = match serde_json::to_string(&PlanningRequest { app_id: app_id.to_string(), workflow: vwf }) {
            Ok(sreq) => sreq,
            Err(err) => {
                return Err(PlanError::PlanningRequestSerialize { id: workflow.id, err });
            },
        };
        ser.stop();

        // Populate a "PlanningRequest" with that (i.e., just populate a future record with the string)
        debug!("Sending request...");
        let remote = prof.time(format!("workflow '{task_id}' on brane-plr"));
        let url: String = format!("{plr}/plan");
        let client: Client = Client::new();
        let req: Request = match client.post(&url).body(sreq).build() {
            Ok(req) => req,
            Err(err) => return Err(PlanError::PlanningRequest { id: workflow.id, url, err }),
        };
        // Send the message
        let res: Response = match client.execute(req).await {
            Ok(res) => res,
            Err(err) => return Err(PlanError::PlanningRequestSend { id: workflow.id, url, err }),
        };
        let status: StatusCode = res.status();
        if status == StatusCode::UNAUTHORIZED {
            // Attempt to parse the response
            let res: String = match res.text().await {
                Ok(res) => res,
                // If errored, default to the other error
                Err(_) => return Err(PlanError::PlanningFailure { id: workflow.id, url, code: status, response: None }),
            };
            let res: PlanningDeniedReply = match serde_json::from_str(&res) {
                Ok(res) => res,
                // If errored, default to the other error
                Err(_) => return Err(PlanError::PlanningFailure { id: workflow.id, url, code: status, response: Some(res) }),
            };

            // Return it
            return Err(PlanError::CheckerDenied { domain: res.domain, reasons: res.reasons });
        } else if !status.is_success() {
            return Err(PlanError::PlanningFailure { id: workflow.id, url, code: status, response: res.text().await.ok() });
        }
        remote.stop();

        // Process the result
        debug!("Receiving response...");
        let post = prof.time(format!("workflow '{task_id}' response processing"));
        let res: String = match res.text().await {
            Ok(res) => res,
            Err(err) => return Err(PlanError::PlanningResponseDownload { id: workflow.id, url, err }),
        };
        let res: PlanningReply = match serde_json::from_str(&res) {
            Ok(res) => res,
            Err(err) => return Err(PlanError::PlanningResponseParse { id: workflow.id, url, raw: res, err }),
        };
        let plan: Workflow = match serde_json::from_value(res.plan.clone()) {
            Ok(res) => res,
            Err(err) => return Err(PlanError::PlanningPlanParse { id: workflow.id, url, raw: res.plan, err }),
        };
        post.stop();

        // Done
        Ok(plan)
    }
}
