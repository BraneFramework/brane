//  PLANNER.rs
//    by Lut99
//
//  Created:
//    25 Oct 2022, 11:35:00
//  Last edited:
//    29 Apr 2025, 14:00:54
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
        let vwf: Value = serde_json::to_value(&workflow).map_err(|source| PlanError::WorkflowSerialize { id: workflow.id.clone(), source })?;

        // Create a serialized request with it
        let sreq: String = serde_json::to_string(&PlanningRequest { app_id: app_id.to_string(), workflow: vwf })
            .map_err(|source| PlanError::PlanningRequestSerialize { id: workflow.id.clone(), source })?;
        ser.stop();

        // Populate a "PlanningRequest" with that (i.e., just populate a future record with the string)
        debug!("Sending request...");
        let remote = prof.time(format!("workflow '{task_id}' on brane-plr"));
        let url: String = format!("http://{plr}/plan");
        let client: Client = Client::new();
        let req: Request = client.post(&url).body(sreq).build().map_err(|source| PlanError::PlanningRequest {
            id: workflow.id.clone(),
            url: url.clone(),
            source,
        })?;
        // Send the message
        let res: Response =
            client.execute(req).await.map_err(|source| PlanError::PlanningRequestSend { id: workflow.id.clone(), url: url.clone(), source })?;
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
            return Err(PlanError::PlanningFailure { id: workflow.id, url: url.clone(), code: status, response: res.text().await.ok() });
        }
        remote.stop();

        // Process the result
        debug!("Receiving response...");
        let post = prof.time(format!("workflow '{task_id}' response processing"));
        let res: String =
            res.text().await.map_err(|source| PlanError::PlanningResponseDownload { id: workflow.id.clone(), url: url.clone(), source })?;
        let res: PlanningReply = serde_json::from_str(&res).map_err(|source| PlanError::PlanningResponseParse {
            id: workflow.id.clone(),
            url: url.clone(),
            raw: res,
            source,
        })?;
        let plan: Workflow = serde_json::from_value(res.plan.clone()).map_err(|source| PlanError::PlanningPlanParse {
            id: workflow.id.clone(),
            url: url.clone(),
            raw: res.plan,
            source,
        })?;
        post.stop();

        // Done
        Ok(plan)
    }
}
