//  PLANNER.rs
//    by Lut99
// 
//  Created:
//    25 Oct 2022, 11:35:00
//  Last edited:
//    28 Feb 2023, 16:38:29
//  Auto updated?
//    Yes
// 
//  Description:
//!   Implements a planner for the instance use-case.
// 


/***** LIBRARY *****/
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime};

use dashmap::DashMap;
use futures_util::TryStreamExt;
use log::{debug, error};
use prost::Message as _;
use rdkafka::{ClientConfig, Message};
use rdkafka::consumer::stream_consumer::StreamConsumer;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;

use brane_ast::Workflow;
use brane_cfg::node::CentralConfig;
use brane_shr::kafka::{ensure_topics, restore_committed_offsets};
use brane_tsk::errors::PlanError;
use brane_tsk::spec::TaskId;
use specifications::planning::{PlanningStatus, PlanningStatusKind, PlanningUpdate};
use specifications::profiling::ProfileScopeHandle;


/***** CONSTANTS *****/
/// Defines the default timeout for the initial planning feedback (in ms)
const DEFAULT_PLANNING_STARTED_TIMEOUT: u128 = 30 * 1000;





/***** FUTURES *****/
/// Waits until the given plan has been planned.
struct WaitUntilPlanned {
    /// The correlation ID of the plan we're waiting for.
    correlation_id : String,
    /// The event-monitor updated list of states we use to check the plan's status.
    updates        : Arc<DashMap<String, PlanningStatus>>,
    /// The waker used by the event monitor.
    waker          : Arc<Mutex<Option<Waker>>>,

    /// Whether or not planning has started.
    started       : bool,
    /// The timeout to wait until the planning should have started.
    timeout       : u128,
    /// The time since the last check.
    timeout_start : SystemTime,
}

impl Future for WaitUntilPlanned {
    type Output = Option<PlanningStatus>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // If not started yet, possibly timeout
        if !self.started {
            // Compute the elapsed time
            let elapsed = match SystemTime::now().duration_since(self.timeout_start) {
                Ok(elapsed) => elapsed,
                Err(err)    => { panic!("The time since we started planning is later than the current time (by {:?}); this should never happen!", err.duration()); }
            };

            // Timeout if the time has passed
            if elapsed.as_millis() >= self.timeout {
                debug!("Workflow '{}' has timed out", self.correlation_id);
                return Poll::Ready(None);
            }
        }

        // Otherwise, if not timed out, switch on the state
        if let Some((_, status)) = self.updates.remove(&self.correlation_id) {
            match status {
                // The planning was started
                PlanningStatus::Started(name) => {
                    // Log it
                    debug!("Planning of workflow '{}' started{}",
                        self.correlation_id,
                        if let Some(name) = name {
                            format!(" by planner '{}'", name)
                        } else {
                            String::new()
                        }
                    );

                    // Set the internal result, then continue being pending
                    self.started = true;
                }

                // The planning was finished
                PlanningStatus::Success(_) |
                PlanningStatus::Failed(_)  |
                PlanningStatus::Error(_)   => {
                    debug!("Planning of workflow '{}' completed", self.correlation_id);
                    return Poll::Ready(Some(status));
                },

                // The rest means pending
                _ => {},
            }
        }

        // We have to update the internal waker too
        {
            let mut state: MutexGuard<Option<Waker>> = self.waker.lock().unwrap();
            *state = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}





/***** HELPER FUNCTIONS *****/
/// Blocks the current thread until the remote planner has planned the workflow with the given correlation ID.
/// 
/// This is done by using Kafka events to wait for it.
/// 
/// # Arguments
/// - `correlation_id`: The identifier for the workflow of which we are interested in the planning results.
/// - `waker`: The Waker of the event monitor that will ping us when a new message has arrived.
/// - `updates`: The event monitor-updated list of the latest status per correlation ID.
/// 
/// # Returns
/// The planned workflow as a Workflow. It being planned means its tasks and datasets are resolved.
/// 
/// # Errors
/// This function errors if we either failed to wait on Kafka, or if the remote planner failed.
async fn wait_planned(correlation_id: impl AsRef<str>, waker: Arc<Mutex<Option<Waker>>>, updates: Arc<DashMap<String, PlanningStatus>>) -> Result<Workflow, PlanError> {
    let correlation_id: &str = correlation_id.as_ref();

    // Wait until a plan result occurs
    let res: Option<PlanningStatus> = WaitUntilPlanned {
        correlation_id : correlation_id.to_string(),
        updates,
        waker,

        started       : false,
        timeout       : DEFAULT_PLANNING_STARTED_TIMEOUT,
        timeout_start : SystemTime::now(),
    }.await;

    // Match on timeouts
    let res: PlanningStatus = match res {
        Some(res) => res,
        None      => { return Err(PlanError::PlanningTimeout{ correlation_id: correlation_id.into(), timeout: DEFAULT_PLANNING_STARTED_TIMEOUT }); },
    };

    // Match the result itself
    match res {
        // The planning was done
        PlanningStatus::Success(wf) => {
            // We attempt to parse the result itself as a Workflow
            let workflow: Workflow = match serde_json::from_str(&wf) {
                Ok(workflow) => workflow,
                Err(err)     => { return Err(PlanError::PlanParseError{ correlation_id: correlation_id.into(), raw: wf, err }); }  
            };

            // Done, return
            Ok(workflow)
        },

        // Otherwise, no plan available
        PlanningStatus::Failed(reason) => Err(PlanError::PlanningFailed{ correlation_id: correlation_id.into(), reason }),
        PlanningStatus::Error(err)     => Err(PlanError::PlanningError{ correlation_id: correlation_id.into(), err }),

        // Other things should not occur; the wait covered those
        _ => { unreachable!(); }
    }
}





/***** LIBRARY *****/
/// The planner is in charge of assigning locations to tasks in a workflow. This one is very simple, assigning 'localhost' to whatever it sees.
pub struct InstancePlanner {
    /// The Kafka servers we're connecting to.
    central_cfg : CentralConfig,

    /// The Kafka producer with which we send commands and such.
    producer  : Arc<FutureProducer>,
    /// The waker triggered by the event monitor to trigger futures waiting for event updates.
    waker     : Arc<Mutex<Option<Waker>>>,
    /// The list of states that contains the most recently received planner updates.
    updates   : Arc<DashMap<String, PlanningStatus>>,
}

impl InstancePlanner {
    /// Constructor for the InstancePlanner.
    /// 
    /// # Arguments
    /// - `central_cfg`: The configuration for this node's environment. For us, mostly Kafka topics and associated broker.
    /// 
    /// # Returns
    /// A new InstancePlanner instance.
    #[inline]
    pub fn new(central_cfg: CentralConfig) -> Result<Self, PlanError> {
        let brokers: String = central_cfg.services.aux_kafka.address.to_string();
        Ok(Self {
            central_cfg,

            producer  : match ClientConfig::new().set("bootstrap.servers", &brokers).set("message.timeout.ms", "5000").create() {
                Ok(producer) => Arc::new(producer),
                Err(err)     => { return Err(PlanError::KafkaProducerError { err }); },
            },
            waker     : Arc::new(Mutex::new(None)),
            updates   : Arc::new(DashMap::new()),
        })
    }



    /// Launches an event monitor in the background (using `tokio::spawn`) for planning updates.
    /// 
    /// Note that the event monitor itself is launched asynchronously. When this function returns, it has merely started (even though it's an async function itself - but that's only used during setup, I swear).
    /// 
    /// # Arguments
    /// - `group_id`: The Kafka group ID to listen on.
    /// 
    /// # Errors
    /// This function errors if we failed to start listening on the Kafka stream and create a future for that.
    pub async fn start_event_monitor(&self, group_id: impl AsRef<str>) -> Result<(), PlanError> {
        let group_id  : &str = group_id.as_ref();

        // Ensure that the to-be-listened on topic exists
        let brokers: String = self.central_cfg.services.aux_kafka.address.to_string();
        if let Err(err) = ensure_topics(vec![ &self.central_cfg.topics.plr_res ], &brokers).await { return Err(PlanError::KafkaTopicError { brokers, topics: vec![ self.central_cfg.topics.plr_res.clone() ], err }); };

        // Create one consumer per topic that we're reading (i.e., one)
        let consumer: StreamConsumer = match ClientConfig::new()
            .set("group.id", group_id)
            .set("bootstrap.servers", &brokers)
            .set("enable.partition.eof", "false")
            .set("session.timeout.ms", "6000")
            .set("enable.auto.commit", "true")
            .create()
        {
            Ok(consumer) => consumer,
            Err(err)     => { return Err(PlanError::KafkaConsumerError{ err }); }
        };

        // Restore previous offsets
        if let Err(err) = restore_committed_offsets(&consumer, &self.central_cfg.topics.plr_res) { return Err(PlanError::KafkaOffsetsError { err }); }

        // Run the Kafka consumer to monitor the planning events on a new thread (or at least, concurrently)
        let waker   : Arc<Mutex<Option<Waker>>>                                      = self.waker.clone();
        let updates : Arc<DashMap<String, PlanningStatus>> = self.updates.clone();
        tokio::spawn(async move {
            loop {
                if let Err(err) = consumer.stream().try_for_each(|borrowed_message| {
                    let owned_message = borrowed_message.detach();
                    let owned_updates = updates.clone();
                    let owned_waker   = waker.clone();

                    // The rest is returned as a future
                    async move {
                        if let Some(payload) = owned_message.payload() {
                            // Decode payload into a PlanningUpdate message.
                            let msg: PlanningUpdate = match PlanningUpdate::decode(payload) {
                                Ok(msg)  => msg,
                                Err(err) => { error!("Failed to decode incoming PlanningUpdate: {}", err); return Ok(()); },
                            };

                            // Match on the kind, inserting the proper states
                            match PlanningStatusKind::from_i32(msg.kind) {
                                Some(PlanningStatusKind::Started) => {
                                    debug!("Status update: Workflow '{}' is now being planned{}", msg.id, if let Some(name) = &msg.result { format!(" by planner '{}'", name) } else { String::new() });
                                    owned_updates.insert(msg.id, PlanningStatus::Started(msg.result));
                                },
        
                                Some(PlanningStatusKind::Success) => {
                                    debug!("Status update: Workflow '{}' has successfully been planned", msg.id);
        
                                    // Make sure a workflow is given
                                    let plan: String = match msg.result {
                                        Some(plan) => plan,
                                        None       => { error!("Incoming PlanningUpdate with PlanningStatusKind::Success is missing a resolved workflow"); return Ok(()); },
                                    };
        
                                    // Store it
                                    owned_updates.insert(msg.id, PlanningStatus::Success(plan));
                                },
                                Some(PlanningStatusKind::Failed) => {
                                    debug!("Status update: Workflow '{}' failed to been planned{}", msg.id, if let Some(reason) = &msg.result { format!(": {}", reason) } else { String::new() });
                                    owned_updates.insert(msg.id, PlanningStatus::Failed(msg.result));
                                },
                                Some(PlanningStatusKind::Error) => {
                                    let err: String = msg.result.unwrap_or_else(|| String::from("<unknown error>"));
                                    debug!("Status update: Workflow '{}' has caused errors to appear: {}", msg.id, err);
                                    owned_updates.insert(msg.id, PlanningStatus::Error(err));
                                },
        
                                None => { error!("Unknown PlanningStatusKind '{}'", msg.kind); return Ok(()); },
                            }
                        }
        
                        // Signal the waker, if any
                        {
                            let mut state: MutexGuard<Option<Waker>> = owned_waker.lock().unwrap();
                            if let Some(waker) = state.take() {
                                waker.wake();
                            }
                        }
                        
                        // Done
                        Ok(())
                    }
                }).await {
                    error!("Failed to run InstancePlanner event monitor: {}", err);
                    error!("Note: you will likely not get any events now. Automatically restarting in 3 seconds, but you might want to investigate the problem.");
                    tokio::time::sleep(Duration::from_millis(3000)).await;
                }
            }
        });

        // Done
        Ok(())
    }



    /// Plans the given workflow.
    /// 
    /// Will populate the planning timings in the given profile struct if the planner reports them.
    /// 
    /// # Arguments
    /// - `workflow`: The Workflow to plan.
    /// - `prof`: The ProfileScope that can be used to provide additional information about the timings of the planning (driver-side).
    /// 
    /// # Returns
    /// The same workflow as given, but now with all tasks and data transfers planned.
    pub async fn plan(&self, workflow: Workflow, prof: ProfileScopeHandle<'_>) -> Result<Workflow, PlanError> {
        // Generate the ID
        let correlation_id: String = format!("{}", TaskId::generate());

        // Ensure that the to-be-send-on topic exists
        let kf = prof.time(format!("workflow {} Kafka preparation", correlation_id));
        let brokers: String = self.central_cfg.services.aux_kafka.address.to_string();
        if let Err(err) = ensure_topics(vec![ &self.central_cfg.topics.plr_cmd ], &brokers).await { return Err(PlanError::KafkaTopicError { brokers, topics: vec![ self.central_cfg.topics.plr_cmd.clone() ], err }); };
        kf.stop();

        // Serialize the workflow
        let ser = prof.time(format!("workflow {} serialization", correlation_id));
        let swork: String = match serde_json::to_string(&workflow) {
            Ok(swork) => swork,
            Err(err)  => { return Err(PlanError::WorkflowSerializeError{ err }); },  
        };
        ser.stop();

        // Populate a "PlanningCommand" with that (i.e., just populate a future record with the string)
        let remote = prof.time(format!("workflow '{}' on brane-plr", correlation_id));
        let message: FutureRecord<String, [u8]> = FutureRecord::to(&self.central_cfg.topics.plr_cmd)
            .key(&correlation_id)
            .payload(swork.as_bytes());

        // Send the message
        if let Err((err, _)) = self.producer.send(message, Timeout::After(Duration::from_secs(5))).await {
            return Err(PlanError::KafkaSendError { correlation_id, topic: self.central_cfg.topics.plr_cmd.clone(), err });
        }

        // Now we wait until the message has been planned.
        let plan: Workflow = wait_planned(&correlation_id, self.waker.clone(), self.updates.clone()).await?;
        remote.stop();

        // Done
        Ok(plan)
    }
}

// #[async_trait::async_trait]
// impl Planner for InstancePlanner {
    
// }
