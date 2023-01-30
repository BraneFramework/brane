//  PLANNER.rs
//    by Lut99
// 
//  Created:
//    25 Oct 2022, 11:35:00
//  Last edited:
//    26 Jan 2023, 09:57:45
//  Auto updated?
//    Yes
// 
//  Description:
//!   Implements a planner for the instance use-case.
// 


/***** LIBRARY *****/
use std::collections::{HashMap, HashSet};
use std::mem;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_recursion::async_recursion;
use futures_util::TryStreamExt;
use log::{debug, info, error};
use prost::Message as _;
use rand::prelude::IteratorRandom;
use rdkafka::{ClientConfig, Message};
use rdkafka::consumer::{CommitMode, Consumer};
use rdkafka::consumer::stream_consumer::StreamConsumer;
use rdkafka::message::OwnedMessage;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use reqwest::Response;

use brane_ast::Workflow;
use brane_ast::locations::Locations;
use brane_ast::ast::{ComputeTaskDef, DataName, Edge, SymTable, TaskDef};
use brane_cfg::infra::InfraFile;
use brane_cfg::node::{CentralConfig, NodeConfig, NodeKindConfig};
use brane_shr::kafka::{ensure_topics, restore_committed_offsets};
use brane_tsk::errors::PlanError;
use brane_tsk::api::get_data_index;
use specifications::address::Address;
use specifications::data::{AccessKind, AvailabilityKind, DataIndex, PreprocessKind};
use specifications::package::Capability;
use specifications::planning::{PlanningStatus, PlanningStatusKind, PlanningUpdate};
use specifications::profiling::TimingReport;


/***** HELPER FUNCTIONS *****/
/// Helper function that sends an update event over Kafka.
/// 
/// # Arguments
/// - `producer`: The Kafka producer to send with.
/// - `topic`: The Kafka topic to send on.
/// - `id`: The planning session ID to correlation this update with.
/// - `status`: The PlanningStatus to update with.
/// 
/// # Errors
/// This function errors if we failed to send the update somehow.
async fn send_update(producer: Arc<FutureProducer>, topic: impl AsRef<str>, correlation_id: impl AsRef<str>, status: PlanningStatus) -> Result<(), PlanError> {
    let topic          : &str = topic.as_ref();
    let correlation_id : &str = correlation_id.as_ref();
    debug!("Sending update '{:?}' on topic '{}' for workflow '{}'", status, topic, correlation_id);

    // Translate the status into a (kind, string) pair.
    let (kind, result): (PlanningStatusKind, Option<String>) = match status {
        PlanningStatus::Started(result) => (PlanningStatusKind::Started, result),

        PlanningStatus::Success(result) => (PlanningStatusKind::Success, Some(result)),
        PlanningStatus::Failed(result)  => (PlanningStatusKind::Failed, result),
        PlanningStatus::Error(result)   => (PlanningStatusKind::Error, Some(result)),

        PlanningStatus::None => { panic!("Cannot update the client on `PlanningStatus::None`"); },
    };
    let result_len: usize = result.as_ref().map(|r| r.len()).unwrap_or(0);

    // Create a planning update
    let update : PlanningUpdate = PlanningUpdate{
        id   : correlation_id.into(),
        kind : kind.into(),
        result,
    };

    // Encode it
    let mut payload : Vec<u8> = Vec::with_capacity(64 + result_len);
    if let Err(err) = update.encode(&mut payload) {
        return Err(PlanError::UpdateEncodeError{ correlation_id: correlation_id.into(), kind, err });
    };

    // Construct the future record that contains the to-be-planned workflow from this
    let scorr: String = correlation_id.into();
    let message: FutureRecord<String, [u8]> = FutureRecord::to(topic)
        .key(&scorr)
        .payload(&payload);

    // Send the message with the appropriate timeout
    let timeout: Timeout = Timeout::After(Duration::from_secs(5));
    if let Err((err, _)) = producer.send(message, timeout).await {
        return Err(PlanError::KafkaSendError{ correlation_id: correlation_id.into(), topic: topic.into(), err });
    }

    // Done
    Ok(())
}



/// Helper function that plans the given list of edges.
/// 
/// # Arguments
/// - `table`: The SymbolTable where this edge lives in.
/// - `edges`: The given list to plan.
/// - `api_addr`: The address where we can reach the `brane-api` service on. Used for asserting that the target domain supports what the package needs.
/// - `dindex`: The DataIndex we use to resolve data references.
/// - `infra`: The infrastructure to resolve locations.
/// - `pc`: The initial value for the program counter. You should use '0' if you're calling this function.
/// - `merge`: The number of the edge until which we will run. You should use 'None' if you're calling this function.
/// - `deferred`: Whether or not to show errors when an intermediate result is not generated yet (false) or not (true).
/// - `done`: A list we use to keep track of edges we've already analyzed (to prevent endless loops).
/// 
/// # Returns
/// Nothing, but does change the given list.
/// 
/// # Errors
/// This function may error if the given list of edges was malformed (usually due to unknown or inaccessible datasets or results).
#[allow(clippy::too_many_arguments)]
#[async_recursion]
async fn plan_edges(table: &mut SymTable, edges: &mut [Edge], api_addr: &Address, dindex: &DataIndex, infra: &InfraFile, pc: usize, merge: Option<usize>, deferred: bool, done: &mut HashSet<usize>) -> Result<(), PlanError> {
    // We cannot get away simply examining all edges in-order; we have to follow their execution structure
    let mut pc: usize = pc;
    while pc < edges.len() && (merge.is_none() || pc != merge.unwrap()) {
        // Match on the edge to progress
        let edge: &mut Edge = &mut edges[pc];
        if done.contains(&pc) { break; }
        done.insert(pc);
        match edge {
            Edge::Node{ task, locs, at, input, result, next } => {
                // This is the node where it all revolves around, in the end
                debug!("Planning task '{}' (edge {})...", table.tasks[*task].name(), pc);

                // If everything is allowed, we make it one easier for the planner by checking we happen to find only one occurrance based on the datasets
                if locs.is_all() {
                    // Search all of the input to collect a list of possible locations
                    let mut data_locs: Vec<&String> = vec![];
                    for (d, _) in input.iter() {
                        // We only take data into account (for now, at least)
                        if let DataName::Data(name) = d {
                            // Attempt to find it
                            if let Some(info) = dindex.get(name) {
                                // Simply add all locations where it lives
                                data_locs.append(&mut info.access.keys().collect::<Vec<&String>>());
                            } else {
                                return Err(PlanError::UnknownDataset{ name: name.clone() });
                            }
                        }
                    }

                    // If there is only one location, then we override locs
                    if data_locs.len() == 1 {
                        *locs = Locations::Restricted(vec![ data_locs[0].clone() ]);
                    }
                }

                // We resolve all locations by collapsing them to the only possibility indicated by the user. More or less than zero? Error!
                if !locs.is_restrictive() || locs.restricted().len() != 1 { return Err(PlanError::AmbigiousLocationError{ name: table.tasks[*task].name().into(), locs: locs.clone() }); }
                let location: &str = &locs.restricted()[0];

                // Fetch the list of capabilities supported by the planned location
                let address: String = format!("{}/infra/capabilities/{}", api_addr, location);
                let res: Response = match reqwest::get(&address).await {
                    Ok(req)  => req,
                    Err(err) => { return Err(PlanError::RequestError{ address, err }); },
                };
                if !res.status().is_success() { return Err(PlanError::RequestFailure{ address, code: res.status(), err: res.text().await.ok() }); }
                let capabilities: String = match res.text().await {
                    Ok(caps) => caps,
                    Err(err) => { return Err(PlanError::RequestBodyError{ address, err }); },
                };
                let capabilities: HashSet<Capability> = match serde_json::from_str(&capabilities) {
                    Ok(caps) => caps,
                    Err(err) => { return Err(PlanError::RequestParseError{ address, raw: capabilities, err }); },
                };

                // Assert that this is what we need
                if let TaskDef::Compute(ComputeTaskDef{ function, requirements, .. }) = &table.tasks[*task] {
                    if !capabilities.is_superset(requirements) { return Err(PlanError::UnsupportedCapabilities{ task: function.name.clone(), loc: location.into(), expected: requirements.clone(), got: capabilities }); }
                } else {
                    panic!("Non-compute tasks are not (yet) supported.");
                };

                // It checks out, plan it
                *at = Some(location.into());
                debug!("Task '{}' planned at '{}'", table.tasks[*task].name(), location);

                // For all dataset/intermediate result inputs, we check if these are available on the planned location.
                for (name, avail) in input {
                    match name {
                        DataName::Data(name) => {
                            if let Some(info) = dindex.get(name) {
                                // Check if it is local or remote
                                if let Some(access) = info.access.get(location) {
                                    debug!("Input dataset '{}' is locally available", name);
                                    *avail = Some(AvailabilityKind::Available { how: access.clone() });
                                } else {
                                    // Select one of the other locations it's available (for now, random?)
                                    if info.access.is_empty() { return Err(PlanError::DatasetUnavailable { name: name.clone(), locs: vec![] }); }
                                    let mut rng = rand::thread_rng();
                                    let location: &str = info.access.keys().choose(&mut rng).unwrap();

                                    // Get the registry of that location
                                    let registry : &Address = &infra.get(location).unwrap_or_else(|| panic!("DataIndex advertises location '{}', but that location is unknown", location)).registry;
                                    let address  : String  = format!("{}/data/download/{}", registry, name);
                                    debug!("Input dataset '{}' will be transferred in from '{}'", name, address);

                                    // That's the location where to pull the dataset from
                                    *avail = Some(AvailabilityKind::Unavailable{ how: PreprocessKind::TransferRegistryTar{ location: location.into(), address } });
                                }
                            } else {
                                return Err(PlanError::UnknownDataset{ name: name.clone() });
                            }
                        },

                        DataName::IntermediateResult(name) => {
                            // It has to be declared before
                            if let Some(loc) = table.results.get(name) {
                                // Match on whether it is available locally or not
                                if location == loc {
                                    debug!("Input intermediate result '{}' is locally available", name);
                                    *avail = Some(AvailabilityKind::Available { how: AccessKind::File{ path: PathBuf::from(name) } });
                                } else {
                                    // Find the remote location in the infra file
                                    let registry: &Address = &infra.get(loc).unwrap_or_else(|| panic!("IntermediateResult advertises location '{}', but that location is unknown", loc)).registry;

                                    // Compute the registry access method
                                    let address: String = format!("{}/results/download/{}", registry, name);
                                    debug!("Input intermediate result '{}' will be transferred in from '{}'", name, address);

                                    // That's the location where to pull the dataset from
                                    *avail = Some(AvailabilityKind::Unavailable{ how: PreprocessKind::TransferRegistryTar{ location: loc.clone(), address } });
                                }
                            } else if !deferred {
                                return Err(PlanError::UnknownIntermediateResult{ name: name.clone() });
                            } else {
                                debug!("Cannot determine value of intermediate result '{}' yet; it might be declared later (deferred)", name);
                            }
                        },
                    }
                }

                // Then, we make the intermediate result available at the location where the function is being run (if there is any)
                if let Some(name) = result {
                    // Insert an entry in the list detailling where to access it and how
                    debug!("Making intermediate result '{}' accessible after execution of '{}' on '{}'", name, table.tasks[*task].name(), location);
                    table.results.insert(name.clone(), location.into());
                }

                // Move to the one indicated by 'next'
                pc = *next;
            },
            Edge::Linear{ next, .. } => {
                // Simply move to the next one
                pc = *next;
            },
            Edge::Stop{} => {
                // We've reached the end of the program
                break;
            },

            Edge::Branch{ true_next, false_next, merge } => {
                // Dereference the numbers to dodge the borrow checker
                let true_next : usize         = *true_next;
                let false_next: Option<usize> = *false_next;
                let merge     : Option<usize> = *merge;

                // First analyse the true_next branch, until it reaches the merge (or quits)
                plan_edges(table, edges, api_addr, dindex, infra, true_next, merge, deferred, done).await?;
                // If there is a false branch, do that one too
                if let Some(false_next) = false_next {
                    plan_edges(table, edges, api_addr, dindex, infra, false_next, merge, deferred, done).await?;
                }

                // If there is a merge, continue there; otherwise, we can assume that we've returned fully in the branch
                if let Some(merge) = merge {
                    pc = merge;
                } else {
                    break;
                }
            },
            Edge::Parallel{ branches, merge } => {
                // Dereference the numbers to dodge the borrow checker
                let branches : Vec<usize> = branches.clone();
                let merge: usize = *merge;

                // Analyse any of the branches
                for b in branches {
                    // No merge needed since we can be safe in assuming parallel branches end with returns
                    plan_edges(table, edges, api_addr, dindex, infra, b, None, deferred, done).await?;
                }

                // Continue at the merge
                pc = merge;
            },
            Edge::Join{ next, .. } => {
                // Move to the next instruction (joins are not relevant for planning)
                pc = *next;
            },

            Edge::Loop{ cond, body, next, .. } => {
                // Dereference the numbers to dodge the borrow checker
                let cond : usize         = *cond;
                let body : usize         = *body;
                let next : Option<usize> = *next;

                // Run the conditions and body in a first pass, with deferation enabled, to do as much as we can
                plan_edges(table, edges, api_addr, dindex, infra, cond, Some(body), true, done).await?;
                plan_edges(table, edges, api_addr, dindex, infra, body, Some(cond), true, done).await?;

                // Then we run through the condition and body again to resolve any unknown things
                plan_deferred(table, edges, infra, cond, Some(body), &mut HashSet::new())?;
                plan_deferred(table, edges, infra, cond, Some(cond), &mut HashSet::new())?;

                // When done, move to the next if there is any (otherwise, the body returns and then so can we)
                if let Some(next) = next {
                    pc = next;
                } else {
                    break;
                }
            },

            Edge::Call{ next } => {
                // We can ignore calls for now, but...
                // TODO: Check if this planning works across functions *screams*
                pc = *next;
            },
            Edge::Return{} => {
                // We will stop analysing here too, since we assume we have been called in recursion mode or something
                break;
            },
        }
    }

    // Done
    debug!("Planning success");
    Ok(())
}

/// Helper function that populates the availability of results right after a first planning round, to catch those that needed to be deferred (i.e., loop variables).
/// 
/// # Arguments
/// - `table`: The SymbolTable these edges live in.
/// - `edges`: The given list to plan.
/// - `infra`: The infrastructure to resolve locations.
/// - `pc`: The started index for the program counter. Should be '0' when called manually, the rest is handled during recursion.
/// - `merge`: If given, then we will stop analysing once we reach that point.
/// 
/// # Returns
/// Nothing, but does change the given list.
/// 
/// # Errors
/// This function may error if there were still results that couldn't be populated even after we've seen all edges.
fn plan_deferred(table: &SymTable, edges: &mut [Edge], infra: &InfraFile, pc: usize, merge: Option<usize>, done: &mut HashSet<usize>) -> Result<(), PlanError> {
    // We cannot get away simply examining all edges in-order; we have to follow their execution structure
    let mut pc: usize = pc;
    while pc < edges.len() && (merge.is_none() || pc != merge.unwrap()) {
        // Match on the edge to progress
        let edge: &mut Edge = &mut edges[pc];
        if done.contains(&pc) { break; }
        done.insert(pc);
        match edge {
            // This is the node where it all revolves around, in the end
            Edge::Node{ at, input, next, .. } => {
                // This next trick involves checking if the node has any unresolved results as input, then trying to resolve them
                for (name, avail) in input {
                    // Continue if it already has a resolved availability
                    if avail.is_some() { continue; }

                    // Get the name of the result
                    if let DataName::IntermediateResult(name) = name {
                        // Extract the planned location
                        let location: &str = at.as_ref().unwrap();

                        // It has to be declared before
                        if let Some(loc) = table.results.get(name) {
                            // Match on whether it is available locally or not
                            if location == loc {
                                debug!("Input intermediate result '{}' is locally available", name);
                                *avail = Some(AvailabilityKind::Available { how: AccessKind::File{ path: PathBuf::from(name) } });
                            } else {
                                // Find the remote location in the infra file
                                let registry: &Address = &infra.get(loc).unwrap_or_else(|| panic!("IntermediateResult advertises location '{}', but that location is unknown", loc)).registry;

                                // Compute the registry access method
                                let address: String = format!("{}/results/download/{}", registry, name);
                                debug!("Input intermediate result '{}' will be transferred in from '{}'", name, address);

                                // That's the location where to pull the dataset from
                                *avail = Some(AvailabilityKind::Unavailable{ how: PreprocessKind::TransferRegistryTar{ location: loc.clone(), address } });
                            }
                        } else {
                            // No more second chances
                            return Err(PlanError::UnknownIntermediateResult{ name: name.clone() });
                        }

                    } else {
                        panic!("Should never see an unresolved Data in the workflow");
                    }
                }

                // Finally, don't forget to move to the next one
                pc = *next;
            },
            Edge::Linear{ next, .. } => {
                // Simply move to the next one
                pc = *next;
            },
            Edge::Stop{} => {
                // We've reached the end of the program
                break;
            },

            Edge::Branch{ true_next, false_next, merge } => {
                // Dereference the numbers to dodge the borrow checker
                let true_next : usize         = *true_next;
                let false_next: Option<usize> = *false_next;
                let merge     : Option<usize> = *merge;

                // First analyse the true_next branch, until it reaches the merge (or quits)
                plan_deferred(table, edges, infra, true_next, merge, done)?;
                // If there is a false branch, do that one too
                if let Some(false_next) = false_next {
                    plan_deferred(table, edges, infra, false_next, merge, done)?;
                }

                // If there is a merge, continue there; otherwise, we can assume that we've returned fully in the branch
                if let Some(merge) = merge {
                    pc = merge;
                } else {
                    break;
                }
            },
            Edge::Parallel{ branches, merge } => {
                // Dereference the numbers to dodge the borrow checker
                let branches : Vec<usize> = branches.clone();
                let merge: usize = *merge;

                // Analyse any of the branches
                for b in branches {
                    // No merge needed since we can be safe in assuming parallel branches end with returns
                    plan_deferred(table, edges, infra, b, None, done)?;
                }

                // Continue at the merge
                pc = merge;
            },
            Edge::Join{ next, .. } => {
                // Move to the next instruction (joins are not relevant for planning)
                pc = *next;
            },

            Edge::Loop{ cond, body, next, .. } => {
                // Dereference the numbers to dodge the borrow checker
                let cond : usize         = *cond;
                let body : usize         = *body;
                let next : Option<usize> = *next;

                // We only have to analyse further deferrence; the actual planning should have been done before `plan_deferred()` is called
                plan_deferred(table, edges, infra, cond, Some(body), done)?;
                plan_deferred(table, edges, infra, cond, Some(cond), done)?;

                // When done, move to the next if there is any (otherwise, the body returns and then so can we)
                if let Some(next) = next {
                    pc = next;
                } else {
                    break;
                }
            },

            Edge::Call{ next } => {
                // We can ignore calls for now, but...
                // TODO: Check if this planning works across functions *screams*
                pc = *next;
            },
            Edge::Return{} => {
                // We will stop analysing here too, since we assume we have been called in recursion mode or something
                break;
            },
        }
    }

    // Done
    Ok(())
}





/***** LIBRARY *****/
/// This function hosts the actual planner, which uses an event monitor to receive plans which are then planned.
/// 
/// # Arguments
/// - `node_config_path`: Path to the node.yml file that defines this node's environment configuration.
/// - `node_config`: The configuration for this node's environment. For us, mostly Kafka topics and paths to infra.yml and (optional) secrets.yml files. This is mostly given to avoid another load, since we could've loaded it from the path too.
/// - `group_id`: The Kafka group ID to listen on.
/// 
/// # Returns
/// This function doesn't really return, unless the Kafka topic stream closes.
/// 
/// # Errors
/// This function only errors if we fail to listen for events. Otherwise, errors are logged to stderr using the `error!` macro.
pub async fn planner_server(node_config_path: impl Into<PathBuf>, node_config: NodeConfig, group_id: impl Into<String>) -> Result<(), PlanError> {
    let node_config_path : PathBuf = node_config_path.into();
    let group_id         : String  = group_id.into();

    // Ensure that the input/output topics exists.
    let topics  : Vec<&str> = vec![ &node_config.node.central().topics.planner_command, &node_config.node.central().topics.planner_results ];
    let brokers : String    = node_config.node.central().services.brokers.iter().map(|a| a.to_string()).collect::<Vec<String>>().join(",");
    if let Err(err) = ensure_topics(topics.clone(), &brokers).await {
        return Err(PlanError::KafkaTopicError{ brokers, topics: topics.into_iter().map(|t| t.into()).collect(), err });
    };

    // Start the producer(s) and consumer(s).
    let producer: Arc<FutureProducer> = match ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("message.timeout.ms", "5000")
        .create()
    {
        Ok(producer) => Arc::new(producer),
        Err(err)     => { return Err(PlanError::KafkaProducerError{ err }); },
    };
    let consumer: StreamConsumer = match ClientConfig::new()
        .set("group.id", &group_id)
        .set("bootstrap.servers", &brokers)
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", "6000")
        .set("enable.auto.commit", "false")
        .create()
    {
        Ok(consumer) => consumer,
        Err(err)     => { return Err(PlanError::KafkaConsumerError{ err }); },
    };

    // Now restore the committed offsets
    if let Err(err) = restore_committed_offsets(&consumer, &node_config.node.central().topics.planner_command) {
        return Err(PlanError::KafkaOffsetsError{ err });
    }

    // Next, we start processing the incoming stream of messages as soon as they arrive
    match consumer.stream().try_for_each(|borrowed_message| {
        consumer.commit_message(&borrowed_message, CommitMode::Sync).unwrap();

        // Shadow with owned clones
        let owned_message     : OwnedMessage        = borrowed_message.detach();
        let producer          : Arc<FutureProducer> = producer.clone();
        let node_config_path  : PathBuf             = node_config_path.clone();

        // Do the rest in a future that takes ownership of the clones
        async move {
            let prof: TimingReport = TimingReport::auto_report("brane-plr", std::io::stdout());

            // Fetch the most recent NodeConfig
            let node_config: NodeConfig = match NodeConfig::from_path(node_config_path) {
                Ok(config) => config,
                Err(err)   => {
                    error!("Failed to load NodeConfig file: {}", err);
                    return Ok(());
                },
            };
            let central: CentralConfig = if let NodeKindConfig::Central(config) = node_config.node {
                config
            } else {
                panic!("Got a node.yml that is not for a central node");
            };

            // Parse the key
            let id: String = String::from_utf8_lossy(owned_message.key().unwrap_or(&[])).to_string();
            info!("Received new plan request with ID '{}' on topic '{}'", id, central.topics.planner_command);
            let _wf = prof.guard(format!("workflow '{}'", id));

            // Parse the payload, if any
            if let Some(payload) = owned_message.payload() {
                let timing = prof.guard(format!("workflow '{}' parsing", id));

                // Parse as UTF-8
                debug!("Message: \"\"\"{}\"\"\"", String::from_utf8_lossy(payload));
                let message: String = String::from_utf8_lossy(payload).to_string();

                // Attempt to parse the workflow
                debug!("Parsing workflow of {} characters for session '{}'", message.len(), id);
                let mut workflow: Workflow = match serde_json::from_str(&message) {
                    Ok(workflow) => workflow,
                    Err(err)     => {
                        error!("Failed to parse incoming message workflow on topic '{}' as Workflow JSON: {}\n\nworkflow:\n{}\n{}\n{}\n", central.topics.planner_command, err, (0..80).map(|_| '-').collect::<String>(), message, (0..80).map(|_| '-').collect::<String>());
                        return Ok(());
                    }
                };
                timing.stop();

                // Send that we've started planning
                if let Err(err) = send_update(producer.clone(), &central.topics.planner_results, &id, PlanningStatus::Started(None)).await { error!("Failed to update client that planning has started: {}", err); };

                // Load the infrastructure file
                let timing = prof.guard(format!("workflow '{}' information", id));
                let infra: InfraFile = match InfraFile::from_path(&central.paths.infra) {
                    Ok(infra) => infra,
                    Err(err)  => {
                        error!("Failed to load infrastructure file '{}': {}", central.paths.infra.display(), err);
                        return Ok(());
                    }
                };

                // Fetch the data index
                let data_index_addr: String = format!("{}/data/info", central.services.api);
                let dindex: DataIndex = match get_data_index(&data_index_addr).await {
                    Ok(dindex) => dindex,
                    Err(err)   => {
                        error!("Failed to fetch DataIndex from '{}': {}", data_index_addr, err);
                        return Ok(());
                    }
                };
                timing.stop();

                // Now we do the planning
                {
                    let report = prof.nested_report(format!("workflow '{}' algorithm", id));
                    let _guard = report.guard("total");

                    // Get the symbol table muteable, so we can... mutate... it
                    let mut table: Arc<SymTable> = Arc::new(SymTable::new());
                    mem::swap(&mut workflow.table, &mut table);
                    let mut table: SymTable      = Arc::try_unwrap(table).unwrap();

                    // Do the main edges first
                    {
                        // Start by getting a list of all the edges
                        let mut edges: Arc<Vec<Edge>> = Arc::new(vec![]);
                        mem::swap(&mut workflow.graph, &mut edges);
                        let mut edges: Vec<Edge>      = Arc::try_unwrap(edges).unwrap();

                        // Plan them
                        debug!("Planning main edges...");
                        if let Err(err) = report.fut("<<<main>>>", plan_edges(&mut table, &mut edges, &central.services.api, &dindex, &infra, 0, None, false, &mut HashSet::new())).await {
                            error!("Failed to plan main edges for workflow with correlation ID '{}': {}", id, err);
                            if let Err(err) = send_update(producer.clone(), &central.topics.planner_results, &id, PlanningStatus::Error(format!("{}", err))).await { error!("Failed to update client that planning has failed: {}", err); }
                            return Ok(());
                        };

                        // Move the edges back
                        let mut edges: Arc<Vec<Edge>> = Arc::new(edges);
                        mem::swap(&mut edges, &mut workflow.graph);
                    }

                    // Then we do the function edges
                    {
                        // Start by getting the map
                        let mut funcs: Arc<HashMap<usize, Vec<Edge>>> = Arc::new(HashMap::new());
                        mem::swap(&mut workflow.funcs, &mut funcs);
                        let mut funcs: HashMap<usize, Vec<Edge>>      = Arc::try_unwrap(funcs).unwrap();

                        // Iterate through all of the edges
                        for (idx, edges) in &mut funcs {
                            debug!("Planning '{}' edges...", table.funcs[*idx].name);
                            if let Err(err) = report.fut(workflow.table.funcs[*idx].name.to_string(), plan_edges(&mut table, edges, &central.services.api, &dindex, &infra, 0, None, false, &mut HashSet::new())).await {
                                error!("Failed to plan function '{}' edges for workflow with correlation ID '{}': {}", table.funcs[*idx].name, id, err);
                                if let Err(err) = send_update(producer.clone(), &central.topics.planner_results, &id, PlanningStatus::Error(format!("{}", err))).await { error!("Failed to update client that planning has failed: {}", err); }
                                return Ok(());
                            }
                        }

                        // Put the map back
                        let mut funcs: Arc<HashMap<usize, Vec<Edge>>> = Arc::new(funcs);
                        mem::swap(&mut funcs, &mut workflow.funcs);
                    }

                    // Then, put the table back
                    let mut table: Arc<SymTable> = Arc::new(table);
                    mem::swap(&mut table, &mut workflow.table);
                }

                // With the planning done, re-serialize
                debug!("Serializing plan...");
                let timing = prof.guard(format!("workflow '{}' post", id));
                let splan: String = match serde_json::to_string(&workflow) {
                    Ok(splan) => splan,
                    Err(err)  => {
                        error!("Failed to serialize plan: {}", err);
                        if let Err(err) = send_update(producer.clone(), &central.topics.planner_results, &id, PlanningStatus::Error(format!("{}", err))).await { error!("Failed to update client that planning has failed: {}", err); }
                        return Ok(());
                    },
                };
                timing.stop();

                // Send the result
                if let Err(err) = send_update(producer.clone(), &central.topics.planner_results, &id, PlanningStatus::Success(splan)).await { error!("Failed to update client that planning has succeeded: {}", err); }
                debug!("Planning OK");
            }

            // Done
            Ok(())
        }
    }).await {
        Ok(_)    => Ok(()),
        Err(err) => Err(PlanError::KafkaStreamError{ err }),
    }
}
