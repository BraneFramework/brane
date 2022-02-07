use anyhow::{bail, Context, Result};
use brane_bvm::vm::VmState;
use brane_cfg::Infrastructure;
use brane_drv::grpc::DriverServiceServer;
use brane_drv::handler::DriverHandler;
use brane_job::interface::{Event, EventKind};
use brane_shr::jobs::JobStatus;
// use clap::Parser;
use brane_drv::errors::DriverError;
use structopt::StructOpt;
use dashmap::DashMap;
use dotenv::dotenv;
use futures::TryStreamExt;
use log::info;
use log::LevelFilter;
use prost::Message as _;
use rdkafka::{
    admin::{AdminClient, AdminOptions, NewTopic, TopicReplication},
    consumer::{Consumer, StreamConsumer},
    error::RDKafkaErrorCode,
    producer::FutureProducer,
    util::Timeout,
    ClientConfig, Message as _, Offset, TopicPartitionList
};
use specifications::common::Value as SpecValue;
use specifications::common::Value;
use std::sync::Arc;
use tonic::transport::Server;

/* TIM */
// #[derive(Parser)]
// #[clap(version = env!("CARGO_PKG_VERSION"))]
// struct Opts {
//     #[clap(long, default_value = "http://127.0.0.1:8080/graphql", env = "GRAPHQL_URL")]
//     graphql_url: String,
//     #[clap(short, long, default_value = "127.0.0.1:50053", env = "ADDRESS")]
//     /// Service address
//     address: String,
//     /// Kafka brokers
//     #[clap(short, long, default_value = "localhost:9092", env = "BROKERS")]
//     brokers: String,
//     /// Topic to send commands to
//     #[clap(short, long = "cmd-topic", default_value = "drv-cmd", env = "COMMAND_TOPIC")]
//     command_topic: String,
//     /// Topic to recieve events from
//     #[clap(short, long = "evt-topic", default_value = "job-evt", env = "EVENT_TOPIC")]
//     event_topic: String,
//     /// Print debug info
//     #[clap(short, long, env = "DEBUG", takes_value = false)]
//     debug: bool,
//     /// Consumer group id
//     #[clap(short, long, default_value = "brane-drv")]
//     group_id: String,
//     /// Infra metadata store
//     #[clap(short, long, default_value = "./infra.yml", env = "INFRA")]
//     infra: String,
// }

#[derive(StructOpt)]
struct Opts {
    /// GraphQL address
    #[structopt(long, default_value = "http://127.0.0.1:8080/graphql", env = "GRAPHQL_URL")]
    graphql_url: String,
    /// Service address
    #[structopt(short, long, default_value = "127.0.0.1:50053", env = "ADDRESS")]
    address: String,
    /// Kafka brokers
    #[structopt(short, long, default_value = "localhost:9092", env = "BROKERS")]
    brokers: String,
    /// Topic to send commands to
    #[structopt(short, long = "cmd-topic", default_value = "drv-cmd", env = "COMMAND_TOPIC")]
    command_topic: String,
    /// Topic to recieve events from
    #[structopt(short, long = "evt-topic", default_value = "job-evt", env = "EVENT_TOPIC")]
    event_topic: String,
    /// Print debug info
    #[structopt(short, long, env = "DEBUG", takes_value = false)]
    debug: bool,
    /// Consumer group id
    #[structopt(short, long, default_value = "brane-drv")]
    group_id: String,
    /// Infra metadata store
    #[structopt(short, long, default_value = "./infra.yml", env = "INFRA")]
    infra: String,
}
/*******/

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    // let opts = Opts::parse();
    let opts = Opts::from_args();

    // Configure logger.
    let mut logger = env_logger::builder();
    logger.format_module_path(false);

    if opts.debug {
        logger.filter_level(LevelFilter::Debug).init();
    } else {
        logger.filter_level(LevelFilter::Info).init();
    }

    // Ensure that the input/output topics exists.
    let command_topic = opts.command_topic.clone();
    if let Err(reason) = ensure_topics(vec![&command_topic, &opts.event_topic], &opts.brokers).await {
        log::error!("{}", reason);
        std::process::exit(-1);
    };

    let infra = Infrastructure::new(opts.infra.clone())?;
    infra.validate()?;

    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &opts.brokers)
        .set("message.timeout.ms", "5000")
        .create()
        .context("Failed to create Kafka producer.")?;

    // Start event monitor in the background.
    let states: Arc<DashMap<String, JobStatus>> = Arc::new(DashMap::new());
    let results: Arc<DashMap<String, Value>> = Arc::new(DashMap::new());
    let locations: Arc<DashMap<String, String>> = Arc::new(DashMap::new());

    tokio::spawn(start_event_monitor(
        opts.brokers.clone(),
        opts.group_id.clone(),
        opts.event_topic.clone(),
        states.clone(),
        results.clone(),
        locations.clone(),
    ));

    let graphql_url = opts.graphql_url.clone();
    let sessions: Arc<DashMap<String, VmState>> = Arc::new(DashMap::new());
    let handler = DriverHandler {
        command_topic,
        graphql_url,
        producer,
        results,
        sessions,
        states,
        locations,
        infra,
    };

    // Start gRPC server with callback service.
    Server::builder()
        .add_service(DriverServiceServer::new(handler))
        .serve(opts.address.parse()?)
        .await
        .context("Failed to start callback gRPC server.")
}

/* TIM */
/// **Edited: now returning ExecutorErrors.**
///
/// Makes sure the required topics are present and watched in the local Kafka server.
/// 
/// **Arguments**
///  * `topics`: The list of topics to make sure they exist of.
///  * `brokers`: The string list of Kafka servers that act as the brokers.
/// 
/// **Returns**  
/// Nothing on success, or an ExecutorError otherwise.
async fn ensure_topics(
    topics: Vec<&str>,
    brokers: &str,
) -> Result<(), DriverError> {
    // Connect with an admin client
    let admin_client: AdminClient<_> = match ClientConfig::new().set("bootstrap.servers", brokers) .create() {
        Ok(client)  => client,
        Err(reason) => { return Err(DriverError::KafkaClientError{ servers: brokers.to_string(), err: reason }); }
    };

    // Collect the topics to create and then create them
    let ktopics: Vec<NewTopic> = topics
        .iter()
        .map(|t| NewTopic::new(t, 1, TopicReplication::Fixed(1)))
        .collect();
    let results = match admin_client.create_topics(ktopics.iter(), &AdminOptions::new()).await {
        Ok(results) => results,
        Err(reason) => { return Err(DriverError::KafkaTopicsError{ topics: DriverError::serialize_vec(&topics), err: reason }); }
    };

    // Report on the results. Don't consider 'TopicAlreadyExists' an error.
    for result in results {
        match result {
            Ok(topic) => info!("Kafka topic '{}' created.", topic),
            Err((topic, error)) => match error {
                RDKafkaErrorCode::TopicAlreadyExists => {
                    info!("Kafka topic '{}' already exists", topic);
                }
                _ => { return Err(DriverError::KafkaTopicError{ topic: topic, err: error }); }
            },
        }
    }

    Ok(())
}
/*******/

///
///
///
async fn start_event_monitor(
    brokers: String,
    group_id: String,
    topic: String,
    states: Arc<DashMap<String, JobStatus>>,
    results: Arc<DashMap<String, Value>>,
    locations: Arc<DashMap<String, String>>,
) -> Result<()> {
    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", group_id)
        .set("bootstrap.servers", brokers)
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", "6000")
        .set("enable.auto.commit", "true")
        .create()
        .context("Failed to create Kafka consumer.")?;

    // Restore previous topic/partition offset.
    let mut tpl = TopicPartitionList::new();
    tpl.add_partition(&topic, 0);

    let committed_offsets = consumer.committed_offsets(tpl.clone(), Timeout::Never)?;
    let committed_offsets = committed_offsets.to_topic_map();
    if let Some(offset) = committed_offsets.get(&(topic.clone(), 0)) {
        match offset {
            Offset::Invalid => tpl.set_partition_offset(&topic, 0, Offset::Beginning)?,
            offset => tpl.set_partition_offset(&topic, 0, *offset)?,
        };
    }

    info!("Restoring commited offsets: {:?}", &tpl);
    consumer
        .assign(&tpl)
        .context("Failed to manually assign topic, partition, and/or offset to consumer.")?;

    consumer
        .stream()
        .try_for_each(|borrowed_message| {
            let owned_message = borrowed_message.detach();
            let owned_states = states.clone();
            let owned_results = results.clone();
            let owned_locations = locations.clone();

            async move {
                if let Some(payload) = owned_message.payload() {
                    // Decode payload into a Event message.
                    let event = Event::decode(payload).unwrap();
                    let kind = EventKind::from_i32(event.kind).unwrap();

                    let event_id: Vec<_> = event.identifier.split('-').collect();
                    let correlation_id = event_id.first().unwrap().to_string();

                    match kind {
                        EventKind::Created => {
                            owned_states.insert(correlation_id.clone(), JobStatus::Created);
                            owned_locations.insert(correlation_id, event.location.clone());
                        }
                        EventKind::Ready => {
                            owned_states.insert(correlation_id, JobStatus::Ready);
                        }
                        EventKind::Initialized => {
                            owned_states.insert(correlation_id, JobStatus::Initialized);
                        }
                        EventKind::Started => {
                            owned_states.insert(correlation_id, JobStatus::Started);
                        }
                        EventKind::Finished => {
                            let payload = String::from_utf8_lossy(&event.payload).to_string();
                            let value: SpecValue = serde_json::from_str(&payload).unwrap();

                            // Using these two hashmaps is not ideal, they lock and we're dependend on polling (from call future).
                            // NOTE: for now we have to make sure the results are inserted before the state becomes "finished" to prevent race conditions.
                            owned_results.insert(correlation_id.clone(), value);
                            owned_states.insert(correlation_id, JobStatus::Finished);
                        }
                        EventKind::Stopped => {
                            owned_states.insert(correlation_id, JobStatus::Stopped);
                        }
                        EventKind::Failed => {
                            owned_states.insert(correlation_id, JobStatus::Failed);
                        }
                        _ => {
                            unreachable!();
                        }
                    }
                }

                Ok(())
            }
        })
        .await?;

    Ok(())
}
