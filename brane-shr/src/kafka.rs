//  KAFKA.rs
//    by Lut99
// 
//  Created:
//    09 Nov 2022, 11:09:12
//  Last edited:
//    09 Nov 2022, 11:11:38
//  Auto updated?
//    Yes
// 
//  Description:
//!   Implements a few Kafka-related functions.
// 

use std::fmt::{Display, Formatter, Result as FResult};

use tracing::{debug, info};
use rdkafka::{ClientConfig, Offset, TopicPartitionList};
use rdkafka::admin::{AdminClient, AdminOptions, NewTopic, TopicReplication, TopicResult};
use rdkafka::consumer::Consumer;
use rdkafka::consumer::stream_consumer::StreamConsumer;
use rdkafka::error::RDKafkaErrorCode;
use rdkafka::util::Timeout;


/***** ERRORS *****/
/// Defines errors that relate to Kafka helpers.
#[derive(Debug)]
pub enum Error {
    /// Failed to create a new admin client to the given brokers.
    AdminClientError{ brokers: String, err: rdkafka::error::KafkaError },
    /// failed to send the command to create new Kafka topics.
    TopicsCreateError{ brokers: String, err: rdkafka::error::KafkaError },
    /// Failed to create a new Kafka topic.
    TopicCreateError{ brokers: String, topic: String, err: rdkafka::error::RDKafkaErrorCode },

    /// Failed to retrieve the offsets for a certain topic.
    OffsetsRetrieveError{ topic: String, err: rdkafka::error::KafkaError },
    /// Failed to assign the offsets for a certain topic to the topic partition list.
    OffsetsAssignError{ topic: String, err: rdkafka::error::KafkaError },
    /// Failed to do the final restore for the offsets of a certain topic.
    OffsetsRestoreError{ topic: String, err: rdkafka::error::KafkaError },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            AdminClientError{ brokers, err }        => write!(f, "Failed to create admin client to Kafka brokers '{brokers}': {err}"),
            TopicsCreateError{ brokers, err }       => write!(f, "Failed to create new topics on Kafka brokers '{brokers}': {err}"),
            TopicCreateError{ brokers, topic, err } => write!(f, "Failed to create new topic '{topic}' on Kafka brokers '{brokers}': {err}"),

            OffsetsRetrieveError{ topic, err } => write!(f, "Failed to retrieve committed offsets for topic '{topic}': {err}"),
            OffsetsAssignError{ topic, err }   => write!(f, "Failed to assign committed offsets for topic '{topic}': {err}"),
            OffsetsRestoreError{ topic, err }  => write!(f, "Failed to restore committed offsets for topic '{topic}': {err}"),
        }
    }
}

impl std::error::Error for Error {}





/***** LIBRARY *****/
/// Ensures that the given topics are registered with the underlying Kafka subsystem.
/// 
/// # Arguments
/// - `topics`: The list of topics to register.
/// - `brokers`: The (comma-separated list) of brokers to register them with.
/// 
/// # Errors
/// This function may error if we failed to ensure the topics. This is likely due to the brokers not being available.
pub async fn ensure_topics(topics: Vec<&str>, brokers: &str) -> Result<(), Error> {
    // Connect with admin rights
    let admin_client: AdminClient<_> = match ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .create()
    {
        Ok(client) => client,
        Err(err)   => { return Err(Error::AdminClientError { brokers: brokers.into(), err }); }
    };

    // Parse the list of topics as Kafka structures
    let topics: Vec<NewTopic> = topics
        .iter()
        .map(|t| NewTopic::new(t, 1, TopicReplication::Fixed(1)))
        .collect();

    // Run them
    let results: Vec<TopicResult> = match admin_client.create_topics(topics.iter(), &AdminOptions::new()).await {
        Ok(results) => results,
        Err(err)    => { return Err(Error::TopicsCreateError{ brokers: brokers.into(), err }); },
    };

    // Report on the results. Don't consider 'TopicAlreadyExists' an error.
    for result in results {
        match result {
            Ok(topic)           => info!("Kafka topic '{}' created.", topic),
            Err((topic, error)) => match error {
                // Do not error on topics that already exist
                RDKafkaErrorCode::TopicAlreadyExists => {
                    info!("Kafka topic '{}' already exists.", topic);
                }
                // Otherwise, do
                err => {
                    return Err(Error::TopicCreateError{ brokers: brokers.into(), topic, err });
                }
            },
        }
    }

    // Done
    Ok(())
}



/// Restores the commit offsets to the given Kafka consumer.
/// 
/// # Arguments
/// - `consumer`: The Kafka consumer who's offsets we want to restore.
/// - `topic`: The topic for which to restore them.
/// 
/// # Errors
/// This function errors if we failed doing so.
pub fn restore_committed_offsets(consumer: &StreamConsumer, topic: impl AsRef<str>) -> Result<(), Error> {
    let topic: &str = topic.as_ref();

    // Define the topic partition list for which to retrieve offsets
    let mut tpl = TopicPartitionList::new();
    tpl.add_partition(topic, 0);

    // Retrieve the offsets
    let committed_offsets = match consumer.committed_offsets(tpl.clone(), Timeout::Never) {
        Ok(offsets) => offsets,
        Err(err)    => { return Err(Error::OffsetsRetrieveError{ topic: topic.into(), err }); },
    };
    let committed_offsets = committed_offsets.to_topic_map();

    // Set the offsets to the topic partition list
    if let Some(offset) = committed_offsets.get(&(topic.into(), 0)) {
        if let Err(err) = match offset {
            Offset::Invalid => tpl.set_partition_offset(topic, 0, Offset::Beginning),
            offset          => tpl.set_partition_offset(topic, 0, *offset),
        } {
            return Err(Error::OffsetsAssignError{ topic: topic.into(), err });
        };
    }

    // Finally, do the restoring
    debug!("Restoring commited offsets: {:?}", &tpl);
    match consumer.assign(&tpl) {
        Ok(_)    => Ok(()),
        Err(err) => Err(Error::OffsetsRestoreError{ topic: topic.into(), err }),
    }
}
