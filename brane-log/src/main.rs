use anyhow::Result;
use brane_log::ingestion;
use brane_log::schema::{Event, Query, Subscription};
use brane_log::{Context, Schema};
use clap::Parser;
use dotenvy::dotenv;
use futures::FutureExt;
use juniper::{self, EmptyMutation};
use juniper_graphql_ws::ConnectionConfig;
use juniper_warp::{playground_filter, subscriptions::serve_graphql_ws};
use tracing::LevelFilter;
use scylla::transport::Compression;
use scylla::{Session, SessionBuilder};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;
use warp::ws::Ws;
use warp::Filter;

#[derive(Parser)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
struct Opts {
    #[clap(short, long, default_value = "127.0.0.1:8081", env = "ADDRESS")]
    /// Service address
    address: String,
    /// Scylla endpoint
    #[clap(short, long, default_value = "127.0.0.1", env = "SCYLLA")]
    scylla: String,
    /// Kafka brokers
    #[clap(short, long, default_value = "127.0.0.1:9092", env = "BROKERS")]
    brokers: String,
    /// Print debug info
    #[clap(short, long, action, env = "DEBUG")]
    debug: bool,
    /// Topic to receive events from
    #[clap(short, long = "evt-topics", env = "EVENT_TOPIC")]
    event_topics: Vec<String>,
    /// Consumer group id
    #[clap(short, long, default_value = "brane-log", env = "GROUP_ID")]
    group_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let opts = Opts::parse();

    // Configure logger.
    let mut logger = env_logger::builder();
    logger.format_module_path(false);

    if opts.debug {
        logger.filter_level(LevelFilter::Debug).init();
    } else {
        logger.filter_level(LevelFilter::Info).init();
    }

    // Configure internal event watcher (used for subscriptions).
    let (events_tx, events_rx) = watch::channel(Event::default());

    // Configure Scylla cluster connection.
    let scylla_session: Session = SessionBuilder::new()
        .known_node(opts.scylla)
        .compression(Some(Compression::Snappy))
        .build()
        .await?;

    // Ensure Scylla keyspace and table.
    ingestion::ensure_db_keyspace(&scylla_session).await?;
    ingestion::ensure_db_tables(&scylla_session).await?;

    let scylla_session = Arc::new(scylla_session);

    // Spawn a single event ingestion worker.
    tokio::spawn(ingestion::start_worker(
        opts.brokers.clone(),
        opts.group_id.clone(),
        opts.event_topics.clone(),
        events_tx,
        scylla_session.clone(),
    ));

    let events = events_rx.clone();

    // Configure Wrap web server.
    let schema = Schema::new(Query {}, EmptyMutation::new(), Subscription {});

    let context_scylla = scylla_session.clone();
    let context_events_rx = events_rx.clone();
    let context = warp::any().map(move || Context {
        scylla: context_scylla.clone(),
        events_rx: context_events_rx.clone(),
    });

    let graphql_filter = juniper_warp::make_graphql_filter(schema, context.boxed());
    let root_node = Arc::new(Schema::new(Query {}, EmptyMutation::new(), Subscription {}));

    let routes = (warp::path("subscriptions").and(warp::ws()).map(move |ws: Ws| {
        let root_node = root_node.clone();
        let events = events.clone();
        let scylla = scylla_session.clone();

        ws.on_upgrade(move |websocket| async move {
            serve_graphql_ws(
                websocket,
                root_node,
                ConnectionConfig::new(Context {
                    scylla,
                    events_rx: events,
                }),
            )
            .map(|r| {
                if let Err(e) = r {
                    println!("Websocket error: {e}");
                }
            })
            .await
        })
    }))
    .map(|reply| {
        // TODO#584: remove this workaround
        warp::reply::with_header(reply, "Sec-WebSocket-Protocol", "graphql-ws")
    })
    .or(warp::post().and(warp::path("graphql")).and(graphql_filter))
    .or(warp::get()
        .and(warp::path("playground"))
        .and(playground_filter("/graphql", Some("/subscriptions"))))
    .with(warp::trace::request());

    let address: SocketAddr = opts.address.clone().parse()?;
    warp::serve(routes).run(address).await;

    Ok(())
}
