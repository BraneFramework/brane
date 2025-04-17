use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{KeyValue, global};
use opentelemetry_otlp::{WithExportConfig as _, WithTonicConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{MeterProviderBuilder, PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_semantic_conventions::SCHEMA_URL;
use opentelemetry_semantic_conventions::attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_NAME, SERVICE_VERSION};
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_opentelemetry::{MetricsLayer, OpenTelemetryLayer};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

pub fn setup_subscriber(log_level_env_var: &str, default_log_level: LevelFilter) {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var(log_level_env_var)
                .with_default_directive(default_log_level.into())
                .from_env_lossy(),
        )
        .init();

    info!("Logger initiated with log level {}", std::env::var(log_level_env_var).unwrap_or(default_log_level.to_string()));
}

fn resource() -> Resource {
    Resource::builder()
        .with_schema_url(
            [
                KeyValue::new(SERVICE_NAME, env!("CARGO_PKG_NAME")),
                KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
                KeyValue::new(DEPLOYMENT_ENVIRONMENT_NAME, "develop"),
            ],
            SCHEMA_URL,
        )
        .build()
}

fn init_meter_provider() -> SdkMeterProvider {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_temporality(opentelemetry_sdk::metrics::Temporality::default())
        .build()
        .unwrap();

    let reader = PeriodicReader::builder(exporter).with_interval(std::time::Duration::from_secs(30)).build();

    // For debugging in development
    let stdout_reader = PeriodicReader::builder(opentelemetry_stdout::MetricExporter::default()).build();

    let meter_provider = MeterProviderBuilder::default().with_resource(resource()).with_reader(reader).with_reader(stdout_reader).build();

    global::set_meter_provider(meter_provider.clone());

    meter_provider
}

// Construct TracerProvider for OpenTelemetryLayer
fn init_tracer_provider() -> SdkTracerProvider {
    // let mut metadata = tonic::metadata::MetadataMap::new();
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint("http://localhost:4318/v1/traces")
        // Our endpoint
        // .with_tonic()
        // .with_endpoint("localhost:4317")
        // .with_metadata(metadata)
        .build().unwrap();

    SdkTracerProvider::builder()
        // Customize sampling strategy
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            1.0,
        ))))
        // If export trace to AWS X-Ray, you can use XrayIdGenerator
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource())
        .with_batch_exporter(exporter)
        // .with_simple_exporter(exporter)
        .build()
}

pub fn setup_subscriber_with_otel(log_level_env_var: &str, default_log_level: LevelFilter) -> OtelGuard {
    let tracer_provider = init_tracer_provider();
    let meter_provider = init_meter_provider();
    let tracer = tracer_provider.tracer("readme_example");

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(MetricsLayer::new(meter_provider.clone()))
        .with(OpenTelemetryLayer::new(tracer))
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var(log_level_env_var)
                .with_default_directive(default_log_level.into())
                .from_env_lossy(),
        )
        .init();

    info!("Logger initiated with log level {}", std::env::var(log_level_env_var).unwrap_or(default_log_level.to_string()));
    info!("Open telemetry connected");

    OtelGuard { tracer_provider, meter_provider }
}

pub struct OtelGuard {
    tracer_provider: SdkTracerProvider,
    meter_provider:  SdkMeterProvider,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        eprintln!("Deinitializing opentelemetry");
        if let Err(err) = self.tracer_provider.shutdown() {
            eprintln!("{err:?}");
        }
        if let Err(err) = self.meter_provider.shutdown() {
            eprintln!("{err:?}");
        }
    }
}
