use clap::Parser;
use tracing::Level;
use tracing::level_filters::LevelFilter;

#[derive(Debug, Parser)]
pub struct Tracing {
    /// If given, prints `info` and `debug` prints.
    #[clap(long, global = true, help = "If given, prints additional information during execution.", group = "verbosity", env = "DEBUG")]
    pub debug: bool,
    /// If given, prints `info`, `debug` and `trace` prints.
    #[clap(long, global = true, help = "If given, prints the largest amount of debug information as possible.", group = "verbosity", env = "TRACE")]
    pub trace: bool,
    /// Logging verbosity `-v` for debug, `-vv` for trace
    #[arg(short, long, global = true, help = "If given, increments the log level by one step.", action = clap::ArgAction::Count, group = "verbosity")]
    pub(crate) verbose: u8,
    /// If given, disables logging levels info and higher.
    #[clap(short, long, global = true, help = "If given, disables info logging", action = clap::ArgAction::Count, group = "verbosity")]
    pub(crate) quiet: u8,
}

impl Tracing {
    // This code is heavily inspired by clap-verbosity-flag crate, however, it did not suit entirely
    // as the trace and debug flags would have been a pain to introduce
    pub fn log_level(&self, default_level: LevelFilter) -> LevelFilter {
        if self.trace {
            return LevelFilter::TRACE;
        } else if self.debug {
            return LevelFilter::DEBUG;
        }

        let numeric_default_level: i16 = match default_level.into_level() {
            Some(Level::TRACE) => 5,
            Some(Level::DEBUG) => 4,
            Some(Level::INFO) => 3,
            Some(Level::WARN) => 2,
            Some(Level::ERROR) => 1,
            None => 0,
        };

        match numeric_default_level.saturating_add(self.verbose.into()).saturating_sub(self.quiet.into()) {
            (..=0) => LevelFilter::OFF,
            1 => LevelFilter::ERROR,
            2 => LevelFilter::WARN,
            3 => LevelFilter::INFO,
            4 => LevelFilter::DEBUG,
            (5..) => LevelFilter::TRACE,
        }
    }
}
