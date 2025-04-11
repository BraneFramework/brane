use brane_cc::spec::IndexLocation;
use brane_dsl::Language;
use clap::Parser;

/// An offline compiler for BraneScript/Bakery to Workflows.
#[derive(Parser)]
#[clap(name = "branec", version, author)]
pub(crate) struct Cli {
    /// If given, shows debug prints.
    #[clap(long, help = "If given, shows INFO- and DEBUG-level prints in the log.", env = "DEBUG")]
    pub(crate) debug: bool,
    /// If given, shows additional trace prints.
    #[clap(long, help = "If given, shows TRACE-level prints in the log. Implies '--debug'", env = "TRACE")]
    pub(crate) trace: bool,

    /// The file(s) to compile. May be '-' to compile from stdin.
    #[clap(name = "FILES", help = "The input files to compile. Use '-' to read from stdin.")]
    pub(crate) files:    Vec<String>,
    /// The output file to write to.
    #[clap(short, long, default_value = "-", help = "The output file to compile to. Use '-' to write to stdout.")]
    pub(crate) output:   String,
    /// The path / address of the packages index.
    #[clap(
        short,
        long,
        default_value = "~/.local/share/brane/packages",
        help = "The location to read the package index from. If it's a path, reads it from the local machine; if it's an address, attempts to read \
                it from the Brane instance instead. You can wrap your input in 'Local<...>' or 'Remote<...>' to disambiguate between the two."
    )]
    pub(crate) packages: IndexLocation,
    /// The path / address of the data index.
    #[clap(
        short,
        long,
        default_value = "~/.local/share/brane/data",
        help = "The location to read the data index from. If it's a path, reads it from the local machine; if it's an address, attempts to read it \
                from the Brane instance instead. You can wrap your input in 'Local<...>' or 'Remote<...>' to disambiguate between the two."
    )]
    pub(crate) data:     IndexLocation,
    /// If given, reads the packages and data in test mode, which simplifies how to interpret them since we won't be executing them.
    #[clap(
        short,
        long,
        help = "If given, reads packages and data simplified as found in the `tests` folder in the Brane repository. This can be done because the \
                packages won't be executed."
    )]
    pub(crate) raw:      bool,

    /// If given, does the stream thing
    #[clap(
        short,
        long,
        help = "If given, enters so-called _streaming mode_. This effectively emulates a REPL, where files may be given on stdin indefinitely \
                (separated by EOF, Ctrl+D). Each file is compiled as soon as it is completely received, and the workflow for that file is written \
                to the output file. Workflows can use definitions made in pervious workflows, just like a REPL."
    )]
    pub(crate) stream:   bool,
    /// Determines the input language of the source.
    #[clap(short, long, default_value = "bscript", help = "Determines the language of the input files.")]
    pub(crate) language: Language,
    /// If given, writes the output JSON to use as little whitespace as possible.
    #[clap(
        short,
        long,
        help = "If given, writes the output JSON in minimized format (i.e., with as little whitespace as possible). Not really readable, but \
                perfect for transmitting it to some other program."
    )]
    pub(crate) compact:  bool,
    /// If given, does not output JSON but instead outputs an assembly-like variant of a workflow.
    #[clap(
        short = 'P',
        long,
        help = "If given, does not output JSON but instead outputs an assembly-like variant of a workflow. Not really readable by machines, but \
                easier to understand by a human (giving this ignores --compact)."
    )]
    pub(crate) pretty:   bool,
}
