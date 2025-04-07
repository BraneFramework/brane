//! Module wherein CLIs from other workspace members are imported. Note that this does not include
//! the CLI from xtask itself, which is defined in [`crate::cli`].
#[cfg(feature = "cli")]
use clap::CommandFactory;
use paste::paste;

/// This macro is used to import clap interfaces from other crates in the workspace. Additionally,
/// we create an accessor get_<..>_command which can be used both with and without cli feature
/// flag to obtain the clap::Command (if there is any).
#[macro_export]
macro_rules! include_cli {
    ($x:ident) => {
        #[cfg(feature = "cli")]
        pub(crate) mod $x {
            include!(concat!("../../brane-", stringify!($x), "/src/cli.rs"));
        }
        paste! {
            #[cfg(feature = "cli")]
            pub fn [<get_ $x _command>]() -> Option<clap::Command> {
                Some($x::Cli::command())
            }

            #[cfg(not(feature = "cli"))]
            pub fn [<get_ $x _command>]() -> Option<clap::Command> {
                None
            }
        }
    };
}

include_cli!(ctl);
include_cli!(cli);
include_cli!(cc);
include_cli!(reg);
include_cli!(api);
include_cli!(plr);
include_cli!(prx);
include_cli!(job);
include_cli!(drv);

// who named one of our packages 'let'...?
pub(crate) mod blet {
    include!("../../brane-let/src/cli.rs");
}

#[cfg(feature = "cli")]
pub fn get_let_command() -> Option<clap::Command> { Some(blet::Cli::command()) }

#[cfg(not(feature = "cli"))]
pub fn get_let_command() -> Option<clap::Command> { None }
