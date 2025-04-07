#[cfg(feature = "cli")]
use clap::CommandFactory;
use paste::paste;

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
