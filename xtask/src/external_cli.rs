#[macro_export]
macro_rules! include_cli {
    ($x:ident) => {
        pub(crate) mod $x {
            //! test
            include!(concat!("../../brane-", stringify!($x), "/src/cli.rs"));
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
