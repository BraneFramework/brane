//  ERRORS.rs
//    by Lut99
//
//  Created:
//    10 May 2023, 16:35:29
//  Last edited:
//    10 May 2023, 16:45:29
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines commonly used functions and structs relating to error
//!   handling.
//

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FResult};


/***** AUXILLARY *****/
/// Defines the formatter used in the [`ErrorTrace`] trait.
#[derive(Debug)]
pub struct ErrorTraceFormatter<'e> {
    /// The error to format.
    err: &'e dyn Error,
}
impl Display for ErrorTraceFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        // We can always serialize the error itself
        write!(f, "{}", self.err)?;

        // If it has a source, recurse to print them all
        if let Some(source) = self.err.source() {
            write!(f, "\n\nCaused by:")?;

            // Write them all
            let mut i: usize = 1;
            let mut source: Option<&dyn Error> = Some(source);
            while let Some(err) = source {
                write!(f, "\n  {i}) {err}")?;
                source = err.source();
                i += 1;
            }
        }

        // Done!
        Ok(())
    }
}





/***** LIBRARY *****/
/// Implements a function over a normal [`Error`] that prints it and any [`Error::source()`] it has.
pub trait ErrorTrace: Error {
    /// Returns a formatter that writes the error to the given formatter, with any sources it has.
    ///
    /// # Returns
    /// A new [`ErrorTraceFormatter`] that can write this error and its sources.
    fn trace(&self) -> ErrorTraceFormatter;
}

// We auto-implement [`ErrorTrace`] for everything [`Error`]
impl<T: Error> ErrorTrace for T {
    #[inline]
    fn trace(&self) -> ErrorTraceFormatter { ErrorTraceFormatter { err: self } }
}
