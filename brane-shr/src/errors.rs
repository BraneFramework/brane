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

#[derive(Debug, Clone)]
pub enum ConfidentialityKind {
    Confidential(String),
    Public,
}

#[derive(Debug)]
pub struct SurfacableError {
    pub confidentiality: ConfidentialityKind,
    pub status_code: http::StatusCode,
    pub err: Box<dyn std::error::Error>,
}

// impl std::error::Error for SurfacableError {
//     fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(self.err.as_ref()) }
// }
//
// // FIXME: implement
// impl std::fmt::Display for SurfacableError {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { todo!() }
// }
#[cfg(feature = "axum")]
use error_trace::ErrorTrace as _;

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for SurfacableError {
    fn into_response(self) -> axum::response::Response {
        match self.confidentiality {
            ConfidentialityKind::Confidential(msg) => {
                // TODO: Create random identifier, surface it and log it so we can relate a user
                // error to our logs
                tracing::error!("Returned a confidential error: {msg}\n\nError:{}", self.err.freeze());
                (self.status_code, msg).into_response()
            },
            ConfidentialityKind::Public => {
                tracing::error!("Returned an error:\n{}", self.err.freeze());
                (self.status_code, self.err.trace().to_string()).into_response()
            },
        }
    }
}
