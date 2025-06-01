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




pub mod confidentiality {
    use std::process::ExitCode;

    use error_trace::ErrorTrace as _;
    use rand::RngCore as _;

    #[derive(Debug, Clone)]
    pub enum ConfidentialityKind {
        Confidential,
        Public,
    }

    pub trait ConfidentialError {
        fn identifier(&self) -> u64;
        fn generate_identifier() -> u64 { rand::rng().next_u64() }
    }

    /// Note: that this error is lazy. It does nothing unless you convert it to another type. Therefore
    /// it is must use.
    #[derive(Debug)]
    #[must_use]
    pub struct HttpError {
        pub confidentiality: ConfidentialityKind,
        pub identifier: u64,
        pub msg: String,
        pub err: Option<Box<dyn std::error::Error>>,

        // Http specific fields
        pub status_code: http::StatusCode,
    }

    impl ConfidentialError for HttpError {
        fn identifier(&self) -> u64 { self.identifier }
    }

    impl HttpError {
        pub fn new(msg: String, err: Box<dyn std::error::Error>, status_code: http::StatusCode) -> Self {
            Self { confidentiality: ConfidentialityKind::Confidential, identifier: Self::generate_identifier(), msg, status_code, err: Some(err) }
        }

        pub fn from_error<E>(err: E, status_code: http::StatusCode) -> Self
        where
            E: std::error::Error + 'static,
            E: Sized,
        {
            Self {
                confidentiality: ConfidentialityKind::Confidential,
                identifier: Self::generate_identifier(),
                msg: format!("{err}"),
                err: Some(Box::new(err)),
                status_code,
            }
        }

        pub fn expose(mut self) -> Self {
            self.confidentiality = ConfidentialityKind::Public;
            self
        }
    }

    #[derive(Debug)]
    #[must_use]
    pub struct BinaryError {
        pub confidentiality: ConfidentialityKind,
        pub identifier: u64,
        pub msg: String,
        pub err: Option<Box<dyn std::error::Error>>,

        // Binary specific fields
        pub exit_code: ExitCode,
    }

    impl ConfidentialError for BinaryError {
        fn identifier(&self) -> u64 { self.identifier }
    }

    impl BinaryError {
        pub fn new(msg: String, err: Option<Box<dyn std::error::Error>>, exit_code: ExitCode) -> Self {
            Self { confidentiality: ConfidentialityKind::Public, identifier: Self::generate_identifier(), msg, err, exit_code }
        }

        pub fn without_source(msg: String) -> Self {
            Self {
                confidentiality: ConfidentialityKind::Public,
                identifier: Self::generate_identifier(),
                msg,
                err: None,
                exit_code: ExitCode::FAILURE,
            }
        }

        pub fn from_error<E>(msg: String, err: E) -> Self
        where
            E: std::error::Error + 'static,
            E: Sized,
        {
            Self {
                confidentiality: ConfidentialityKind::Public,
                identifier: Self::generate_identifier(),
                msg,
                err: Some(Box::new(err)),
                exit_code: ExitCode::FAILURE,
            }
        }
    }

    #[cfg(feature = "axum")]
    impl axum::response::IntoResponse for HttpError {
        fn into_response(self) -> axum::response::Response {
            let status_code = self.status_code;
            tracing::error!("{}", self.to_log_message());
            match self.confidentiality {
                ConfidentialityKind::Confidential => {
                    // TODO: Create random identifier, surface it and log it so we can relate a user
                    // error to our logs
                    (status_code, self.msg).into_response()
                },
                ConfidentialityKind::Public => {
                    let msg = match self.err {
                        Some(err) => err.trace().to_string(),
                        None => self.msg,
                    };
                    tracing::error!("Returned an error:\n{msg}");
                    (status_code, msg).into_response()
                },
            }
        }
    }

    impl HttpError {
        pub fn to_log_message(&self) -> String {
            match self.confidentiality {
                ConfidentialityKind::Confidential => {
                    // TODO: Create random identifier, surface it and log it so we can relate a user
                    // error to our logs
                    format!("Returned a confidential error: {msg}", msg = self.msg)
                },
                ConfidentialityKind::Public => match &self.err {
                    Some(err) => format!("{msg}\n{err}", msg = self.msg, err = err.trace()),
                    None => self.msg.clone(),
                },
            }
        }
    }
}
