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



/// Helper struct that wraps serde errors to provide better diagnostics
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Failed to deserialize")]
pub struct SerdeError<T: std::fmt::Debug + std::fmt::Display> {
    cause:  T,
    #[source_code]
    input:  String,
    #[label("{cause}")]
    offset: miette::SourceOffset,
}

#[cfg(feature = "yaml")]
impl SerdeError<serde_yaml::Error> {
    pub fn from_yaml(source: String, value: serde_yaml::Error) -> Self {
        let offset = value.location().map(|loc| miette::SourceOffset::from_location(&source, loc.line(), loc.column())).unwrap();
        Self { cause: value, input: source, offset }
    }
}

#[cfg(feature = "json")]
impl SerdeError<serde_json::Error> {
    pub fn from_json(source: String, value: serde_json::Error) -> Self {
        let offset = miette::SourceOffset::from_location(&source, value.line(), value.column());
        Self { cause: value, input: source, offset }
    }
}



pub mod confidentiality {
    use std::collections::HashMap;
    use std::error::Error;
    use std::fmt::Write as _;
    use std::marker::PhantomData;
    use std::process::ExitCode;

    use error_trace::ErrorTrace as _;
    use http::HeaderValue;
    use miette::{Diagnostic, Report};
    use rand::RngCore as _;

    #[derive(Debug, Clone)]
    pub enum Confidentiality {
        /// No details should be shown whatsoever
        FullyConfidential,
        /// Only the first error should be shown
        OnlyMessage,
        /// An alternative message should be shown to the original error
        AlternativeMessage(String),
        /// Show as much information as possible
        Public,
    }

    pub trait ConfidentialError {
        fn identifier(&self) -> u64;
        fn generate_identifier() -> u64 { rand::rng().next_u64() }
    }
    pub trait HttpErrorSerializer {}
    #[derive(Debug)]
    pub struct ProblemDetailsSerializer;
    impl HttpErrorSerializer for ProblemDetailsSerializer {}
    #[derive(Debug)]
    pub struct PlainSerializer;
    impl HttpErrorSerializer for PlainSerializer {}

    /// Note: that this error is lazy. It does nothing unless you convert it to another type. Therefore
    /// it is must use.
    #[derive(Debug)]
    #[must_use]
    pub struct HttpError<S: HttpErrorSerializer = ProblemDetailsSerializer> {
        pub confidentiality: Confidentiality,
        pub identifier: u64,
        pub err: Report,

        // Http specific fields
        pub status_code: http::StatusCode,

        _ser: PhantomData<S>,
    }

    #[derive(Debug)]
    #[must_use]
    pub struct BinaryError {
        pub identifier: u64,
        pub err: Report,

        // Binary specific fields
        pub exit_code: ExitCode,
    }

    pub trait HttpStatus {
        fn status_code(&self) -> http::StatusCode;
    }

    pub trait IntoHttpError<S: HttpErrorSerializer> {
        fn into_http_error(self, confidentiality: Confidentiality) -> HttpError<S>;
    }

    impl<E, S> IntoHttpError<S> for E
    where
        E: Diagnostic + HttpStatus + Send + Sync + 'static,
        S: HttpErrorSerializer,
    {
        fn into_http_error(self, confidentiality: Confidentiality) -> HttpError<S> {
            let status_code = self.status_code();
            HttpError { confidentiality, identifier: <HttpError<S>>::generate_identifier(), err: Report::new(self), status_code, _ser: PhantomData }
        }
    }

    pub trait IntoExitCode {
        fn exit_code(&self) -> ExitCode;
    }

    pub trait IntoBinaryError {
        fn into_binary_error(self) -> BinaryError;
    }

    impl<E> IntoBinaryError for E
    where
        E: Diagnostic + Send + Sync + 'static,
    {
        fn into_binary_error(self) -> BinaryError {
            // TODO: Use IntoExitCode
            // let exit_code = self.exit_code();
            BinaryError::new_from_diagnostic(Box::new(self), ExitCode::FAILURE)
        }
    }

    impl<S: HttpErrorSerializer> ConfidentialError for HttpError<S> {
        fn identifier(&self) -> u64 { self.identifier }
    }

    impl<S: HttpErrorSerializer> HttpError<S> {
        pub fn new_from_error(confidentiality: Confidentiality, err: Box<dyn Error + Send + Sync>, status_code: http::StatusCode) -> Self {
            Self { confidentiality, identifier: Self::generate_identifier(), status_code, err: Report::new_boxed(err.into()), _ser: PhantomData }
        }

        pub fn new_from_diagnostic(confidentiality: Confidentiality, err: Box<dyn Diagnostic + Send + Sync>, status_code: http::StatusCode) -> Self {
            Self { confidentiality, identifier: Self::generate_identifier(), status_code, err: Report::new_boxed(err), _ser: PhantomData }
        }

        pub fn new_from_report(confidentiality: Confidentiality, err: Report, status_code: http::StatusCode) -> Self {
            Self { confidentiality, identifier: Self::generate_identifier(), status_code, err, _ser: PhantomData }
        }

        pub fn expose(mut self) -> Self {
            self.confidentiality = Confidentiality::Public;
            self
        }

        pub fn message(&self) -> String {
            match self.confidentiality {
                Confidentiality::AlternativeMessage(ref message) => message.clone(),
                Confidentiality::OnlyMessage | Confidentiality::Public => format!("{}", self.err),
                Confidentiality::FullyConfidential => "Error message has been redacted".to_owned(),
            }
        }
    }

    impl ConfidentialError for BinaryError {
        fn identifier(&self) -> u64 { self.identifier }
    }

    impl BinaryError {
        pub fn new_from_error(err: Box<dyn Error + Send + Sync>, exit_code: ExitCode) -> Self {
            Self { identifier: Self::generate_identifier(), err: Report::new_boxed(err.into()), exit_code }
        }

        pub fn new_from_diagnostic(err: Box<dyn Diagnostic + Send + Sync>, exit_code: ExitCode) -> Self {
            Self { identifier: Self::generate_identifier(), err: Report::new_boxed(err), exit_code }
        }

        pub fn new_from_report(err: Report, exit_code: ExitCode) -> Self { Self { identifier: Self::generate_identifier(), err, exit_code } }
    }

    #[cfg(feature = "axum")]
    impl axum::response::IntoResponse for HttpError<PlainSerializer> {
        fn into_response(self) -> axum::response::Response {
            let status_code = self.status_code;
            self.log();

            let mut message = self.message();

            if let Confidentiality::Public = self.confidentiality {
                writeln!(&mut message, "\nCaused by: {trace}", trace = self.err.trace()).expect("Writing to string should never fail");
            }

            writeln!(&mut message, "\nIdentifier: {id}", id = self.identifier).expect("Writing to string should never fail");
            (status_code, message).into_response()
        }
    }

    #[cfg(feature = "problem-details")]
    #[cfg(feature = "axum")]
    impl axum::response::IntoResponse for HttpError<ProblemDetailsSerializer> {
        fn into_response(self) -> axum::response::Response {
            let mut response = (self.status_code, axum::Json(self.into_problem_details())).into_response();
            response.headers_mut().insert(http::header::CONTENT_TYPE, HeaderValue::from_str("application/problem+json").unwrap());
            response
        }
    }

    #[cfg(feature = "problem-details")]
    pub use problem_details::ProblemDetails;
    #[cfg(feature = "problem-details")]
    use serde_json::json;

    #[cfg(feature = "problem-details")]
    impl<S: HttpErrorSerializer> HttpError<S> {
        pub fn into_problem_details(self) -> problem_details::ProblemDetails<HashMap<&'static str, serde_json::Value>> {
            self.log();

            let mut details = ProblemDetails::new();
            let mut extensions: HashMap<&'static str, serde_json::Value> = Default::default();


            details = details.with_title(self.message());
            details = details.with_status(self.status_code);
            extensions.insert("confidentiality", json!(format!("{:?}", self.confidentiality)));
            extensions.insert("identifier", json!(self.identifier));

            if matches!(self.confidentiality, Confidentiality::Public) {
                let causes = self.err.chain().map(|x| format!("{x}")).collect::<Vec<_>>();
                extensions.insert("errors", json!(causes));

                extensions.insert("details", json!(format!("{err:?}", err = self.err)));
                if let Some(ref help) = self.err.help() {
                    extensions.insert("help", json!(format!("{help}")));
                };

                if let Some(ref url) = self.err.url() {
                    extensions.insert("url", json!(format!("{url}")));
                };
            }

            details.with_extensions(extensions)
        }
    }

    impl<T: HttpErrorSerializer> HttpError<T> {
        pub fn log(&self) {
            match self.confidentiality {
                Confidentiality::AlternativeMessage(ref msg) => {
                    tracing::error!(
                        identifier = self.identifier,
                        confidentiality = ?self.confidentiality,
                        trace = %self.err.trace(),
                        "[Confidential http error: '{id:x}'] {msg}",
                        id = self.identifier,
                    );
                },
                Confidentiality::Public => {
                    let msg = self.message();
                    tracing::error!(
                        identifier = self.identifier,
                        confidentiality = ?self.confidentiality,
                        trace = %self.err.trace(),
                        "[Public http error: '{id:x}'] {msg}",
                        id = self.identifier,
                    );
                },
                Confidentiality::FullyConfidential | Confidentiality::OnlyMessage => {
                    let msg = self.message();
                    tracing::error!(
                        identifier = self.identifier,
                        confidentiality = ?self.confidentiality,
                        trace = %self.err.trace(),
                        "[Confidential http error: '{id:x}'] {msg}",
                        id = self.identifier,
                    );
                },
            };
        }
    }
}
