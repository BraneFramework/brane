//  LIB.rs
//    by Lut99
//
//  Created:
//    14 Jun 2023, 17:38:09
//  Last edited:
//    02 May 2025, 15:05:31
//  Auto updated?
//    Yes
//
//  Description:
//!   Wrapper around `brane-cli` that provides C-bindings for interacting with
//!   a remote backend. This allows C-programs to act as a BRANE client.
//!   
//!   The basics of how to do this are followed from:
//!   http://blog.asleson.org/2021/02/23/how-to-writing-a-c-shared-library-in-rust/
//

use std::cell::{RefCell, RefMut};
use std::ffi::{CStr, CString};
use std::fmt::Write as _;
use std::io::Write;
use std::mem;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Once};
use std::time::Instant;

use brane_ast::state::CompileState;
use brane_ast::traversals::print::ast;
use brane_ast::{CompileResult, Error as AstError, ParserOptions, Warning as AstWarning};
use brane_cli::run::{InstanceVmState, initialize_instance, run_instance};
use brane_exe::FullValue;
use brane_tsk::api::{get_data_index, get_package_index};
use console::style;
use humanlog::{DebugMode, HumanLogger};
use log::{debug, error, info, trace};
use parking_lot::{Mutex, MutexGuard};
use specifications::data::DataIndex;
use specifications::package::PackageIndex;
use specifications::wir::Workflow;
use tokio::runtime::{Builder, Runtime};


/***** CONSTANTS *****/
/// The version string of this package, null-terminated for C-compatibility.
static C_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");





/***** GLOBALS *****/
/// Ensures that the initialization function is run only once.
static LOG_INIT: Once = Once::new();

/// Handle to the shared tokio runtime that is ref-counted among all compilers and virtual machines
/// We do it this wacky way to ensure deallocation of the runtime when the last compiler/vm gets free'd, while still re-using the same one on every new().
static RUNTIME: Mutex<Option<Arc<Runtime>>> = Mutex::new(None);





/***** HELPER FUNCTIONS *****/
/// Initializes the logging system if it hadn't already.
#[inline]
fn init_logger() {
    LOG_INIT.call_once(|| {
        if let Err(err) = HumanLogger::terminal(DebugMode::Debug).init() {
            eprintln!("WARNING: Failed to setup Rust logger: {err} (logging disabled for this session)");
        }
    });
}

/// Initializes a tokio runtime if there wasn't one already.
///
/// # Returns
/// A shared ownership of the global runtime.
///
/// # Errors
/// This function may error if a new runtime needed to be initialized and that failed.
#[inline]
fn init_runtime() -> Result<Arc<Runtime>, std::io::Error> {
    // Acquire a lock
    let mut rt: MutexGuard<Option<Arc<Runtime>>> = RUNTIME.lock();

    // Check if there is one to get
    if let Some(rt) = &*rt {
        // Return the downgraded reference to it
        Ok(rt.clone())
    } else {
        // Spawn a new runtime and set it globally
        let runtime: Arc<Runtime> = Arc::new(Builder::new_current_thread().enable_io().enable_time().build()?);
        *rt = Some(runtime.clone());
        Ok(runtime)
    }
}
/// Cleans any runtime left in the global space _if_ it is not being used by any other VMs or whathaveyou.
#[inline]
fn cleanup_runtime() {
    // Acquire a lock
    let mut rt: MutexGuard<Option<Arc<Runtime>>> = RUNTIME.lock();

    // Check if we need to delete it
    let sc: usize = if let Some(rt) = &*rt { Arc::strong_count(rt) } else { 0 };

    // Delete it if necessary
    if sc == 1 {
        *rt = None;
    }
}

/// Reads a C-string as a Rust string (or at least, attempts to).
///
/// # Arguments
/// - `cstr`: The [`*const c_char`](c_char) that we attempt to read as a Rust-string.
///
/// # Returns
/// The converted [`str`].
///
/// # Errors
/// This function may error if the given `cstr` was not valid unicode.
#[inline]
#[track_caller]
unsafe fn cstr_to_rust<'s>(cstr: *const c_char) -> &'s str {
    let cstr: &CStr = CStr::from_ptr(cstr);
    match cstr.to_str() {
        Ok(cstr) => cstr,
        Err(err) => {
            panic!("Given char-pointer does point to valid UTF-8 string: {err}");
        },
    }
}

/// Converts a Rust string to a [malloc](libc::malloc())-allocated C-string.
///
/// # Arguments
/// - `string`: The Rust-string to convert.
///
/// # Returns
/// The newly allocated C-style string.
#[inline]
unsafe fn rust_to_cstr(string: String) -> *mut c_char {
    // Convert it to a CString first to get the trailing null-byte (and proper encoding and such)
    let string: CString = CString::new(string).unwrap();

    // Write that in a malloc-allocated area (so C can free() it), and then set it in the output
    let n_chars: usize = string.as_bytes().len();
    let target: *mut c_char = libc::malloc(n_chars + 1) as *mut c_char;
    libc::strncpy(target, string.as_ptr(), n_chars);
    std::slice::from_raw_parts_mut(target, n_chars + 1)[n_chars] = '\0' as core::ffi::c_char;

    // Return the string
    target
}





/***** HELPER STRUCTS *****/
/// Defines a [`Write`]-capable, shared handle over a single bytes buffer.
#[derive(Clone, Debug)]
struct BytesHandle {
    /// The shared bytes buffer to write to.
    buffer: Rc<RefCell<Vec<u8>>>,
}

impl Default for BytesHandle {
    #[inline]
    fn default() -> Self { Self::new() }
}
impl BytesHandle {
    /// Constructor for the StringHandle.
    ///
    /// # Returns
    /// A new instance of Self that is empty, ready for writing.
    #[inline]
    pub fn new() -> Self { Self { buffer: Rc::new(RefCell::new(vec![])) } }

    /// Flushes the bytes handle, returning its contents and the resetting them to empty.
    ///
    /// # Returns
    /// A byte vector representing the internal contents.
    #[inline]
    fn flush_as_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        {
            // Get a mutable borrow
            let mut buffer: RefMut<Vec<u8>> = self.buffer.borrow_mut();
            // Swap the contents with a fresh un
            mem::swap(&mut result, buffer.as_mut());
        }

        // Done, return the reaped results
        result
    }

    /// Flushes the bytes handle, returning its contents as a string and the resetting them to empty.
    ///
    /// # Returns
    /// A string representing the internal contents.
    ///
    /// # Errors
    /// This function errors if we failed to get the internals as valid UTF-8.
    #[inline]
    fn flush_as_string(&self) -> Result<String, std::string::FromUtf8Error> { String::from_utf8(self.flush_as_bytes()) }
}
impl Write for BytesHandle {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.buffer.borrow_mut().write(buf) }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> { self.buffer.borrow_mut().write_all(buf) }

    #[inline]
    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> std::io::Result<()> { self.buffer.borrow_mut().write_fmt(fmt) }

    #[inline]
    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> { self.buffer.borrow_mut().write_vectored(bufs) }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> { self.buffer.borrow_mut().flush() }

    #[inline]
    fn by_ref(&mut self) -> &mut Self { self }
}





/***** LIBRARY FUNCTIONS *****/
/// Returns the BRANE version for which this compiler is valid.
///
/// # Returns
/// String version that contains a major, minor and patch version separated by dots.
#[no_mangle]
pub extern "C" fn version() -> *const c_char {
    // SAFETY: We can easily do this without a care in the world, since the string is static and won't need deallocation.
    C_VERSION.as_ptr() as *const c_char
}



/// Forces the serialization functions to either use colour or not.
///
/// If you don't call this function, then it depends on whether the backend [`console`] library thinks if the stdout/stderr support ANSI colours.
///
/// # Arguments
/// - `force`: If true, then ANSI characters will be forced to be printed. Otherwise, if false, they will be forced to _not_ be printed.
#[no_mangle]
pub extern "C" fn set_force_colour(force: bool) {
    // Delegate to the console functions, is all we need to do.
    console::set_colors_enabled(force);
    console::set_colors_enabled_stderr(force);
}





/***** LIBRARY ERROR *****/
/// Defines the error type returned by this library.
#[derive(Debug)]
pub struct Error {
    /// The message to print.
    msg: String,
}



/// Destructor for the Error type.
///
/// # Safety
/// You _must_ call this destructor yourself whenever you are done with the struct to cleanup any code. _Don't_ use any C-library free!
///
/// # Arguments
/// - `err`: The [`Error`] to deallocate.
#[no_mangle]
pub unsafe extern "C" fn error_free(err: *mut Error) {
    init_logger();
    trace!("Destroying Error...");

    // Simply captute the box, then drop
    drop(Box::from_raw(err));
    cleanup_runtime();
}

/// Serializes the error message in this error to the given buffer.
///
/// # Arguments
/// - `err`: the [`Error`] to serialize the error of.
/// - `buffer`: The buffer to serialize to. Will be freshly allocated using `malloc` for the correct size; can be freed using `free()`.
///
/// # Panics
/// This function can panic if the given `err` or `buffer` are NULL-pointers.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn error_serialize_err(err: *const Error, buffer: *mut *mut c_char) {
    *buffer = std::ptr::null_mut();

    // Unwrap the pointers
    let err: &Error = match err.as_ref() {
        Some(err) => err,
        None => {
            panic!("Given Error is a NULL-pointer");
        },
    };

    // Set the C-string equivalent of this as the result
    *buffer = rust_to_cstr(err.msg.clone());

    // OK, done!
}

/// Prints the error message in this error to stderr.
///
/// # Arguments
/// - `err`: The [`Error`] to print.
///
/// # Panics
/// This function can panic if the given `err` is a NULL-pointer.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn error_print_err(err: *const Error) {
    init_logger();

    // Read the pointer
    let err: &Error = match err.as_ref() {
        Some(err) => err,
        None => {
            panic!("Given Error is a NULL-pointer");
        },
    };

    // Simply log it as an error
    error!("{}", err.msg);
}





/***** LIBRARY SOURCE ERROR *****/
/// Defines the error type returned by this library.
#[derive(Debug)]
pub struct SourceError<'f> {
    /// The filename of the file we are referencing.
    file:   &'f str,
    /// The complete source we attempted to parse. Note that we copy instead of reference to be cooler (and to rollback the state on errors).
    source: String,

    /// The warning messages to print.
    warns: Vec<AstWarning>,
    /// The error messages to print.
    errs:  Vec<AstError>,
    /// Any custom error message to print that is not from the compiler itself.
    msg:   Option<String>,
}



/// Destructor for the Error type.
///
/// # Safety
/// You _must_ call this destructor yourself whenever you are done with the struct to cleanup any code. _Don't_ use any C-library free!
///
/// # Arguments
/// - `serr`: The [`SourceError`] to deallocate.
#[no_mangle]
pub unsafe extern "C" fn serror_free(serr: *mut SourceError) {
    init_logger();
    trace!("Destroying SourceError...");

    // Simply captute the box, then drop
    drop(Box::from_raw(serr));
    cleanup_runtime();
}



/// Returns if a source warning has occurred.
///
/// # Arguments
/// - `serr`: The [`SourceError`] struct to inspect.
///
/// # Returns
/// True if [`serr_print_swarns`] would print anything, or false otherwise.
///
/// # Panics
/// This function can panic if the given `serr` is a NULL-pointer.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn serror_has_swarns(serr: *const SourceError) -> bool {
    // Unwrap the pointer
    let serr: &SourceError = match serr.as_ref() {
        Some(err) => err,
        None => {
            panic!("Given SourceError is a NULL-pointer");
        },
    };

    // Now return if there are any warnings
    !serr.warns.is_empty()
}

/// Returns if a source error has occurred.
///
/// # Arguments
/// - `serr`: The [`SourceError`] struct to inspect.
///
/// # Returns
/// True if [`serr_print_serrs`] would print anything, or false otherwise.
///
/// # Panics
/// This function can panic if the given `err` is a NULL-pointer.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn serror_has_serrs(serr: *const SourceError) -> bool {
    // Unwrap the pointer
    let serr: &SourceError = match serr.as_ref() {
        Some(err) => err,
        None => {
            panic!("Given SourceError is a NULL-pointer");
        },
    };

    // Now return if there are any errors
    !serr.errs.is_empty()
}

/// Returns if a program error has occurred.
///
/// # Arguments
/// - `serr`: The [`SourceError`] struct to inspect.
///
/// # Returns
/// True if [`serr_print_err`] would print anything, or false otherwise.
///
/// # Panics
/// This function can panic if the given `err` is a NULL-pointer.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn serror_has_err(serr: *const SourceError) -> bool {
    // Unwrap the pointer
    let serr: &SourceError = match serr.as_ref() {
        Some(err) => err,
        None => {
            panic!("Given SourceError is a NULL-pointer");
        },
    };

    // Now return if there is a message
    serr.msg.is_some()
}



/// Serializes the source warnings in this error to the given buffer.
///
/// Note that there may be zero or more warnings at once. To discover if there are any, check [`serror_has_swarns()`].
///
/// # Arguments
/// - `serr`: the [`SourceError`] to serialize the source warnings of.
/// - `buffer`: The buffer to serialize to. Will be freshly allocated using `malloc` for the correct size; can be freed using `free()`.
///
/// # Panics
/// This function can panic if the given `serr` or `buffer` are NULL-pointers.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn serror_serialize_swarns(serr: *const SourceError, buffer: *mut *mut c_char) {
    *buffer = std::ptr::null_mut();

    // Unwrap the pointers
    let serr: &SourceError = match serr.as_ref() {
        Some(err) => err,
        None => {
            panic!("Given SourceError is a NULL-pointer");
        },
    };

    // Early quit if there is no warning
    if serr.warns.is_empty() {
        // Write a single-byte buffer with only the null buffer
        let target: *mut c_char = libc::malloc(1) as *mut c_char;
        std::slice::from_raw_parts_mut(target, 1)[0] = '\0' as core::ffi::c_char;
        *buffer = target;

        // A'ight that's it then
        return;
    }

    // Otherwise, serialize all warnings to a C-string
    let mut warns: Vec<u8> = Vec::new();
    for warn in &serr.warns {
        // Write them to a Rust string first
        warn.prettywrite(&mut warns, serr.file, &serr.source).unwrap();
    }
    let warns: String = String::from_utf8(warns).unwrap();

    // Set the C-string equivalent of this as the result
    *buffer = rust_to_cstr(warns);

    // And that's it
}

/// Serializes the source errors in this error to the given buffer.
///
/// Note that there may be zero or more errors at once. To discover if there are any, check [`serror_has_serrs()`].
///
/// # Arguments
/// - `serr`: the [`SourceError`] to serialize the source errors of.
/// - `buffer`: The buffer to serialize to.
/// - `max_len`: The length of the buffer. Will simply stop writing if this length is exceeded.
///
/// # Panics
/// This function can panic if the given `serr` or `buffer` are NULL-pointers.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn serror_serialize_serrs(serr: *const SourceError, buffer: *mut *mut c_char) {
    *buffer = std::ptr::null_mut();

    // Unwrap the pointers
    let serr: &SourceError = match serr.as_ref() {
        Some(err) => err,
        None => {
            panic!("Given SourceError is a NULL-pointer");
        },
    };

    // Early quit if there is no warning
    if serr.errs.is_empty() {
        // Write a single-byte buffer with only the null buffer
        let target: *mut c_char = libc::malloc(1) as *mut c_char;
        std::slice::from_raw_parts_mut(target, 1)[0] = '\0' as core::ffi::c_char;
        *buffer = target;

        // A'ight that's it then
        return;
    }

    // Otherwise, serialize all warnings to a C-string
    let mut errs: Vec<u8> = Vec::new();
    for err in &serr.errs {
        // Write them to a Rust string first
        err.prettywrite(&mut errs, serr.file, &serr.source).unwrap();
    }
    let errs: String = String::from_utf8(errs).unwrap();

    // Set the C-string equivalent of this as the result
    *buffer = rust_to_cstr(errs);

    // And that's it
}

/// Serializes the error message in this error to the given buffer.
///
/// Note that there may be no error, but only source warnings- or errors. To discover if there is any, check [`serror_has_err()`].
///
/// # Arguments
/// - `serr`: the [`SourceError`] to serialize the error of.
/// - `buffer`: The buffer to serialize to.
/// - `max_len`: The length of the buffer. Will simply stop writing if this length is exceeded.
///
/// # Panics
/// This function can panic if the given `serr` or `buffer` are NULL-pointers.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn serror_serialize_err(serr: *const SourceError, buffer: *mut *mut c_char) {
    *buffer = std::ptr::null_mut();

    // Unwrap the pointers
    let serr: &SourceError = match serr.as_ref() {
        Some(err) => err,
        None => {
            panic!("Given SourceError is a NULL-pointer");
        },
    };

    // We only have something to print if we have something to print
    match &serr.msg {
        Some(msg) => {
            // We can simply attempt to copy the message
            *buffer = rust_to_cstr(msg.clone());
        },

        None => {
            // Write a single-byte buffer with only the null buffer
            let target: *mut c_char = libc::malloc(1) as *mut c_char;
            std::slice::from_raw_parts_mut(target, 1)[0] = '\0' as core::ffi::c_char;
            *buffer = target;
        },
    }
}



/// Prints the source warnings in this error to stderr.
///
/// Note that there may be zero or more warnings at once. To discover if there are any, check [`serror_has_swarns()`].
///
/// # Arguments
/// - `serr`: The [`SourceError`] to print the source warnings of.
///
/// # Panics
/// This function can panic if the given `serr` is a NULL-pointer.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn serror_print_swarns(serr: *const SourceError) {
    // Unwrap the pointer
    let serr: &SourceError = match serr.as_ref() {
        Some(err) => err,
        None => {
            panic!("Given SourceError is a NULL-pointer");
        },
    };

    // Iterate over the warnings to print them
    for warn in &serr.warns {
        warn.prettyprint(serr.file, &serr.source);
    }
}

/// Prints the source errors in this error to stderr.
///
/// Note that there may be zero or more errors at once. To discover if there are any, check [`serror_has_serrs()`].
///
/// # Arguments
/// - `serr`: The [`SourceError`] to print the source errors of.
///
/// # Panics
/// This function can panic if the given `serr` is a NULL-pointer.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn serror_print_serrs(serr: *const SourceError) {
    // Unwrap the pointer
    let serr: &SourceError = match serr.as_ref() {
        Some(serr) => serr,
        None => {
            panic!("Given SourceError is a NULL-pointer");
        },
    };

    // Iterate over the errors to print them
    for err in &serr.errs {
        err.prettyprint(serr.file, &serr.source);
    }
}

/// Prints the error message in this error to stderr.
///
/// Note that there may be no error, but only source warnings- or errors. To discover if there is any, check [`serror_has_err()`].
///
/// # Arguments
/// - `serr`: The [`SourceError`] to print the error of.
///
/// # Panics
/// This function can panic if the given `serr` is a NULL-pointer.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn serror_print_err(serr: *const SourceError) {
    init_logger();

    // Unwrap the pointer
    let serr: &SourceError = match serr.as_ref() {
        Some(err) => err,
        None => {
            panic!("Given SourceError is a NULL-pointer");
        },
    };

    // Print the message as an error-log, if any
    if let Some(msg) = &serr.msg {
        error!("{msg}");
    }
}





/***** LIBRARY PACKAGEINDEX *****/
/// Constructs a new [`PackageIndex`] that lists the available packages in a remote instance.
///
/// # Arguments
/// - `endpoint`: The remote API-endpoint to read the packages from. The path (`/graphql`) will be deduced and needn't be given, just the host and port.
/// - `pindex`: Will point to the newly created [`PackageIndex`] when done. Will be [`NULL`] if there is an error (see below).
///
/// # Returns
/// [`Null`] in all cases except when an error occurs. Then, an [`Error`]-struct is returned describing the error. Don't forget this has to be freed using [`error_free()`]!
///
/// # Panics
/// This function can panic if the given `endpoint` does not point to a valud UTF-8 string.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn pindex_new_remote(endpoint: *const c_char, pindex: *mut *mut Arc<Mutex<PackageIndex>>) -> *const Error {
    init_logger();
    *pindex = std::ptr::null_mut();
    info!("Collecting package index...");

    // Read the input string
    let endpoint: &str = cstr_to_rust(endpoint);

    // Create a local threaded tokio context
    let runtime: Arc<Runtime> = match init_runtime() {
        Ok(runtime) => runtime,
        Err(e) => {
            let err: Error = Error { msg: format!("Failed to create local Tokio context: {e}") };
            return Box::into_raw(Box::new(err));
        },
    };

    // Build the package index around it
    let addr: String = format!("{endpoint}/graphql");
    let index: PackageIndex = match runtime.block_on(get_package_index(&addr)) {
        Ok(index) => index,
        Err(e) => {
            let err: Error = Error { msg: format!("Failed to read package index from '{addr}': {e}") };
            return Box::into_raw(Box::new(err));
        },
    };

    // Store it and we're done
    debug!("Found {} packages", index.packages.len());
    *pindex = Box::into_raw(Box::new(Arc::new(Mutex::new(index))));
    std::ptr::null()
}

/// Destructor for the PackageIndex.
///
/// # Safety
/// You _must_ call this destructor yourself whenever you are done with the struct to cleanup any code. _Don't_ use any C-library free!
///
/// # Arguments
/// - `pindex`: The [`PackageIndex`] to free.
#[no_mangle]
pub unsafe extern "C" fn pindex_free(pindex: *mut Arc<Mutex<PackageIndex>>) {
    init_logger();
    trace!("Destroying PackageIndex...");

    // Simply capture the box, then drop
    drop(Box::from_raw(pindex));
    cleanup_runtime();
}





/***** LIBRARY DATAINDEX *****/
/// Constructs a new [`DataIndex`] that lists the available datasets in a remote instance.
///
/// # Arguments
/// - `endpoint`: The remote API-endpoint to read the datasets from. The path (`/data/info`) will be deduced and needn't be given, just the host and port.
/// - `dindex`: Will point to the newly created [`DataIndex`] when done. Will be [`NULL`] if there is an error (see below).
///
/// # Returns
/// [`Null`] in all cases except when an error occurs. Then, an [`Error`]-struct is returned describing the error. Don't forget this has to be freed using [`error_free()`]!
///
/// # Panics
/// This function can panic if the given `endpoint` does not point to a valud UTF-8 string.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn dindex_new_remote(endpoint: *const c_char, dindex: *mut *mut Arc<Mutex<DataIndex>>) -> *const Error {
    init_logger();
    *dindex = std::ptr::null_mut();
    info!("Collecting data index...");

    // Read the input string
    let endpoint: &str = cstr_to_rust(endpoint);

    // Create a local threaded tokio context
    let runtime: Arc<Runtime> = match init_runtime() {
        Ok(runtime) => runtime,
        Err(e) => {
            let err: Error = Error { msg: format!("Failed to create local Tokio context: {e}") };
            return Box::into_raw(Box::new(err));
        },
    };

    // Build the package index around it
    let addr: String = format!("{endpoint}/data/info");
    let index: DataIndex = match runtime.block_on(get_data_index(&addr)) {
        Ok(index) => index,
        Err(e) => {
            let err: Error = Error { msg: format!("Failed to read data index from '{addr}': {e}") };
            return Box::into_raw(Box::new(err));
        },
    };

    // Store it and we're done
    debug!("Found {} datasets", index.iter().count());
    *dindex = Box::into_raw(Box::new(Arc::new(Mutex::new(index))));
    std::ptr::null()
}

/// Destructor for the DataIndex.
///
/// # Safety
/// You _must_ call this destructor yourself whenever you are done with the struct to cleanup any code. _Don't_ use any C-library free!
///
/// # Arguments
/// - `dindex`: The [`DataIndex`] to free.
#[no_mangle]
pub unsafe extern "C" fn dindex_free(dindex: *mut Arc<Mutex<DataIndex>>) {
    init_logger();
    trace!("Destroying DataIndex...");

    // Simply capture the box, then drop
    drop(Box::from_raw(dindex));
    cleanup_runtime();
}





/***** LIBRARY WORKFLOW *****/
/// Destructor for the Workflow.
///
/// # Safety
/// You _must_ call this destructor yourself whenever you are done with the struct to cleanup any code. _Don't_ use any C-library free!
///
/// # Arguments
/// - `workflow`: The [`Workflow`] to free.
#[no_mangle]
pub unsafe extern "C" fn workflow_free(workflow: *mut Workflow) {
    init_logger();
    trace!("Destroying Workflow...");

    // Simply capture the box, then drop
    drop(Box::from_raw(workflow));
    cleanup_runtime();
}



/// Given a workflow, injects an end user into it.
///
/// # Arguments
/// - `workflow`: The [`Workflow`] to inject into.
/// - `user`: The name of the user to inject.
///
/// # Panics
/// This function can panic if the given `workflow` is a NULL-pointer, or if the given `user` is not valid UTF-8/a NULL-pointer.
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn workflow_set_user(workflow: *mut Workflow, user: *const c_char) {
    // Set the output to NULL
    init_logger();
    info!("Injecting user into workflow...");

    // Unwrap the input workflow & user
    let workflow: &mut Workflow = match workflow.as_mut() {
        Some(wf) => wf,
        None => {
            panic!("Given Workflow is a NULL-pointer");
        },
    };
    let user: &str = cstr_to_rust(user);

    // Inject one into the other, done
    workflow.user = Arc::new(Some(user.into()));
    debug!("End-user is now set to '{user}'");
}



/// Serializes the workflow by essentially disassembling it.
///
/// # Arguments
/// - `workflow`: The [`Workflow`] to disassemble.
/// - `assembly`: The serialized assembly of the same workflow, as a string. Don't forget to free it! Will be [`NULL`] if there is an error (see below).
///
/// # Returns
/// [`Null`] in all cases except when an error occurs. Then, an [`Error`]-struct is returned describing the error. Don't forget this has to be freed using [`error_free()`]!
///
/// # Panics
/// This function can panic if the given `workflow` is a NULL-pointer.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn workflow_disassemble(workflow: *const Workflow, assembly: *mut *mut c_char) -> *const Error {
    // Set the output to NULL
    init_logger();
    *assembly = std::ptr::null_mut();
    info!("Generating workflow assembly...");

    // Unwrap the input workflow
    let workflow: &Workflow = match workflow.as_ref() {
        Some(wf) => wf,
        None => {
            panic!("Given Workflow is a NULL-pointer");
        },
    };

    // Run the compiler traversal to serialize it
    let mut result: Vec<u8> = Vec::new();
    if let Err(e) = ast::do_traversal(workflow, &mut result) {
        let err: Error = Error { msg: format!("Failed to print given workflow: {}", e[0]) };
        return Box::into_raw(Box::new(err));
    };

    // Write that in a malloc-allocated area (so C can free it), and then set it in the output
    *assembly = rust_to_cstr(String::from_utf8_unchecked(result));

    // Done, return that no error occurred
    std::ptr::null()
}





/***** LIBRARY COMPILER *****/
#[derive(Debug)]
pub struct Compiler {
    /// The package index to use for compilation.
    pindex: Arc<Mutex<PackageIndex>>,
    /// The data index to use for compilation.
    dindex: Arc<Mutex<DataIndex>>,

    /// The additional, total collected source that we are working with
    source: String,
    /// The compile state to use in between snippets.
    state:  CompileState,
}



/// Constructor for the Compiler.
///
/// # Arguments
/// - `pindex`: The [`PackageIndex`] to resolve package references in the snippets with.
/// - `dindex`: The [`DataIndex`] to resolve dataset references in the snippets with.
/// - `compiler`: Will point to the newly created [`Compiler`] when done. Will be [`NULL`] if there is an error (see below).
///
/// # Returns
/// [`Null`] in all cases except when an error occurs. Then, an [`Error`]-struct is returned describing the error. Don't forget this has to be freed using [`error_free()`]!
///
/// # Panics
/// This function can panic if the given `pindex` or `dindex` points to NULL.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn compiler_new(
    pindex: *const Arc<Mutex<PackageIndex>>,
    dindex: *const Arc<Mutex<DataIndex>>,
    compiler: *mut *mut Compiler,
) -> *const Error {
    init_logger();
    *compiler = std::ptr::null_mut();
    info!("Constructing BraneScript compiler v{}...", env!("CARGO_PKG_VERSION"));

    // Read the indices
    let pindex: &Arc<Mutex<PackageIndex>> = match pindex.as_ref() {
        Some(index) => index,
        None => {
            panic!("Given PackageIndex is a NULL-pointer");
        },
    };
    let dindex: &Arc<Mutex<DataIndex>> = match dindex.as_ref() {
        Some(index) => index,
        None => {
            panic!("Given DataIndex is a NULL-pointer");
        },
    };

    // Construct a new Compiler and return it as a pointer
    *compiler = Box::into_raw(Box::new(Compiler {
        pindex: pindex.clone(),
        dindex: dindex.clone(),

        source: String::new(),
        state:  CompileState::new(),
    }));
    debug!("Compiler created");
    std::ptr::null()
}

/// Destructor for the Compiler.
///
/// # Safety
/// You _must_ call this destructor yourself whenever you are done with the struct to cleanup any code. _Don't_ use any C-library free!
///
/// # Arguments
/// - `compiler`: The [`Compiler`] to free.
#[no_mangle]
pub unsafe extern "C" fn compiler_free(compiler: *mut Compiler) {
    init_logger();
    trace!("Destroying BraneScript compiler...");

    // Take ownership of the compiler and then drop it to destroy
    drop(Box::from_raw(compiler));
    cleanup_runtime();
}



/// Compiles the given BraneScript snippet to the BRANE Workflow Representation.
///
/// Note that this function changes the `compiler`'s state.
///
/// # Safety
/// Be aware that the returned [`SourceError`] refers the the given `compiler` and `what`. Freeing any of those two and then using the [`SourceError`] _will_ lead to undefined behaviour.
///
/// You _must_ free this [`SourceError`] using [`serror_free()`], since its allocated using Rust internals and cannot be deallocated directly using `malloc`. Note, however, that it's safe to call [`serror_free()`] _after_ freeing `compiler` or `what` (but that's the only function).
///
/// # Arguments
/// - `compiler`: The [`Compiler`] to compile with. Essentially this determines which previous compile state to use.
/// - `what`: Some string describing what we are compiling (e.g., a file, `<intern>`, a cell, etc.)
/// - `raw`: The raw BraneScript snippet to parse.
/// - `workflow`: Will point to the compiled AST. Will be [`NULL`] if there is an error (see below).
///
/// # Returns
/// A [`SourceError`]-struct describing the error, if any, and source warnings/errors.
///
/// # Panics
/// This function can panic if the given `compiler` points to NULL, or `what`/`raw` does not point to a valid UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn compiler_compile(
    compiler: *mut Compiler,
    what: *const c_char,
    raw: *const c_char,
    workflow: *mut *mut Workflow,
) -> *const SourceError<'static> {
    // Initialize the logger if we hadn't already
    init_logger();
    *workflow = std::ptr::null_mut();
    info!("Compiling snippet...");



    /* INPUT */
    // Cast the Compiler pointer to a Compiler reference
    debug!("Reading compiler input...");
    let compiler: &mut Compiler = match compiler.as_mut() {
        Some(compiler) => compiler,
        None => {
            panic!("Given Compiler is a NULL-pointer");
        },
    };

    // Get the input as a Rust string
    let what: &str = cstr_to_rust(what);
    let raw: &str = cstr_to_rust(raw);

    // Create the error already
    let mut serr: Box<SourceError> = Box::new(SourceError { file: what, source: String::new(), warns: vec![], errs: vec![], msg: None });



    /* COMPILE */
    debug!("Compiling snippet...");

    // Append the source we keep track of
    compiler.source.push_str(raw);
    compiler.source.push('\n');

    // Compile that using `brane-ast`
    serr.source.clone_from(&compiler.source);
    let wf: Workflow = {
        // Acquire locks on the indices
        let pindex: MutexGuard<PackageIndex> = compiler.pindex.lock();
        let dindex: MutexGuard<DataIndex> = compiler.dindex.lock();

        // Run the snippet
        match brane_ast::compile_snippet(&mut compiler.state, raw.as_bytes(), &pindex, &dindex, &ParserOptions::bscript()) {
            CompileResult::Workflow(workflow, warns) => {
                compiler.state.offset += 1 + raw.chars().filter(|c| *c == '\n').count();
                serr.warns = warns;
                workflow
            },

            CompileResult::Eof(e) => {
                serr.errs = vec![e];
                compiler.state.offset += 1 + raw.chars().filter(|c| *c == '\n').count();
                return Box::into_raw(serr);
            },
            CompileResult::Err(errs) => {
                serr.errs = errs;
                compiler.state.offset += 1 + raw.chars().filter(|c| *c == '\n').count();
                return Box::into_raw(serr);
            },

            CompileResult::Program(_, _) | CompileResult::Unresolved(_, _) => {
                unreachable!();
            },
        }
    };

    // Write the workflow to the output
    *workflow = Box::into_raw(Box::new(wf));

    // OK, return the error struct!
    debug!("Compilation success");
    Box::into_raw(serr)
}





/***** FULL VALUE *****/
/// Destructor for the FullValue.
///
/// # Safety
/// You _must_ call this destructor yourself whenever you are done with the struct to cleanup any code. _Don't_ use any C-library free!
///
/// # Arguments
/// - `fvalue`: The [`FullValue`] to free.
#[no_mangle]
pub unsafe extern "C" fn fvalue_free(fvalue: *mut FullValue) {
    init_logger();
    trace!("Destroying FullValue...");

    // Take ownership of the value and then drop it to destroy
    drop(Box::from_raw(fvalue));
    cleanup_runtime();
}



/// Checks if this [`FullValue`] needs processing.
///
/// For now, this only occurs when it is a [`FullValue::Data`] (download it) or [`FullValue::IntermediateResult`] (throw a warning).
///
/// # Arguments
/// - `fvalue`: The [`FullValue`] to analyse.
///
/// # Returns
/// True if `vm_process()` should be called on this value or false otherwise.
///
/// # Panics
/// This function can panic if `fvalue` pointed to [`NULL`].
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn fvalue_needs_processing(fvalue: *const FullValue) -> bool {
    // Unwrap the input
    let fvalue: &FullValue = match fvalue.as_ref() {
        Some(vm) => vm,
        None => {
            panic!("Given FullValue is a NULL-pointer");
        },
    };

    // Match it
    matches!(fvalue, FullValue::Data(_) | FullValue::IntermediateResult(_))
}

/// Serializes a FullValue to show as result of the workflow.
///
/// # Arguments
/// - `fvalue`: the [`FullValue`] to serialize.
/// - `data_dir`: The data directory to which we downloaded the `fvalue`, if we did so.
/// - `result`: The buffer to serialize to. Will be freshly allocated using `malloc` for the correct size; can be freed using `free()`.
///
/// # Panics
/// This function can panic if the given `fvalue` is a NULL-pointer or if `data_dir` did not point to a valid UTF-8 string.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn fvalue_serialize(fvalue: *const FullValue, data_dir: *const c_char, result: *mut *mut c_char) {
    *result = std::ptr::null_mut();

    // Unwrap the pointers
    let fvalue: &FullValue = match fvalue.as_ref() {
        Some(fvalue) => fvalue,
        None => {
            panic!("Given FullValue is a NULL-pointer");
        },
    };
    let data_dir: PathBuf = PathBuf::from(cstr_to_rust(data_dir));

    // Serialize the result only if there is anything to serialize
    let mut sfvalue: String = String::new();
    if !matches!(fvalue, FullValue::Void) {
        writeln!(&mut sfvalue, "\nWorkflow returned value {}", style(format!("'{}'", fvalue)).bold().cyan()).unwrap();

        // Treat some values special
        match fvalue {
            // Print sommat additional if it's an intermediate result.
            FullValue::IntermediateResult(_) => {
                writeln!(&mut sfvalue, "(Intermediate results are not available locally; promote it using 'commit_result()')").unwrap();
            },

            // If it's a dataset, show where to access it
            FullValue::Data(name) => {
                writeln!(&mut sfvalue, "(It's available under '{}')", data_dir.join(name.as_ref()).display()).unwrap();
            },

            // Nothing for the rest
            _ => {},
        }
    }

    // That's what we serialize to the output
    *result = rust_to_cstr(sfvalue);

    // Done!
}





/***** VIRTUAL MACHINE *****/
/// Defines a BRANE instance virtual machine.
///
/// This can run a compiled workflow on a running instance.
pub struct VirtualMachine {
    /// The tokio runtime handle to use for this VM
    runtime: Arc<Runtime>,
    /// The endpoint to connect to for downloading registries
    #[allow(dead_code)]
    api_endpoint: String,
    /// The endpoint to connect to when running.
    drv_endpoint: String,
    /// The directory of certificates to use.
    #[allow(dead_code)]
    certs_dir: String,
    /// The state of everything we need to know about the virtual machine
    state: InstanceVmState<BytesHandle, BytesHandle>,
}



/// Constructor for the VirtualMachine.
///
/// # Arguments
/// - `api_endpoint`: The Brane API endpoint to connect to to download available registries and all that.
/// - `drv_endpoint`: The BRANE driver endpoint to connect to to execute stuff.
/// - `certs_dir`: The directory where certificates for downloading datasets are stored.
/// - `pindex`: The [`PackageIndex`] to resolve package references in the snippets with.
/// - `dindex`: The [`DataIndex`] to resolve dataset references in the snippets with.
/// - `virtual_machine`: Will point to the newly created [`VirtualMachine`] when done. Will be [`NULL`] if there is an error (see below).
///
/// # Returns
/// An [`Error`]-struct that contains the error occurred, or [`NULL`] otherwise.
///
/// # Panics
/// This function can panic if the given `pindex` or `dindex` are NULL, or if the given `api_endpoint`, `drv_endpoint` or `certs_dir` do not point to a valid UTF-8 string.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn vm_new(
    api_endpoint: *const c_char,
    drv_endpoint: *const c_char,
    certs_dir: *const c_char,
    pindex: *const Arc<Mutex<PackageIndex>>,
    dindex: *const Arc<Mutex<DataIndex>>,
    vm: *mut *mut VirtualMachine,
) -> *const Error {
    init_logger();
    *vm = std::ptr::null_mut();
    info!("Constructing BraneScript virtual machine v{}...", env!("CARGO_PKG_VERSION"));

    // Read the endpoints & directories
    let api_endpoint: &str = cstr_to_rust(api_endpoint);
    let drv_endpoint: &str = cstr_to_rust(drv_endpoint);
    let certs_dir: &str = cstr_to_rust(certs_dir);

    // Read the indices
    let pindex: &Arc<Mutex<PackageIndex>> = match pindex.as_ref() {
        Some(index) => index,
        None => {
            panic!("Given PackageIndex is a NULL-pointer");
        },
    };
    let dindex: &Arc<Mutex<DataIndex>> = match dindex.as_ref() {
        Some(index) => index,
        None => {
            panic!("Given DataIndex is a NULL-pointer");
        },
    };

    // Prepare a tokio environment
    let runtime: Arc<Runtime> = match init_runtime() {
        Ok(runtime) => runtime,
        Err(e) => {
            let err: Error = Error { msg: format!("Failed to create local Tokio context: {e}") };
            return Box::into_raw(Box::new(err));
        },
    };

    // Prepare the state
    let handle: BytesHandle = BytesHandle::new();
    let state: InstanceVmState<BytesHandle, BytesHandle> = match runtime.block_on(initialize_instance(
        handle.clone(),
        handle,
        drv_endpoint,
        pindex.clone(),
        dindex.clone(),
        /* TODO: Add user here as well */
        None,
        None,
        ParserOptions::bscript(),
    )) {
        Ok(state) => state,
        Err(e) => {
            let err: Error = Error { msg: format!("Failed to create new InstanceVmState: {e}") };
            return Box::into_raw(Box::new(err));
        },
    };

    // OK, return the new thing
    *vm = Box::into_raw(Box::new(VirtualMachine {
        runtime,
        api_endpoint: api_endpoint.into(),
        drv_endpoint: drv_endpoint.into(),
        certs_dir: certs_dir.into(),
        state,
    }));
    debug!("Virtual machine created");
    std::ptr::null()
}

/// Destructor for the VirtualMachine.
///
/// # Safety
/// You _must_ call this destructor yourself whenever you are done with the struct to cleanup any code. _Don't_ use any C-library free!
///
/// # Arguments
/// - `vm`: The [`VirtualMachine`] to free.
#[no_mangle]
pub unsafe extern "C" fn vm_free(vm: *mut VirtualMachine) {
    init_logger();
    trace!("Destroying VirtualMachine...");

    // See if the global context needs to be destroyed
    cleanup_runtime();

    // Take ownership of the VM and then drop it to destroy
    drop(Box::from_raw(vm));
    cleanup_runtime();
}



/// Runs the given code snippet on the backend instance.
///
/// # Arguments
/// - `vm`: The [`VirtualMachine`] that we execute with. This determines which backend to use.
/// - `workflow`: The compiled workflow to execute.
/// - `prints`: A newly allocated string which represents any stdout- or stderr prints done during workflow execution. Will be [`NULL`] if there is an error (see below).
/// - `result`: A [`FullValue`] which represents the return value of the workflow, and a [`ProgramCounter`] that denotes which instruction produced it (or [`None`] if the workflow was empty). Will be [`NULL`] if there is an error (see below).
///
/// # Returns
/// An [`Error`]-struct that contains the error occurred, or [`NULL`] otherwise.
///
/// # Panics
/// This function may panic if the input `vm` or `workflow` pointed to a NULL-pointer.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn vm_run(
    vm: *mut VirtualMachine,
    workflow: *const Workflow,
    prints: *mut *mut c_char,
    result: *mut *mut FullValue,
) -> *const Error {
    init_logger();
    *prints = std::ptr::null_mut();
    *result = std::ptr::null_mut();
    info!("Executing workflow on virtual machine...");
    let start: Instant = Instant::now();

    // Unwrap the VM
    let vm: &mut VirtualMachine = match vm.as_mut() {
        Some(vm) => vm,
        None => {
            panic!("Given VirtualMachine is a NULL-pointer");
        },
    };
    // Unwrap the workflow
    let workflow: &Workflow = match workflow.as_ref() {
        Some(workflow) => workflow,
        None => {
            panic!("Given Workflow is a NULL-pointer");
        },
    };

    // Run the state
    debug!("Executing snippet...");
    let value: FullValue = match vm.runtime.block_on(run_instance(&vm.drv_endpoint, &mut vm.state, workflow, false)) {
        Ok(value) => value,
        Err(e) => {
            let err: Box<Error> = Box::new(Error { msg: format!("Failed to run workflow on '{}': {}", vm.drv_endpoint, e) });
            return Box::into_raw(err);
        },
    };

    // Store it and we're done!
    *prints = rust_to_cstr(vm.state.stdout.flush_as_string().unwrap());
    *result = Box::into_raw(Box::new(value));
    debug!("Done (execution took {:.2}s)", start.elapsed().as_secs_f32());
    std::ptr::null()
}

/// Processes the result referred to by the [`FullValue`].
///
/// Processing currently consists of:
/// - Downloading the dataset if it's a [`FullValue::Data`]
/// - Throwing a warning if it's a [`FullValue::IntermediateResult`]
/// - Doing nothing otherwise
///
/// # Arguments
/// - `vm`: The [`VirtualMachine`] that we download with. This determines which backend to use.
/// - `result`: The [`FullValue`] which we will attempt to download if needed.
/// - `data_dir`: The directory to download the result to. This should be the generic data directory, as a new directory for this dataset will be created within.
///
/// # Returns
/// An [`Error`]-struct that contains the error occurred, or [`NULL`] otherwise.
///
/// # Panics
/// This function may panic if the input `vm` or `result` pointed to a NULL-pointer, or if `data_dir` did not point to a valid UTF-8 string.
// TODO: Resolve this problem
//
/// /// <div class="warning">
/// This function is currently broken because of ecosystem changes. See: https://github.com/epi-project/brane/issues/195
/// </div>
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn vm_process(_vm: *mut VirtualMachine, _result: *const FullValue, _data_dir: *const c_char) -> *const Error {
    todo!("vm_process: This function doesn't know its workflow and can therefore cannot be implemented currently");
}
