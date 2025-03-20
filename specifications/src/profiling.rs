//  PROFILING.rs
//    by Lut99
//
//  Created:
//    01 Feb 2023, 09:54:51
//  Last edited:
//    06 Feb 2024, 12:53:50
//  Auto updated?
//    Yes
//
//  Description:
//!   A second version of the profiling library, with better support for
//!   generate dynamic yet pretty and (most of all) ordered profiling
//!   logs.
//!   
//!   Note that, while this library is not designed for Edge timings (i.e.,
//!   user-relevant profiling), some parts of it can probably be re-used for
//!   that (especially the Timing struct).
//

use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::fs::File;
use std::future::Future;
use std::io::Write;
use std::marker::PhantomData;
use std::ops::Deref;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use enum_debug::EnumDebug;
use log::warn;
use parking_lot::{Mutex, MutexGuard};
use serde::{Deserialize, Serialize};


/***** HELPER MACROS *****/
/// Formats a given number of spaces.
macro_rules! spaces {
    ($n:expr) => {
        " ".repeat($n)
    };
}





/***** HELPER ENUMS *****/
/// Defines an enum that abstracts of the specific kind of timing (i.e., branch or leaf).
#[derive(Debug, Deserialize, EnumDebug, Serialize)]
enum ProfileTiming {
    /// It's a single Timing (i.e., a leaf)
    Timing(String, Arc<Mutex<Timing>>),
    /// It's a nested scope.
    Scope(Arc<ProfileScope>),
}
impl ProfileTiming {
    /// Returns the internal Timing.
    ///
    /// # Panics
    /// This function panics if we were not a timing but a `ProfileTiming::Scope` instead.
    #[inline]
    fn timing(&self) -> &Arc<Mutex<Timing>> {
        if let Self::Timing(_, timing) = self {
            timing
        } else {
            panic!("Cannot unwrap ProfileTiming::{} as ProfileTiming::Timing", self.variant());
        }
    }

    /// Returns whether this `ProfileTiming` is a scope.
    #[inline]
    fn is_scope(&self) -> bool { matches!(self, Self::Scope(_)) }

    /// Returns the internal [`ProfileScope`].
    ///
    /// # Panics
    /// This function panics if we were not a scope but a `ProfileTiming::Timing` instead.
    #[inline]
    fn scope(&self) -> &Arc<ProfileScope> {
        if let Self::Scope(scope) = self {
            scope
        } else {
            panic!("Cannot unwrap ProfileTiming::{} as ProfileTiming::Scope", self.variant());
        }
    }
}





/***** FORMATTERS *****/
/// Formats the giving Timing to show a (hopefully) sensible scale to the given formatter.
#[derive(Debug)]
pub struct TimingFormatter<'t>(&'t Timing);
impl Display for TimingFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        if self.0.nanos < 10_000 {
            write!(f, "{}ns", self.0.nanos)
        } else if self.0.nanos < 10_000_000 {
            write!(f, "{}us", self.0.nanos / 1_000)
        } else if self.0.nanos < 10_000_000_000 {
            write!(f, "{}ms", self.0.nanos / 1_000_000)
        } else {
            write!(f, "{}s", self.0.nanos / 1_000_000_000)
        }
    }
}



/// Formats the given [`ProfileReport`] to show a new list of results (but with a clear toplevel).
#[derive(Debug)]
pub struct ProfileReportFormatter<'r> {
    /// The scope of the toplevel report to write.
    scope: &'r ProfileScope,
}
impl Display for ProfileReportFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        writeln!(f, "### Timing report for {} ###", self.scope.name)?;
        write!(f, "{}", self.scope.display())
    }
}



/// Formats the given [`ProfileScope`] to show a neat list of results.
#[derive(Debug)]
pub struct ProfileScopeFormatter<'s> {
    /// The scope to format.
    scope:  &'s ProfileScope,
    /// The indentation to format with.
    indent: usize,
}
impl Display for ProfileScopeFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        // Print the internal timings
        let mut newline: bool = false;
        for t in self.scope.timings.lock().iter() {
            // Add a newline if required
            if t.is_scope() || newline {
                writeln!(f)?;
            }

            // Write the entry
            use ProfileTiming::*;
            match t {
                Timing(name, timing) => {
                    // Write the timing as a list item
                    writeln!(f, "{}  - {} timing results: {}", spaces!(self.indent), name, timing.lock().display())?;
                    newline = false;
                },

                Scope(scope) => {
                    // Write the scope also as a list item
                    writeln!(f, "{}  - {} timing results:", spaces!(self.indent), scope.name)?;
                    write!(f, "{}", scope.display_indented(self.indent + 4))?;
                    newline = true;
                },
            }
        }

        // Done
        Ok(())
    }
}





/***** AUXILLARY *****/
/// Defines a taken `Timing`, which represents an amount of time that has passed.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Timing {
    /// The amount of nanoseconds that have passed.
    nanos: u128,
}

impl Timing {
    /// Returns a `Timing` in which no time has passed.
    ///
    /// # Returns
    /// A new `Timing` instance, for which all `Timing::elapsed_XX()` functions will return 0.
    #[inline]
    pub const fn none() -> Self { Self { nanos: 0 } }

    /// Writes a human-readable representation of the elapsed time in this Timing.
    ///
    /// Will attempt to find the correct scale automagically; specifically, will try to write as seconds _unless_ the time is less than that. Then, it will move to milliseconds, all the way up to nanoseconds.
    ///
    /// # Returns
    /// A [`TimingFormatter`] that implements Display to do this kind of formatting on this Timing.
    #[inline]
    pub fn display(&self) -> TimingFormatter { TimingFormatter(self) }

    /// Returns the time that has been elapsed, in seconds.
    ///
    /// # Returns
    /// The elapsed time that this `Timing` represents in seconds.
    #[inline]
    pub const fn elapsed_s(&self) -> u128 { self.nanos / 1_000_000_000 }

    /// Returns the time that has been elapsed, in milliseconds.
    ///
    /// # Returns
    /// The elapsed time that this `Timing` represents in milliseconds.
    #[inline]
    pub const fn elapsed_ms(&self) -> u128 { self.nanos / 1_000_000 }

    /// Returns the time that has been elapsed, in microseconds.
    ///
    /// # Returns
    /// The elapsed time that this `Timing` represents in microseconds.
    #[inline]
    pub const fn elapsed_us(&self) -> u128 { self.nanos / 1_000 }

    /// Returns the time that has been elapsed, in nanoseconds.
    ///
    /// # Returns
    /// The elapsed time that this `Timing` represents in nanoseconds.
    #[inline]
    pub const fn elapsed_ns(&self) -> u128 { self.nanos }
}

impl AsRef<Timing> for Timing {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
impl From<&Timing> for Timing {
    #[inline]
    fn from(value: &Timing) -> Self { *value }
}
impl From<&mut Timing> for Timing {
    #[inline]
    fn from(value: &mut Timing) -> Self { *value }
}

impl From<Duration> for Timing {
    #[inline]
    fn from(value: Duration) -> Self { Timing { nanos: value.as_nanos() } }
}
impl From<&Duration> for Timing {
    #[inline]
    fn from(value: &Duration) -> Self { Timing { nanos: value.as_nanos() } }
}
impl From<&mut Duration> for Timing {
    #[inline]
    fn from(value: &mut Duration) -> Self { Timing { nanos: value.as_nanos() } }
}



/// Defines the `TimerGuard`, which takes a [`Timing`] as long as it is in scope.
#[derive(Debug)]
pub struct TimerGuard<'s> {
    /// The start of the timing.
    start:     Instant,
    /// The timing to populate.
    timing:    Arc<Mutex<Timing>>,
    /// We mark the phantom lifetime because the above is a weak reference
    _lifetime: PhantomData<&'s ()>,
}
impl TimerGuard<'_> {
    /// Early stop the timer. This effectively just janks the guard out-of-scope by taking ownership of it.
    #[inline]
    pub fn stop(self) {}
}
impl Drop for TimerGuard<'_> {
    fn drop(&mut self) {
        // Set it, done
        let mut lock: MutexGuard<Timing> = self.timing.lock();
        *lock = self.start.elapsed().into();
    }
}



/// Provides a convenience wrapper around a reference to a [`ProfileScope`].
#[derive(Clone, Debug)]
pub struct ProfileScopeHandle<'s> {
    /// The actual scope itself.
    scope:     Arc<ProfileScope>,
    /// A lifetime which allows us to assume the weak reference is valid.
    _lifetime: PhantomData<&'s ()>,
}
impl ProfileScopeHandle<'static> {
    /// Provides a dummy handle for if you are not interested in profiling, but need to use the functions.
    #[inline]
    pub fn dummy() -> Self { Self { scope: Arc::new(ProfileScope::new("<<<dummy>>>")), _lifetime: PhantomData } }
}
impl ProfileScopeHandle<'_> {
    /// Finishes a scope, by janking the handle wrapping it out-of-scope.
    #[inline]
    pub fn finish(self) {}
}
impl Deref for ProfileScopeHandle<'_> {
    type Target = ProfileScope;

    #[inline]
    fn deref(&self) -> &Self::Target { &self.scope }
}

/// Provides a convenience wrapper around a reference to a [`ProfileScope`] that ignores the lifetime mumbo.
///
/// If this object outlives its parent scope, there won't be any errors; _however_, note that the profilings collected afterwards will not be printed.
#[derive(Clone, Debug)]
pub struct ProfileScopeHandleOwned {
    /// The actual scope itself.
    scope: Arc<ProfileScope>,
}
impl ProfileScopeHandleOwned {
    /// Provides a dummy handle for if you are not interested in profiling, but need to use the functions.
    #[inline]
    pub fn dummy() -> Self { Self { scope: Arc::new(ProfileScope::new("<<<dummy>>>")) } }
}
impl ProfileScopeHandleOwned {
    /// Finishes a scope, by janking the handle wrapping it out-of-scope.
    #[inline]
    pub fn finish(self) {}
}
impl Deref for ProfileScopeHandleOwned {
    type Target = ProfileScope;

    #[inline]
    fn deref(&self) -> &Self::Target { &self.scope }
}

impl<'s> From<ProfileScopeHandle<'s>> for ProfileScopeHandleOwned {
    #[inline]
    fn from(value: ProfileScopeHandle<'s>) -> Self { Self { scope: value.scope } }
}





/***** LIBRARY *****/
/// Defines the toplevel `ProfileReport` that writes to stdout or disk or whatever when it goes out-of-scope.
#[derive(Debug, Deserialize, Serialize)]
pub struct ProfileReport<W: Write> {
    /// The writer that we wrap.
    writer: Option<W>,
    /// The toplevel scope that we wrap. NOTE: Is [`Option`] to extract it at [`ProfileReport::into_scope()`].
    scope:  Option<ProfileScope>,
}

impl ProfileReport<File> {
    /// Constructor for the `ProfileReport` that will write it to a file in a default location (`/logs/profile`) with a default name (date & time of the profile state) when it goes out-of-scope.
    ///
    /// # Arguments
    /// - `name`: The name for the toplevel scope in this report.
    /// - `filename`: A more snake-case-like filename for the file.
    ///
    /// # Returns
    /// A new `ProfileReport` instance.
    pub fn auto_reporting_file(name: impl Into<String>, file_name: impl Into<String>) -> Self {
        // Define the target path
        let now: DateTime<Local> = Local::now();
        let path: PathBuf =
            PathBuf::from("/logs").join("profile").join(format!("profile_{}_{}.txt", file_name.into(), now.format("%Y-%m-%d_%H-%M-%s")));

        // Attempt to open the file
        let handle: Option<File> = match File::create(&path) {
            Ok(handle) => Some(handle),
            Err(err) => {
                warn!("Failed to create profile log file '{}': {} (report will not be auto-printed)", path.display(), err);
                None
            },
        };

        // Run the thing
        Self { writer: handle, scope: Some(ProfileScope::new(name)) }
    }
}
impl<W: Write> ProfileReport<W> {
    /// Constructor for the `ProfileReport` that will write it to the given `Write`r when it goes out-of-scope.
    ///
    /// # Arguments
    /// - `name`: The name for the toplevel scope in this report.
    /// - `writer`: The `Write`-enabled writer that we will write to upon dropping.
    ///
    /// # Returns
    /// A new `ProfileReport` instance.
    #[inline]
    pub fn auto_reporting(name: impl Into<String>, writer: impl Into<W>) -> Self {
        Self { writer: Some(writer.into()), scope: Some(ProfileScope::new(name)) }
    }

    /// Returns the inner scope that can be used without worrying about auto-reporting.
    ///
    /// # Returns
    /// A reference to the [`ProfileScope`] that can be used to do anything except the gnarly auto-reporting.
    #[inline]
    pub fn scope(&self) -> &ProfileScope { self.scope.as_ref().unwrap() }

    /// Returns the inner scope that can be used without worrying about auto-reporting.
    ///
    /// # Returns
    /// A [`ProfileScope`] that can be used to do anything except the gnarly auto-reporting.
    #[inline]
    pub fn into_scope(mut self) -> ProfileScope {
        let scope: ProfileScope = self.scope.take().unwrap();
        std::mem::forget(self);
        scope
    }
}
impl<W: Write> Drop for ProfileReport<W> {
    fn drop(&mut self) {
        // Simply try to write to our internal thing, if any
        if let Some(writer) = &mut self.writer {
            let scope: &ProfileScope = self.scope.as_ref().unwrap();
            if let Err(err) = write!(writer, "{}", ProfileReportFormatter { scope }) {
                warn!("Failed to auto-report ProfileReport '{}': {}", scope.name, err);
            };
        }
    }
}

impl<W: Write> Deref for ProfileReport<W> {
    type Target = ProfileScope;

    #[inline]
    fn deref(&self) -> &Self::Target { self.scope.as_ref().unwrap() }
}



/// Defines a scope within a [`ProfileReport`].
#[derive(Debug, Deserialize, Serialize)]
pub struct ProfileScope {
    /// The name of the scope.
    name:    String,
    /// The timings in this scope.
    timings: Mutex<Vec<ProfileTiming>>,
}

impl ProfileScope {
    /// Constructor for the `ProfileScope`.
    ///
    /// # Arguments
    /// - `name`: The name of the `ProfileScope`.
    ///
    /// # Returns
    /// A new `ProfileScope` instance.
    pub fn new(name: impl Into<String>) -> Self { Self { name: name.into(), timings: Mutex::new(vec![]) } }

    /// Returns a [`TimerGuard`], which takes a time exactly as long as it is in scope.
    ///
    /// # Arguments
    /// - `name`: The name to set for this Timing.
    ///
    /// # Returns
    /// A new [`Timer`] struct to take a timing.
    pub fn time(&self, name: impl Into<String>) -> TimerGuard {
        // Get a lock
        let mut lock: MutexGuard<Vec<ProfileTiming>> = self.timings.lock();

        // Create the entry
        lock.push(ProfileTiming::Timing(name.into(), Arc::new(Mutex::new(Timing::none()))));

        // Create a TimerGuard around that timing.
        let timing: Arc<Mutex<Timing>> = lock.last().unwrap().timing().clone();
        TimerGuard { start: Instant::now(), timing, _lifetime: PhantomData }
    }

    /// Profiles the given function and adds its timing under the given name.
    ///
    /// # Arguments
    /// - `name`: The name to set for this Timing.
    /// - `func`: The function to profile.
    ///
    /// # Returns
    /// The result of the function, if any.
    pub fn time_func<R>(&self, name: impl Into<String>, func: impl FnOnce() -> R) -> R {
        // Time the function
        let start: Instant = Instant::now();
        let res: R = func();
        let end: Timing = start.elapsed().into();

        // Add the timing internally
        let mut lock: MutexGuard<Vec<ProfileTiming>> = self.timings.lock();
        lock.push(ProfileTiming::Timing(name.into(), Arc::new(Mutex::new(end))));

        // Return the result
        res
    }

    /// Profiles the given future by creating a future that times it while running.
    ///
    /// # Arguments
    /// - `name`: The name to set for this Timing.
    /// - `fut`: The Future to profile.
    ///
    /// # Returns
    /// A future that returns the same result as the given, but times its execution as a side-effect.
    pub fn time_fut<'s, R>(&'s self, name: impl Into<String>, fut: impl 's + Future<Output = R>) -> impl 's + Future<Output = R> {
        let name: String = name.into();

        // Before we begin, we add the timing to respect the ordering
        let timing: Arc<Mutex<Timing>> = {
            let mut lock: MutexGuard<Vec<ProfileTiming>> = self.timings.lock();
            lock.push(ProfileTiming::Timing(name, Arc::new(Mutex::new(Timing::none()))));
            lock.last().unwrap().timing().clone()
        };

        // Now profile the future
        async move {
            // Time the future
            let start: Instant = Instant::now();
            let res: R = fut.await;
            let end: Timing = start.elapsed().into();

            // Add the timing internally
            let mut lock: MutexGuard<Timing> = timing.lock();
            *lock = end;

            // Return the result
            res
        }
    }

    /// Returns a new `ProfileScope` that can be used to do more elaborate nested timings.
    ///
    /// # Arguments
    /// - `name`: The name of the new scope.
    ///
    /// # Returns
    /// A new `ProfileScope` that can be used to take timings.
    pub fn nest(&self, name: impl Into<String>) -> ProfileScopeHandle {
        // Create the new scope
        let scope: Self = Self::new(name);

        // Insert it internally
        let mut lock: MutexGuard<Vec<ProfileTiming>> = self.timings.lock();
        lock.push(ProfileTiming::Scope(Arc::new(scope)));

        // Return a weak reference to it
        ProfileScopeHandle { scope: lock.last().unwrap().scope().clone(), _lifetime: PhantomData }
    }

    /// Profiles the given function, but provides it with extra profile options by giving it its own `ProfileScope` to populate.
    ///
    /// Note that the `ProfileScope` is already automatically given a "total"-timing, representing the function's profiling. This is still untimed as long as the function sees it, obviously.
    ///
    /// # Arguments
    /// - `name`: The name to set for this Timing.
    /// - `func`: The function to profile.
    ///
    /// # Returns
    /// The result of the function, if any.
    pub fn nest_func<R>(&self, name: impl Into<String>, func: impl FnOnce(ProfileScopeHandle) -> R) -> R {
        // Create a new scope
        let scope: ProfileScopeHandle = self.nest(name);

        // Add an entry for the scope
        let timing: Arc<Mutex<Timing>> = {
            let mut lock: MutexGuard<Vec<ProfileTiming>> = scope.timings.lock();
            lock.push(ProfileTiming::Timing("total".into(), Arc::new(Mutex::new(Timing::none()))));
            lock.last().unwrap().timing().clone()
        };

        // Time the function
        let start: Instant = Instant::now();
        let res: R = func(scope);
        let end: Timing = start.elapsed().into();

        // Set that time
        let mut lock: MutexGuard<Timing> = timing.lock();
        *lock = end;

        // Return the result
        res
    }

    /// Profiles the given future by creating a future that times it while running, but provides it with extra profile options by giving it its own `ProfileScope` to popupate.
    ///
    /// Note that the `ProfileScope` is already automatically given a "total"-timing, representing the future's profiling. This is still untimed as long as the future sees it, obviously.
    ///
    /// # Arguments
    /// - `name`: The name to set for this Timing.
    /// - `fut`: The Future to profile.
    ///
    /// # Returns
    /// A future that returns the same result as the given, but times its execution as a side-effect.
    pub fn nest_fut<'s, F: Future>(
        &'s self,
        name: impl Into<String>,
        fut: impl 's + FnOnce(ProfileScopeHandle<'s>) -> F,
    ) -> impl 's + Future<Output = F::Output> {
        let name: String = name.into();

        // Create a new scope
        let scope: ProfileScopeHandle = self.nest(name);

        // Add an entry for the scope
        let timing: Arc<Mutex<Timing>> = {
            let mut lock: MutexGuard<Vec<ProfileTiming>> = scope.timings.lock();
            lock.push(ProfileTiming::Timing("total".into(), Arc::new(Mutex::new(Timing::none()))));
            lock.last().unwrap().timing().clone()
        };

        // Now profile the future
        async move {
            // Time the future
            let start: Instant = Instant::now();
            let res: F::Output = fut(scope).await;
            let end: Timing = start.elapsed().into();

            // Add the timing internally
            let mut lock: MutexGuard<Timing> = timing.lock();
            *lock = end;

            // Return the result
            res
        }
    }

    /// Returns a formatter that neatly displays the results of this scope.
    ///
    /// Note that this does _not_ end with a newline, so typically you want to call `writeln!()`/`println!()` on this.
    ///
    /// # Returns
    /// A new [`ProfileScopeFormatter`].
    #[inline]
    pub fn display(&self) -> ProfileScopeFormatter { ProfileScopeFormatter { scope: self, indent: 0 } }

    /// Returns a formatter that neatly displays the results of this scope with a given number of spaces before each line.
    ///
    /// Note that this does _not_ end with a newline, so typically you want to call `writeln!()`/`println!()` on this.
    ///
    /// # Arguments
    /// - `indent`: The number of spaces to print before each line.
    ///
    /// # Returns
    /// A new [`ProfileScopeFormatter`].
    #[inline]
    pub fn display_indented(&self, indent: usize) -> ProfileScopeFormatter { ProfileScopeFormatter { scope: self, indent } }
}
