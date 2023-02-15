//  PROFILING.rs
//    by Lut99
// 
//  Created:
//    15 Jan 2023, 16:28:37
//  Last edited:
//    16 Jan 2023, 12:16:57
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines useful structs that we can use during profiling performance
//!   of the framework (and also workflows / tasks, while at it).
// 

use std::fmt::{Debug, Display, Formatter, Result as FResult};
use std::future::Future;
use std::io::Write;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::error;
use parking_lot::{Mutex, MutexGuard};
use serde::{Deserialize, Serialize};


/***** HELPER FUNCTIONS *****/
/// Writes the TimingReport to the given writer.
/// 
/// # Arguments
/// - `writer`: The `Write`r to write to.
/// - `name`: The name of the timing report to write.
/// - `timings`: The timings in the timing report to write.
/// 
/// # Errors
/// This function errors if we failed to write to the given writer.
fn write_report(writer: &mut impl Write, name: impl AsRef<str>, timings: MutexGuard<Vec<ReportedTiming>>, indent: usize) -> Result<(), std::io::Error> {
    writeln!(writer, "Timing report for {}:", name.as_ref())?;
    for timing in timings.iter() {
        // Match on the kind
        match timing {
            ReportedTiming::Timing(what, timing) => { writeln!(writer, "{}  - Timing results for {}: {}", (0..indent).map(|_| ' ').collect::<String>(), what, timing.lock().display())?; },
            ReportedTiming::Report(report)       => { write!(writer, "{}  - ", (0..indent).map(|_| ' ').collect::<String>())?; write_report(writer, &report.name, report.timings.lock(), indent + 4)?; },
        }
    }

    // Done
    Ok(())
}





/***** HELPERS *****/
/// Wraps around either a Timing or a TimingReport.
#[derive(Debug)]
enum ReportedTiming<'r> {
    /// It's a naked timing
    Timing(String, Arc<Mutex<Timing>>),
    /// It's a nested report
    Report(Arc<TimingReport<'r>>),
}
impl<'r> ReportedTiming<'r> {
    /// Returns a reference to the internal Timing _if_ this was a `ReportedTiming::Timing`.
    /// 
    /// # Returns
    /// A reference to the internal `RefCell<Timing>`.
    /// 
    /// # Panics
    /// This function panics if we were not, in fact, a `ReportedTiming::Timing`.
    #[inline]
    fn timing(&self) -> &Arc<Mutex<Timing>> { if let Self::Timing(_, timing) = self { timing } else { panic!("Cannot unwrap a ReportedTiming::Report as a ReportedTiming::Timing"); } }

    /// Returns a reference to the internal report _if_ this was a `ReportedTiming::Report`.
    /// 
    /// # Returns
    /// A reference to the internal `TimingReport`.
    /// 
    /// # Panics
    /// This function panics if we were not, in fact, a `ReportedTiming::Report`.
    #[inline]
    fn report(&self) -> &Arc<TimingReport<'r>> { if let Self::Report(report) = self { report } else { panic!("Cannot unwrap a ReportedTiming::Timing as a ReportedTiming::Report"); } }
}





/***** AUXILLARY *****/
/// Formats the giving Timing to show a (hopefully) sensible scale to the given formatter.
#[derive(Debug)]
pub struct TimingFormatter<'t>(&'t Timing);
impl<'t> Display for TimingFormatter<'t> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        if self.0.nanos < 10_000 { write!(f, "{}ns", self.0.nanos) }
        else if self.0.nanos < 10_000_000 { write!(f, "{}us", self.0.nanos / 1_000) }
        else if self.0.nanos < 10_000_000_000 { write!(f, "{}ms", self.0.nanos / 1_000_000) }
        else { write!(f, "{}s", self.0.nanos / 1_000_000_000) }
    }
}



/// Defines the TimingGuard, which takes timings until it goes out-of-scope and shows them to stdout.
#[derive(Clone, Debug)]
pub struct TimingGuard<'t> {
    /// The start time of the guard.
    start  : Instant,
    /// The timing that we want to populate, eventually.
    timing : Arc<Mutex<Timing>>,

    /// Fake reference to the parent for better lifetime helpings.
    _parent : PhantomData<&'t ()>,
}
impl<'t> TimingGuard<'t> {
    /// Consumes this TimingGuard to return the time early.
    #[inline]
    pub fn stop(self) {}
}
impl<'t> Drop for TimingGuard<'t> {
    fn drop(&mut self) {
        // Update the time it took us in the internal timing
        *self.timing.lock() = self.start.elapsed().into();
    }
}

/// Defines the ReportGuard, which takes a nested report for easy modification.
#[derive(Clone, Debug)]
pub struct ReportGuard<'w, 'r> {
    /// The report that we want to populate.
    report  : Arc<TimingReport<'w>>,
    /// Fake reference to the parent for better lifetime helpings.
    _parent : PhantomData<&'r ()>,
}
impl<'w, 'r> Deref for ReportGuard<'w, 'r> {
    type Target = TimingReport<'w>;

    fn deref(&self) -> &Self::Target { &self.report }
}





/***** LIBRARY *****/
/// Defines a taken Timing, which represents an amount of time that has passed.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Timing {
    /// The amount of nanoseconds that have passed.
    nanos : u128,
}

impl Timing {
    /// Returns a Timing in which no time has passed.
    /// 
    /// # Returns
    /// A new Timing instance, for which all `Timing::elapsed_XX()` functions will return 0.
    #[inline]
    pub const fn none() -> Self {
        Self{ nanos : 0 }
    }



    /// Writes a human-readable representation of the elapsed time in this Timing.
    /// 
    /// Will attempt to find the correct scale automagically; specifically, will try to write as seconds _unless_ the time is less than that. Then, it will move to milliseconds, all the way up to nanoseconds.
    /// 
    /// # Returns
    /// A TimingFormatter that implements Display to do this kind of formatting on this Timing.
    #[inline]
    pub fn display(&self) -> TimingFormatter { TimingFormatter(self) }

    /// Returns the time that has been elapsed, in seconds.
    /// 
    /// # Returns
    /// The elapsed time that this Timing represents in seconds.
    #[inline]
    pub const fn elapsed_s(&self) -> u128 { self.nanos / 1_000_000_000 }

    /// Returns the time that has been elapsed, in milliseconds.
    /// 
    /// # Returns
    /// The elapsed time that this Timing represents in milliseconds.
    #[inline]
    pub const fn elapsed_ms(&self) -> u128 { self.nanos / 1_000_000 }

    /// Returns the time that has been elapsed, in microseconds.
    /// 
    /// # Returns
    /// The elapsed time that this Timing represents in microseconds.
    #[inline]
    pub const fn elapsed_us(&self) -> u128 { self.nanos / 1_000 }

    /// Returns the time that has been elapsed, in nanoseconds.
    /// 
    /// # Returns
    /// The elapsed time that this Timing represents in nanoseconds.
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
    fn from(value: Duration) -> Self { Timing{ nanos: value.as_nanos() } }
}
impl From<&Duration> for Timing {
    #[inline]
    fn from(value: &Duration) -> Self { Timing{ nanos: value.as_nanos() } }
}
impl From<&mut Duration> for Timing {
    #[inline]
    fn from(value: &mut Duration) -> Self { Timing{ nanos: value.as_nanos() } }
}



/// Defines the TimingReport, which can be used to output various profile things to some file.
// #[derive(Deserialize, Serialize)]
pub struct TimingReport<'w> {
    /// If not None, points to something to report the findings to once the TimingReport goes out-of-scope.
    // #[serde(skip)]
    auto_report : Option<Mutex<Box<dyn 'w + Send + Write>>>,

    /// The name of the report.
    name    : String,
    /// The timings hidden within this report, together with their description.
    timings : Mutex<Vec<ReportedTiming<'w>>>,
}

impl<'w> TimingReport<'w> {
    /// Constructor for the TimingReport that initializes it to new.
    /// 
    /// # Arguments
    /// - `name`: The name of the report so that it is identifyable in case multiple reports are being written.
    /// 
    /// # Returns
    /// A new TimingReport that can be used to report... timings...
    #[inline]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            auto_report : None,

            name    : name.into(),
            timings : Mutex::new(Vec::new()),
        }
    }

    /// Constructor for the TimingReport that will automatically report it to the given `Write`r when it goes out-of-scope.
    /// 
    /// # Arguments
    /// - `name`: The name of the report so that it is identifyable in case multiple reports are being written.
    /// - `writer`: The `Write`r to write to once we drop ourselves. Note that any failure to write to this writer will be reported using `error!()`, but not considered fatal.
    /// 
    /// # Returns
    /// A new TimingReport that can be used to report... timings...
    #[inline]
    pub fn auto_report(name: impl Into<String>,writer: impl 'w + Send + Write) -> Self {
        Self {
            auto_report : Some(Mutex::new(Box::new(writer))),

            name    : name.into(),
            timings : Mutex::new(Vec::new()),
        }
    }



    /// Record a given Timing in this report.
    /// 
    /// If the given `what` already exists, overrides the timing for it silently.
    /// 
    /// # Arguments
    /// - `what`: Some description of the Timing we are reporting. Should fill in the blank in `Timing results for ...`.
    /// - `timing`: The Timing to register.
    #[inline]
    pub fn add(&self, what: impl Into<String>, timing: impl Into<Timing>) {
        let mut timings: MutexGuard<Vec<ReportedTiming>> = self.timings.lock();
        if timings.capacity() == timings.len() { let extra: usize = timings.len(); timings.reserve(extra); }
        timings.push(ReportedTiming::Timing(what.into(), Arc::new(Mutex::new(timing.into()))));
    }

    /// Start recording a timing in this report, returning a TimingGuard that can be used to stop it.
    /// 
    /// The timing will automatically stop if the TimingGuard goes out-of-scope.
    /// 
    /// # Arguments
    /// - `what`: Some description of the Timing we are reporting. Should fill in the blank in `Timing results for ...`.
    /// 
    /// # Returns
    /// A TimingGuard instance that can be used to finalize the timing.
    pub fn guard(&self, what: impl Into<String>) -> TimingGuard {
        // Insert the new timing
        let mut timings: MutexGuard<Vec<ReportedTiming>> = self.timings.lock();
        if timings.capacity() == timings.len() { let extra: usize = timings.len(); timings.reserve(extra); }
        timings.push(ReportedTiming::Timing(what.into(), Arc::new(Mutex::new(Timing::none()))));

        // Return the guard for that timing
        let timings_len: usize = timings.len();
        TimingGuard {
            start  : Instant::now(),
            timing : timings[timings_len - 1].timing().clone(),

            _parent : PhantomData::default(),
        }
    }

    /// Adds the time the given function takes to the report.
    /// 
    /// # Arguments
    /// - `what`: Some description of the Timing we are reporting. Should fill in the blank in `Timing results for ...`.
    /// - `func`: The Function to profile.
    /// 
    /// # Returns
    /// The result of the function we've profiled.
    #[inline]
    pub fn func<R>(&self, what: impl Into<String>, func: impl FnOnce() -> R) -> R {
        // Profile the function
        let start   : Instant = Instant::now();
        let res     : R       = func();
        let elapsed : Timing  = start.elapsed().into();

        // Insert the timing and return the result
        let mut timings: MutexGuard<Vec<ReportedTiming>> = self.timings.lock();
        if timings.capacity() == timings.len() { let extra: usize = timings.len(); timings.reserve(extra); }
        timings.push(ReportedTiming::Timing(what.into(), Arc::new(Mutex::new(elapsed))));
        res
    }
    /// Adds the time the given future takes to the report.
    /// 
    /// # Arguments
    /// - `what`: Some description of the Timing we are reporting. Should fill in the blank in `Timing results for ...`.
    /// - `func`: The Future to profile.
    /// 
    /// # Returns
    /// The result of the function we've profiled.
    #[inline]
    pub async fn fut<R>(&self, what: impl Into<String>, func: impl Future<Output = R>) -> R {
        // Profile the function
        let start   : Instant = Instant::now();
        let res     : R       = func.await;
        let elapsed : Timing  = start.elapsed().into();

        // Insert the timing and return the result
        let mut timings: MutexGuard<Vec<ReportedTiming>> = self.timings.lock();
        if timings.capacity() == timings.len() { let extra: usize = timings.len(); timings.reserve(extra); }
        timings.push(ReportedTiming::Timing(what.into(), Arc::new(Mutex::new(elapsed))));
        res
    }



    /// Creates a nested TimingReport, then returns a reference to it such that we may find what we are looking for.
    /// 
    /// The nested report will have auto_reported set to `None`, but will still be written when this parent auto-reports (if set to do so).
    /// 
    /// # Arguments
    /// - `name`: The name of the new TimingReport.
    /// 
    /// # Returns
    /// A mutable reference to the new report so that it can be altered immediately.
    pub fn nested_report<'s>(&'s self, name: impl Into<String>) -> ReportGuard<'w, 's> {
        // Create the report
        let mut timings: MutexGuard<Vec<ReportedTiming>> = self.timings.lock();
        if timings.capacity() == timings.len() { let extra: usize = timings.len(); timings.reserve(extra); }
        timings.push(ReportedTiming::Report(Arc::new(TimingReport {
            auto_report : None,

            name    : name.into(),
            timings : Mutex::new(vec![]),
        })));

        // Return the reference
        let timings_len: usize = timings.len();
        ReportGuard {
            report  : timings[timings_len - 1].report().clone(),
            _parent : PhantomData::default(),
        }
    }
}
impl<'w> Drop for TimingReport<'w> {
    fn drop(&mut self) {
        // If we automatically report, do so
        if let Some(writer) = &mut self.auto_report {
            let mut writer: MutexGuard<Box<dyn Send + Write>> = writer.lock();
            if let Err(err) = write_report(&mut *writer, &self.name, self.timings.lock(), 0) { error!("Failed to automatically report TimingReport '{}': {}", self.name, err); }
        }
    }
}

impl<'w> Debug for TimingReport<'w> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        // Unpack the report for better knowing when we have to extend upon this function
        let Self{ auto_report, name, timings } = self;

        // Print it
        if f.alternate() {
            writeln!(f, "TimingReport{{")?;
            writeln!(f, "    auto_report : {}", if auto_report.is_some() { "Some(Box<dyn Write>)" } else { "None" })?;
            writeln!(f, "    name        : {}", name)?;
            writeln!(f, "    timings     : {:#?}", timings)?;
            writeln!(f, "}}")?;
        } else {
            write!(f, "TimingReport{{ auto_report: {}, name: {}, timings: {:?} }}", if auto_report.is_some() { "Some(Box<dyn Write>)" } else { "None" }, name, timings)?;
        }

        // Done
        Ok(())
    }
}

impl<'w> AsRef<TimingReport<'w>> for TimingReport<'w> {
    #[inline]
    fn as_ref(&self) -> &Self { self }
}
