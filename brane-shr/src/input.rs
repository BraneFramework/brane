//  INPUT.rs
//    by Lut99
//
//  Created:
//    06 Jun 2023, 18:38:50
//  Last edited:
//    07 Jun 2023, 15:46:31
//  Auto updated?
//    Yes
//
//  Description:
//!   Contains functions for prompting the user in the various user-facing
//!   executables.
//

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::fmt::{Display, Formatter, Result as FResult, Write as _};
use std::fs::{self, DirEntry, ReadDir};
use std::hash::Hash;
use std::path::PathBuf;
use std::str::FromStr;
use std::{error, mem};

use dialoguer::theme::ColorfulTheme;
use dialoguer::{Completion, Confirm, History, Input, Select};
use log::{info, warn};

const HISTORY_CAPACITY: usize = 500;


/***** ERRORS *****/
/// Defines the errors that may occur when running any of the input functions.
#[derive(Debug)]
pub enum Error {
    /// Failed to run a confirm prompt
    Confirm { err: dialoguer::Error },
    /// Failed to run a select prompt
    Select { n_opts: usize, err: dialoguer::Error },
    /// Failed to run a text prompt
    Text { err: dialoguer::Error },
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Error::*;
        match self {
            Confirm { .. } => write!(f, "Failed to prompt the user (you!) to answer yes or no"),
            Select { n_opts, .. } => write!(f, "Failed to prompt the user (you!) to select one of {n_opts} options"),
            Text { .. } => write!(f, "Failed to prompt the user (you!) for a string input"),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use Error::*;
        match self {
            Confirm { err, .. } => Some(err),
            Select { err, .. } => Some(err),
            Text { err, .. } => Some(err),
        }
    }
}





/***** HISTORIES *****/
/// Defines a history that relates to a particular file.
///
/// Will automatically write-back on dropping.
#[derive(Clone, Debug)]
pub struct FileHistory {
    /// Defines the path to write the history to upon destruction.
    path:    PathBuf,
    /// Defines the in-memory history.
    history: VecDeque<String>,
}

impl FileHistory {
    /// Create an empty File History
    ///
    /// # Arguments
    /// - `path`: Points to the location of this history's file.
    ///
    /// # Returns
    /// A new FileHistory instance.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            history: Default::default(),
        }
    }

    /// Constructor for the FileHistory.
    ///
    /// Attempts to read the history from the given `path`, and writes it back when this struct is dropped (unless [`Self::forget()`] is called). To this end, avoid having two FileHistory's that point to the same file.
    ///
    /// # Arguments
    /// - `path`: Points to the location of this history's file.
    ///
    /// # Returns
    /// A new FileHistory instance.
    ///
    /// # Warnings
    /// This function emits warnings using [`warn!()`] when it fails to read the file.
    pub fn from_file(path: impl Into<PathBuf>) -> Result<Self, std::io::Error> {
        let path: PathBuf = path.into();

        // Attempt to read the file
        let raw: String = fs::read_to_string(&path)?;

        // Store it as line-separated, and restore escaped characters
        let iter = raw.lines().map(|s| s.to_string());
        let mut history: VecDeque<String> = Default::default();
        for line in iter {
            // Deflate the special characters by parsing them
            let mut escaping: bool = false;
            let mut new_line: String = String::with_capacity(line.len());
            for c in line.chars() {
                if !escaping && c == '\\' {
                    escaping = true;
                } else if escaping && c == 'n' {
                    new_line.push('\n');
                } else if escaping && c == 'r' {
                    new_line.push('\r');
                } else {
                    new_line.push(c);
                    escaping = false;
                }
            }

            // Add it to the list
            history.push_back(new_line);
        }

        // We can now save the restored history
        Ok(Self { path, history })
    }

    /// Read a file history from disk or create a new instance
    ///
    /// # Arguments
    /// - `path`: Points to the location of this history's file.
    ///
    /// # Returns
    /// A new FileHistory instance.
    pub fn from_file_or_new(path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = path.into();

        Self::from_file(path.clone()).unwrap_or_else(|err| {
            info!("Failed to read history file '{}': {}", path.display(), err);
            Self::new(path)
        })
    }

    /// Drops this history without saving it.
    pub fn forget(self) { mem::forget(self); }
}
impl Drop for FileHistory {
    fn drop(&mut self) {
        // Convert the history to an escaped, line-separated string
        let mut raw: String = String::new();
        for line in &self.history {
            // Reserve enough space
            raw.reserve(line.len() + 2);

            // Copy the line char-by-char to escape characters
            for c in line.chars() {
                if c == '\n' {
                    raw.push_str("\\n");
                } else if c == '\r' {
                    raw.push_str("\\r");
                } else if c == '\\' {
                    raw.push_str("\\\\");
                } else {
                    raw.push(c);
                }
            }

            // Add the end-of-line
            writeln!(&mut raw).unwrap();
        }

        // Attempt to write that to the path
        if let Err(err) = fs::write(&self.path, raw) {
            warn!("Failed to save history to '{}': {}", self.path.display(), err);
        }
    }
}

impl History<String> for FileHistory {
    #[inline]
    fn read(&self, pos: usize) -> Option<String> { self.history.get(pos).cloned() }

    fn write(&mut self, val: &String) {
        // Pop the front if we don't have the space
        while self.history.len() >= HISTORY_CAPACITY {
            self.history.pop_back();
        }

        // Simply push to the end
        if self.history.len() == self.history.capacity() {
            self.history.reserve(self.history.len());
        }
        self.history.push_front(val.clone());
    }
}





/***** AUTOCOMPLETERS *****/
/// Autocompletes files
#[derive(Clone, Copy, Debug)]
pub struct FileAutocompleter;
impl Completion for FileAutocompleter {
    fn get(&self, input: &str) -> Option<String> {
        // Get the input as a directory and some filter in that directory
        let (dir, filter): (&str, &str) = match input.rfind('/') {
            Some(pos) => (&input[..pos + 1], &input[pos + 1..]),
            None => ("./", input),
        };

        // Attempt to find all entries that are allowed by the filter in that directory
        let mut targets: Vec<String> = vec![];
        let entries: ReadDir = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) => {
                warn!("Failed to read directory '{dir}': {err}");
                return None;
            },
        };
        for (i, entry) in entries.enumerate() {
            // Unwrap the entry
            let entry: DirEntry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!("Failed to unwrap directory '{dir}' entry {i}: {err}");
                    return None;
                },
            };

            // Filter the entry
            let sentry: OsString = entry.file_name();
            let sentry: Cow<str> = sentry.to_string_lossy();
            if sentry.len() < filter.len() || &sentry[..filter.len()] != filter {
                continue;
            }

            // Otherwise, add it as a possibility
            // Before we do, add an optional '/' if this is a directory
            let sentry: String = if entry.path().is_dir() { format!("{dir}{sentry}/") } else { format!("{dir}{sentry}") };

            // Otherwise, add it as possibility
            targets.push(sentry);
        }

        // The guess is the largest complete part of all entries
        let mut common: Option<(String, usize)> = None;
        for target in targets {
            // Check if we already saw a target
            if let Some((value, length)) = &mut common {
                // Truncate the length to be the smallest of the two
                *length = std::cmp::min(target.len(), *length);

                // Compare this with the new value to find the largest subset
                let (mut new, mut old) = (target[..*length].char_indices(), value[..*length].chars());
                while let (Some((i, c1)), Some(c2)) = (new.next(), old.next()) {
                    if c1 != c2 {
                        // We update the prefix length to encapsulate the largest part
                        *length = i;
                    }
                }
            } else {
                let target_len: usize = target.len();
                common = Some((target, target_len));
            }
        }

        // Return what we found
        common.map(|(mut p, l)| {
            p.truncate(l);
            p
        })
    }
}


/***** VALIDATORS *****/
/// A validator can be used to provide a shared concrete type when none are available.
pub type NoValidator = fn(&String) -> Result<(), String>;



/***** LIBRARY *****/
/// Prompts the user with a yes/no question.
///
/// # Arguments
/// - `prompt`: The prompt to display to the user.
/// - `default`: If not [`None`], allows the user to answer a default yes/no based on the given boolean value (true for yes, false for no).
///
/// # Returns
/// True if the user answered yes, or else false.
///
/// # Errors
/// This function errors if we failed to interact with the user.
pub fn confirm(prompt: impl ToString, default: Option<bool>) -> Result<bool, Error> {
    // Construct the prompt
    let theme: ColorfulTheme = ColorfulTheme::default();
    let mut confirm: Confirm = Confirm::with_theme(&theme);
    confirm = confirm.with_prompt(prompt.to_string());
    if let Some(default) = default {
        confirm = confirm.default(default);
    }

    // Run the prompt
    match confirm.interact() {
        Ok(res) => Ok(res),
        Err(err) => Err(Error::Confirm { err }),
    }
}



/// Prompts the user for a string.
///
/// # Generic arguments
/// - `S`: The [`FromStr`]-capable type to query.
///
/// # Arguments
/// - `what`: Some string description to show to the user that tells them what kind of thing they are inputting. Should fill in: `Invalid ...`. Only used in the case they fail the first time.
/// - `prompt`: The prompt to display to the user.
/// - `default`: Any default value to give, or else [`None`].
/// - `validator`: A validator that implements the [`dialoguer::InputValidator`] trait, or None if it is not possible. You can use the [`NoValidator`] concrete type when using no validator like so `None::<NoValidator>`
/// - `history`: An optional [`History`]-capabable struct that can be used to keep track of this prompt's history.
///
/// # Returns
/// The users inputted value for `S`.
///
/// # Errors
/// This function errors if we failed to interact with the user.
pub fn input<S, VA>(
    what: impl Display,
    prompt: impl ToString,
    default: Option<impl Into<S>>,
    validator: Option<VA>,
    mut history: Option<impl History<String>>,
) -> Result<S, Error>
where
    S: FromStr + ToString,
    S::Err: error::Error,
    VA: dialoguer::InputValidator<String>,
    VA::Err: ToString,
{
    // Preprocess the input
    let mut prompt: String = prompt.to_string();
    let default: Option<S> = default.map(|d| d.into());

    // Loop until the user enters a valid value.
    let theme: ColorfulTheme = ColorfulTheme::default();

    // Construct the prompt
    let mut input: Input<String> = Input::with_theme(&theme);
    if let Some(default) = &default {
        input = input.default(default.to_string());
    }
    if let Some(history) = &mut history {
        input = input.history_with(history);
    }

    if let Some(validator) = validator {
        input = input.validate_with(validator);
    }

    loop {
        let input = input.clone().with_prompt(&prompt);
        // Run the prompt
        let res: String = match input.interact_text() {
            Ok(res) => res,
            Err(err) => {
                return Err(Error::Text { err });
            },
        };

        // Attempt to parse it as S
        match S::from_str(&res) {
            Ok(res) => {
                return Ok(res);
            },
            Err(err) => {
                warn!("Failed to parse '{}' as {}: {}", res, std::any::type_name::<S>(), err);
                prompt = format!("Illegal value for {what}; try again");
            },
        }
    }
}

// This function is mostly necessary as we cannot implement FromStr for Option<Address>. We could
// return a String and then parse it later again, but this has the downside that we cannot
// guarantee using the type system that this is sound, so we would need to unwrap.
// If somebody thinks of a way to integrate this directly into `input()`. I'm all for it.
// TODO: Documentation
pub fn input_option<S, VA>(
    what: impl Display,
    prompt: impl ToString,
    default: Option<impl Into<S>>,
    validator: Option<VA>,
    mut history: Option<impl History<String>>,
) -> Result<Option<S>, Error>
where
    S: FromStr + ToString,
    S::Err: error::Error,
    VA: dialoguer::InputValidator<String>,
    VA::Err: ToString,
{
    // Preprocess the input
    let mut prompt: String = prompt.to_string();
    let default: Option<S> = default.map(|d| d.into());

    // Loop until the user enters a valid value.
    let theme: ColorfulTheme = ColorfulTheme::default();

    // Construct the prompt
    let mut input: Input<String> = Input::with_theme(&theme);
    if let Some(default) = &default {
        input = input.default(default.to_string());
    }
    if let Some(history) = &mut history {
        input = input.history_with(history);
    }

    if let Some(validator) = validator {
        input = input.validate_with(validator);
    }

    loop {
        let input = input.clone().with_prompt(&prompt);
        // Run the prompt
        let res: String = match input.interact_text() {
            Ok(res) => res,
            Err(err) => {
                return Err(Error::Text { err });
            },
        };

        if res.trim().is_empty() {
            return Ok(None);
        }

        // Attempt to parse it as S
        match S::from_str(&res) {
            Ok(res) => {
                return Ok(Some(res));
            },
            Err(err) => {
                warn!("Failed to parse '{}' as {}: {}", res, std::any::type_name::<S>(), err);
                prompt = format!("Illegal value for {what}; try again");
            },
        }
    }
}

/// Prompts the user for an input path.
///
/// While [`input()`] can be used too, this function features auto-completion for the filesystem.
///
/// # Arguments
/// - `prompt`: The prompt to display to the user.
/// - `default`: Any default path to give, or else [`None`].
/// - `history`: An optional [`History`]-capabable struct that can be used to keep track of this prompt's history.
///
/// # Returns
/// The user's chosen path.
///
/// # Errors
/// This function errors if we failed to interact with the user.
pub fn input_path(prompt: impl ToString, default: Option<impl Into<PathBuf>>, mut history: Option<impl History<String>>) -> Result<PathBuf, Error> {
    // Construct the prompt
    let theme: ColorfulTheme = ColorfulTheme::default();
    let mut input: Input<String> = Input::with_theme(&theme);
    input = input.with_prompt(prompt.to_string()).completion_with(&FileAutocompleter);
    input = input.validate_with(|path_str: &String| PathBuf::from_str(path_str).map(|_| ()).map_err(|_| String::from("Input is not a valid path")));
    if let Some(default) = default {
        input = input.default(default.into().to_string_lossy().into());
    }
    if let Some(history) = &mut history {
        input = input.history_with(history);
    }

    // Run the prompt
    match input.interact_text() {
        Ok(path) => Ok(path.into()),
        Err(err) => Err(Error::Text { err }),
    }
}

/// Prompts the user for a vector of arbitrary size.
///
/// # Arguments
/// - `what`: Some string description to show to the user that tells them what kind of value they are inputting. Should fill in: `Invalid ...`. Only used in the case they fail the first time.
/// - `prompt`: The prompt to display to the user. You can use `%I` to get the current prompt index.
/// - `second_prompt`: Another prompt to show for entries beyond the first. You can use `%I` to get the current prompt index.
/// - `validator`: A validator that implements the [`dialoguer::InputValidator`] trait, or None if it is not possible. You can use the [`NoValidator`] concrete type when using no validator like so `None::<NoValidator>`
/// - `history`: An optional [`History`]-capabable struct that can be used to keep track of this prompt's history.
///
/// # Returns
/// A new [`Vec`] that contains the user's entered values.
///
/// # Errors
/// This function errors if we failed to interact with the user.
pub fn input_vec<V, VA>(
    what: impl Display,
    prompt: impl ToString,
    second_prompt: impl ToString,
    validator: Option<VA>,
    mut history: Option<impl History<String>>,
) -> Result<Vec<V>, Error>
where
    V: FromStr,
    V::Err: error::Error,
    VA: dialoguer::InputValidator<String>,
    VA::Err: ToString,
{
    // Do some preprocessing
    let theme: ColorfulTheme = ColorfulTheme::default();
    let mut prompt: Cow<str> = Cow::Owned(prompt.to_string());
    let second_prompt: String = second_prompt.to_string();

    // Now query as long as the user wants to
    let mut vec: Vec<V> = Default::default();

    // Construct the prompt
    let mut input: Input<String> = Input::with_theme(&theme);
    if let Some(history) = &mut history {
        input = input.history_with(history);
    }

    if let Some(validator) = validator {
        input = input.validate_with(validator);
    }

    loop {
        let input = input.clone().with_prompt(prompt.replace("%I", &(vec.len() + 1).to_string())).allow_empty(true);
        // Interact with it
        let entry: String = match input.interact_text() {
            Ok(entry) => entry,
            Err(err) => {
                return Err(Error::Text { err });
            },
        };
        if entry.is_empty() {
            return Ok(vec);
        }

        let value: V = match V::from_str(&entry) {
            Ok(val) => val,
            Err(err) => {
                warn!("Failed to parse '{}' as {}: {}", entry, std::any::type_name::<V>(), err);
                prompt = Cow::Owned(format!("'{entry}' is not a valid {what}; try again (or leave empty to finish)"));
                continue;
            },
        };

        // Finally, add it to the map and continue
        vec.push(value);
        prompt = Cow::Borrowed(&second_prompt);
    }
}

/// Prompts the user for a map of arbitrary size.
///
/// The user can specify keys multiple times to overwrite previous ones.
///
/// # Arguments
/// - `key_what`: Some string description to show to the user that tells them what kind of key they are inputting. Should fill in: `Invalid ...`. Only used in the case they fail the first time.
/// - `val_what`: Some string description to show to the user that tells them what kind of value they are inputting. Should fill in: `Invalid ...`. Only used in the case they fail the first time.
/// - `prompt`: The prompt to display to the user. You can use `%I` to get the current prompt index.
/// - `second_prompt`: Another prompt to show for entries beyond the first. You can use `%I` to get the current prompt index.
/// - `split`: The split sequence between keys and values.
/// - `validator`: A validator that implements the [`dialoguer::InputValidator`] trait, or None if it is not possible. You can use the [`NoValidator`] concrete type when using no validator like so `None::<NoValidator>`
/// - `history`: An optional [`History`]-capabable struct that can be used to keep track of this prompt's history.
///
/// # Returns
/// A new [`HashMap`] that contains the user's entered values.
///
/// # Errors
/// This function errors if we failed to interact with the user.
pub fn input_map<K, V, VA>(
    key_what: impl Display,
    val_what: impl Display,
    prompt: impl ToString,
    second_prompt: impl ToString,
    split: impl AsRef<str>,
    validator: Option<VA>,
    mut history: Option<impl History<String>>,
) -> Result<HashMap<K, V>, Error>
where
    K: Eq + FromStr + Hash,
    V: FromStr,
    K::Err: error::Error,
    V::Err: error::Error,
    VA: dialoguer::InputValidator<String>,
    VA::Err: ToString,
{
    // Do some preprocessing
    let theme: ColorfulTheme = ColorfulTheme::default();
    let mut prompt: Cow<str> = Cow::Owned(prompt.to_string());
    let second_prompt: String = second_prompt.to_string();
    let split: &str = split.as_ref();

    // Now query as long as the user wants to
    let mut map: HashMap<K, V> = HashMap::new();

    // Construct the prompt
    let mut input: Input<String> = Input::with_theme(&theme);
    if let Some(history) = &mut history {
        input = input.history_with(history);
    }

    if let Some(validator) = validator {
        input = input.validate_with(validator);
    }

    loop {
        let input = input.clone().with_prompt(prompt.replace("%I", &(map.len() + 1).to_string())).allow_empty(true);
        // Interact with it
        let entry: String = match input.interact_text() {
            Ok(entry) => entry,
            Err(err) => {
                return Err(Error::Text { err });
            },
        };
        if entry.is_empty() {
            return Ok(map);
        }

        // Split on the first splitter
        let (key, value): (&str, &str) = match entry.find(split) {
            Some(pos) => (&entry[..pos], &entry[pos + 1..]),
            None => {
                prompt = Cow::Owned(format!(
                    "'{entry}' is not a valid {key_what}{split}{val_what} pair; try again using '{split}' (or leave empty to finish)"
                ));
                continue;
            },
        };

        // Parse the Key and Value individually
        let key: K = match K::from_str(key) {
            Ok(key) => key,
            Err(err) => {
                warn!("Failed to parse '{}' as {}: {}", key, std::any::type_name::<K>(), err);
                prompt = Cow::Owned(format!("'{key}' is not a valid {key_what}; try again (or leave empty to finish)"));
                continue;
            },
        };
        let value: V = match V::from_str(value) {
            Ok(val) => val,
            Err(err) => {
                warn!("Failed to parse '{}' as {}: {}", value, std::any::type_name::<V>(), err);
                prompt = Cow::Owned(format!("'{value}' is not a valid {val_what}; try again (or leave empty to finish)"));
                continue;
            },
        };

        // Finally, add it to the map and continue
        map.insert(key, value);
        prompt = Cow::Borrowed(&second_prompt);
    }
}



/// Prompts the user to select on the given values.
///
/// # Arguments
/// - `prompt`: The prompt to display to the user.
/// - `options`: A list of options to select from.
/// - `default`: If not [`None`], then the select highlights another item than the first.
///
/// # Returns
/// The selected option. If the user aborted the select, [`None`] is returned instead.
///
/// # Errors
/// This function errors if we failed to interact with the user.
// TODO: This should be display preferable I would think
pub fn select<S: ToString>(prompt: impl ToString, options: impl IntoIterator<Item = S>, default: Option<usize>) -> Result<S, Error> {
    // Collect the options
    let mut options: Vec<S> = options.into_iter().collect();

    // Construct the prompt
    let theme: ColorfulTheme = ColorfulTheme::default();
    let mut input: Select = Select::with_theme(&theme);
    input = input.with_prompt(prompt.to_string()).default(default.unwrap_or(0)).items(&options).report(true);

    // Run it
    match input.interact() {
        Ok(index) => Ok(options.swap_remove(index)),
        Err(err) => Err(Error::Select { n_opts: options.len(), err }),
    }
}

/// Prompts the user to select on the given values.
///
/// # Arguments
/// - `prompt`: The prompt to display to the user.
/// - `options`: A list of options to select from.
/// - `default`: If not [`None`], then the select highlights another item than the first.
///
/// # Returns
/// The selected option. If the user aborted the select, [`None`] is returned instead.
///
/// # Errors
/// This function errors if we failed to interact with the user.
pub fn select_enum<T: Display + PartialEq>(prompt: impl ToString, options: impl IntoIterator<Item = T>, default: Option<T>) -> Result<T, Error> {
    // Collect the options
    let mut options: Vec<T> = options.into_iter().collect();

    // Construct the prompt
    let theme: ColorfulTheme = ColorfulTheme::default();
    let mut input: Select = Select::with_theme(&theme);
    let default_index: usize = default.and_then(|item| options.iter().position(|elem| elem == &item)).unwrap_or(0);

    input = input.with_prompt(prompt.to_string()).default(default_index).items(&options).report(true);

    // Run it
    match input.interact() {
        Ok(index) => Ok(options.swap_remove(index)),
        Err(err) => Err(Error::Select { n_opts: options.len(), err }),
    }
}
