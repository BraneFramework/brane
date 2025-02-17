//  DEBUG.rs
//    by Lut99
//
//  Created:
//    26 Oct 2022, 14:47:11
//  Last edited:
//    12 Dec 2022, 13:13:23
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a few debug tools.
//

use std::cell::{RefCell, RefMut};
use std::fmt::{Display, Formatter, Result as FResult};


/***** LIBRARY *****/
/// Defines a struct that capitalizes the first letter of the given string when printing it.
pub struct CapitalizeFormatter<'a> {
    s: &'a str,
}
impl<'a> CapitalizeFormatter<'a> {
    /// Constructor for the CapitalizeFormatter.
    ///
    /// # Arguments
    /// - `s`: The string to print with a capital, initial letter.
    ///
    /// # Returns
    /// A new instance of CapitalizeFormatter.
    #[inline]
    pub fn new(s: &'a (impl ?Sized + AsRef<str>)) -> Self { Self { s: s.as_ref() } }
}
impl Display for CapitalizeFormatter<'_> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        if !self.s.is_empty() {
            let mut chars = self.s.chars();
            write!(f, "{}{}", chars.next().unwrap().to_uppercase(), chars.collect::<String>())
        } else {
            Ok(())
        }
    }
}

/// Helper trait for the CapitalizeFormatter that implements a convenient capitalize() function for all strings.
pub trait Capitalizeable: AsRef<str> {
    /// Returns this str-like object wrapped in a `CapitalizeFormatter` so it may be printed with a capital first letter.
    ///
    /// # Returns
    /// A new CapitalizeFormatter that implements `Display` (only).
    #[inline]
    fn capitalize(&self) -> CapitalizeFormatter { CapitalizeFormatter::new(self) }
}
impl<T> Capitalizeable for T where T: AsRef<str> {}



/// Defines a struct that can format a string of bytes as pairs of hexadecimals.
pub struct HexFormatter<'a> {
    /// The bytes to format
    bytes: &'a [u8],
}
impl<'a> HexFormatter<'a> {
    /// Constructor for the HexFormatter.
    ///
    /// # Arguments
    /// - `bytes`: The Bytes-like object to format.
    ///
    /// # Returns
    /// A new instance of the HexFormatter that implements Display.
    #[inline]
    pub fn new(bytes: &'a impl AsRef<[u8]>) -> Self { Self { bytes: bytes.as_ref() } }
}
impl Display for HexFormatter<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        // Write in pairs of two for as long as we can (i.e., four bits)
        let mut first: bool = true;
        for b in self.bytes {
            if first {
                first = false;
            } else {
                write!(f, " ")?;
            }
            write!(f, "0x{:X} 0x{:X}", b & 0xF0, b & 0x0F)?;
        }

        // Done
        Ok(())
    }
}



/// Defines a struct that can format a large block of text neatly.
pub struct BlockFormatter<S1> {
    /// Reference to the thing to format.
    to_fmt: S1,
}
impl<S1> BlockFormatter<S1> {
    /// Constructor for the BlockFormatter.
    ///
    /// # Arguments
    /// - `to_fmt`: The thing to format.
    ///
    /// # Returns
    /// A new BlockFormatter instance.
    #[inline]
    pub fn new(to_fmt: S1) -> Self { Self { to_fmt } }
}
impl<S1> Display for BlockFormatter<S1>
where
    S1: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        // Write stdout, with lines to capture it
        writeln!(f, "{}\n{}\n{}", (0..80).map(|_| '-').collect::<String>(), self.to_fmt, (0..80).map(|_| '-').collect::<String>(),)?;

        // Done
        Ok(())
    }
}



/// A helper struct that implements Display for a given iterator that prints it like a human-readable list.
pub struct PrettyListFormatter<'a, I> {
    /// The list to print.
    iter: RefCell<I>,
    /// The word to use as a connector word at the end.
    word: &'a str,
}
impl<'a, I> PrettyListFormatter<'a, I> {
    /// Constructor for the PrettyListFormatter.
    ///
    /// # Arguments
    /// - `iter`: The list to prettyprint.
    /// - `word`: The word to use at the end of the list (e.g., `and` or `or`).
    ///
    /// # Returns
    /// A new instance of the PrettyListFormatter that can be used to show the given iterator as a pretty list.
    #[inline]
    pub fn new(iter: I, word: &'a str) -> Self { Self { iter: RefCell::new(iter), word } }
}
impl<I> Display for PrettyListFormatter<'_, I>
where
    I: Iterator,
    <I as Iterator>::Item: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut list: RefMut<I> = self.iter.borrow_mut();

        let mut first: bool = true;
        let mut lookahead: Option<<I as Iterator>::Item> = list.next();
        while lookahead.is_some() {
            // Move the lookahead back
            let item: <I as Iterator>::Item = lookahead.take().unwrap();
            lookahead = list.next();

            // If this isn't the first one, print a thing in between
            if first {
                first = false;
            } else if lookahead.is_some() {
                // Just a regular comma
                write!(f, ", ")?;
            } else {
                // The connecting word
                write!(f, " {} ", self.word)?;
            }

            // Print the thing
            write!(f, "{item}")?;
        }

        // Done
        Ok(())
    }
}
