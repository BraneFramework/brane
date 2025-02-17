//  FETCHER.rs
//    by Lut99
//
//  Created:
//    14 Sep 2022, 11:32:04
//  Last edited:
//    01 Mar 2023, 09:51:43
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements the SnippetFetcher, which will attempt to get multiple
//!   lines until a parseable snippet has been reached.
//

use std::error::Error;

use brane_dsl::TextPos;
use log::error;


/***** LIBRARY *****/
/// Iterator that will progressively get new lines until a parseable snippet has been reached.
pub struct SnippetFetcher<'a> {
    /// A closure we use to get new lines.
    #[allow(clippy::type_complexity)]
    pub get_line: Box<dyn 'a + FnMut() -> Result<Option<String>, Box<dyn Error>>>,
}

impl<'a> SnippetFetcher<'a> {
    /// Constructor for the SnippetFetcher that will fetch using the given closure.
    ///
    /// # Generic arguments
    /// - `F`: The type of the given fetcher closure. This closure should return line-by-line, or `None` if a (permanent) end-of-file is reached. Note that it is assumed that the returned line does _not_ have a newline appended to it at the end. Optionally, it may also return an Error of any kind.
    ///
    /// # Arguments
    /// - `fetcher`: The function to fetch new lines with.
    ///
    /// # Returns
    /// A new SnippetFetcher iterator instance.
    #[inline]
    pub fn new<F>(fetcher: F) -> Self
    where
        F: 'a + FnMut() -> Result<Option<String>, Box<dyn Error>>,
    {
        Self { get_line: Box::new(fetcher) }
    }
}

impl Iterator for SnippetFetcher<'_> {
    type Item = (TextPos, String);

    fn next(&mut self) -> Option<Self::Item> {
        // Get snippets until enough
        let mut offset: TextPos = TextPos::new(0, 0);
        let mut buffer: String = String::new();
        let mut n_open_paren: usize = 0;
        let mut n_open_square: usize = 0;
        let mut n_open_curly: usize = 0;
        let mut n_open_triang: usize = 0;
        loop {
            // Get the next line
            let line: String = match (self.get_line)() {
                Ok(res) => match res {
                    Some(line) => line,
                    None => {
                        return None;
                    },
                },
                Err(err) => {
                    error!("Failed to fetch new line: {}", err);
                    return None;
                },
            };
            offset.line += 1;

            // Analyze if any BraneScript thingamabobs are opened (i.e., brackets of any kind)
            for c in line.chars() {
                match c {
                    // Open
                    '(' => {
                        n_open_paren += 1;
                    },
                    '[' => {
                        n_open_square += 1;
                    },
                    '{' => {
                        n_open_curly += 1;
                    },
                    '<' => {
                        n_open_triang += 1;
                    },

                    // Close
                    ')' => {
                        n_open_paren = n_open_paren.saturating_sub(1);
                    },
                    ']' => {
                        n_open_square = n_open_square.saturating_sub(1);
                    },
                    '}' => {
                        n_open_curly = n_open_curly.saturating_sub(1);
                    },
                    '>' => {
                        n_open_triang = n_open_triang.saturating_sub(1);
                    },

                    // The rest is fine
                    _ => {},
                }
                offset.col += 1;
            }

            // If there any are opened, try again
            buffer.push_str(&line);
            buffer.push('\n');
            if n_open_paren > 0 || n_open_square > 0 || n_open_curly > 0 || n_open_triang > 0 {
                continue;
            }
            return Some((offset, buffer));
        }
    }
}
