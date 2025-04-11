//  STACK.rs
//    by Lut99
//
//  Created:
//    26 Aug 2022, 18:34:47
//  Last edited:
//    14 Nov 2022, 10:40:58
//  Auto updated?
//    Yes
//
//  Description:
//!   Implements a simple stack for use in the BraneScript VM.
//

use std::borrow::{Borrow, BorrowMut};
use std::mem;
use std::ops::{Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive};

use tracing::warn;

pub use crate::errors::StackError as Error;
use crate::value::Value;


/***** LIBRARY *****/
/// Defines a single slot on the Stack.
#[derive(Debug, Clone)]
pub enum StackSlot {
    /// The slot contains a real value
    Value(Value),
    /// The slot is a phantom pop marker
    PopMarker,
}

impl StackSlot {
    /// Returns whether this StackSlot is a value or not.
    #[inline]
    fn is_value(&self) -> bool { matches!(self, Self::Value(_)) }

    /// Returns whether this StackSlot is a pop marker or not.
    #[inline]
    fn is_pop_marker(&self) -> bool { matches!(self, Self::PopMarker) }

    /// If this StackSlot is a value, returns a copy of it. Panics otherwise.
    #[inline]
    fn into_value(self) -> Value {
        if let Self::Value(value) = self {
            value
        } else {
            panic!("Cannot get '{self:?}' as a Value");
        }
    }

    /// If this StackSlot is a value, returns a reference to it. Panics otherwise.
    #[inline]
    fn as_value(&self) -> &Value {
        if let Self::Value(value) = self {
            value
        } else {
            panic!("Cannot get '{self:?}' as a Value");
        }
    }

    /// If this StackSlot is a value, returns a mutable reference to it. Panics otherwise.
    #[inline]
    fn as_value_mut(&mut self) -> &mut Value {
        if let Self::Value(value) = self {
            value
        } else {
            panic!("Cannot get '{self:?}' as a Value");
        }
    }
}

impl From<&Value> for StackSlot {
    #[inline]
    fn from(value: &Value) -> Self { Self::from(value.clone()) }
}
impl From<Value> for StackSlot {
    #[inline]
    fn from(value: Value) -> Self { Self::Value(value) }
}



/// Represents a slice of the Stack.
#[derive(Debug)]
pub struct StackSlice {
    /// The slice of the stack we wrap.
    slots: [StackSlot],
}

impl StackSlice {
    /// Local constructor that takes a slice and wraps it in ourselves.
    ///
    /// # Arguments
    /// - `slots`: The slice of StackSlots that this StackSlice wraps.
    ///
    /// # Returns
    /// A new StackSlice type.
    #[inline]
    unsafe fn from_slots_unchecked(slots: &[StackSlot]) -> &Self { mem::transmute(slots) }

    /// Local constructor that takes a slice and wraps it in ourselves, but now muteably.
    ///
    /// # Arguments
    /// - `slots`: The slice of StackSlots that this StackSlice wraps.
    ///
    /// # Returns
    /// A new StackSlice type.
    #[inline]
    unsafe fn from_slots_unchecked_mut(slots: &mut [StackSlot]) -> &mut Self { mem::transmute(slots) }

    /// Returns the top value of the stack without popping it.
    ///
    /// # Returns
    /// The top value of the stack, or None if the stack (slice) is empty.
    pub fn peek(&self) -> Option<&Value> {
        // Iterate until we find a value
        for v in self.slots.iter().rev() {
            if let StackSlot::Value(v) = v {
                return Some(v);
            }
        }
        None
    }

    /// The number of elements in this slice.
    #[inline]
    pub fn len(&self) -> usize { self.slots.len() }

    /// Returns whether this slice is empty or not (i.e., has zero-length)
    #[inline]
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Returns a reference-iterator for the slice.
    #[inline]
    pub fn iter(&mut self) -> impl Iterator<Item = &Value> {
        self.slots.iter().filter_map(|s: &StackSlot| if s.is_value() { Some(s.as_value()) } else { None })
    }

    /// Returns a muteable reference-iterator for the slice.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Value> {
        self.slots.iter_mut().filter_map(|s: &mut StackSlot| if s.is_value() { Some(s.as_value_mut()) } else { None })
    }
}

impl Index<usize> for StackSlice {
    type Output = Value;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output { self.slots[index].as_value() }
}
impl Index<Range<usize>> for StackSlice {
    type Output = StackSlice;

    fn index(&self, index: Range<usize>) -> &Self::Output {
        // If empty, we can always early quit
        if index.start >= self.slots.len() {
            return unsafe { Self::from_slots_unchecked(&[]) };
        }
        // Otherwise, bound the end if necessary
        let end: usize = if index.end <= self.slots.len() { index.end } else { self.slots.len() };
        // Return the proper slice part
        unsafe { Self::from_slots_unchecked(&self.slots[index.start..end]) }
    }
}
impl Index<RangeTo<usize>> for StackSlice {
    type Output = Self;

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        // If empty, we can always early quit
        if self.slots.is_empty() {
            return unsafe { Self::from_slots_unchecked(&[]) };
        }
        // Otherwise, bound the end if necessary
        let end: usize = if index.end <= self.slots.len() { index.end } else { self.slots.len() };
        // Return the proper slice part
        unsafe { Self::from_slots_unchecked(&self.slots[..end]) }
    }
}
impl Index<RangeFrom<usize>> for StackSlice {
    type Output = Self;

    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        // If empty, we can always early quit
        if index.start >= self.slots.len() {
            return unsafe { Self::from_slots_unchecked(&[]) };
        }
        // Return the proper slice part
        unsafe { Self::from_slots_unchecked(&self.slots[index.start..]) }
    }
}
impl Index<RangeFull> for StackSlice {
    type Output = Self;

    #[inline]
    fn index(&self, _index: RangeFull) -> &Self::Output { self }
}
impl Index<RangeInclusive<usize>> for StackSlice {
    type Output = Self;

    fn index(&self, index: RangeInclusive<usize>) -> &Self::Output {
        let start: usize = *index.start();
        let end: usize = *index.end();

        // If empty, we can always early quit
        if start >= self.slots.len() {
            return unsafe { Self::from_slots_unchecked(&[]) };
        }
        // Otherwise, bound the end if necessary
        let end: usize = if end < self.slots.len() { end + 1 } else { self.slots.len() };
        // Return the proper slice part
        unsafe { Self::from_slots_unchecked(&self.slots[start..end]) }
    }
}
impl Index<RangeToInclusive<usize>> for StackSlice {
    type Output = Self;

    fn index(&self, index: RangeToInclusive<usize>) -> &Self::Output {
        // If empty, we can always early quit
        if self.slots.is_empty() {
            return unsafe { Self::from_slots_unchecked(&[]) };
        }
        // Otherwise, bound the end if necessary
        let end: usize = if index.end < self.slots.len() { index.end + 1 } else { self.slots.len() };
        // Return the proper slice part
        unsafe { Self::from_slots_unchecked(&self.slots[..end]) }
    }
}

impl IndexMut<usize> for StackSlice {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output { self.slots[index].as_value_mut() }
}
impl IndexMut<Range<usize>> for StackSlice {
    fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
        // If empty, we can always early quit
        if index.start >= self.slots.len() {
            return unsafe { Self::from_slots_unchecked_mut(&mut []) };
        }
        // Otherwise, bound the end if necessary
        let end: usize = if index.end <= self.slots.len() { index.end } else { self.slots.len() };
        // Return the proper slice part
        unsafe { Self::from_slots_unchecked_mut(&mut self.slots[index.start..end]) }
    }
}
impl IndexMut<RangeTo<usize>> for StackSlice {
    fn index_mut(&mut self, index: RangeTo<usize>) -> &mut Self::Output {
        // If empty, we can always early quit
        if self.slots.is_empty() {
            return unsafe { Self::from_slots_unchecked_mut(&mut []) };
        }
        // Otherwise, bound the end if necessary
        let end: usize = if index.end <= self.slots.len() { index.end } else { self.slots.len() };
        // Return the proper slice part
        unsafe { Self::from_slots_unchecked_mut(&mut self.slots[..end]) }
    }
}
impl IndexMut<RangeFrom<usize>> for StackSlice {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut Self::Output {
        // If empty, we can always early quit
        if index.start >= self.slots.len() {
            return unsafe { Self::from_slots_unchecked_mut(&mut []) };
        }
        // Return the proper slice part
        unsafe { Self::from_slots_unchecked_mut(&mut self.slots[index.start..]) }
    }
}
impl IndexMut<RangeFull> for StackSlice {
    #[inline]
    fn index_mut(&mut self, _index: RangeFull) -> &mut Self::Output { self }
}
impl IndexMut<RangeInclusive<usize>> for StackSlice {
    fn index_mut(&mut self, index: RangeInclusive<usize>) -> &mut Self::Output {
        let start: usize = *index.start();
        let end: usize = *index.end();

        // If empty, we can always early quit
        if start >= self.slots.len() {
            return unsafe { Self::from_slots_unchecked_mut(&mut []) };
        }
        // Otherwise, bound the end if necessary
        let end: usize = if end < self.slots.len() { end + 1 } else { self.slots.len() };
        // Return the proper slice part
        unsafe { Self::from_slots_unchecked_mut(&mut self.slots[start..end]) }
    }
}
impl IndexMut<RangeToInclusive<usize>> for StackSlice {
    fn index_mut(&mut self, index: RangeToInclusive<usize>) -> &mut Self::Output {
        // If empty, we can always early quit
        if self.slots.is_empty() {
            return unsafe { Self::from_slots_unchecked_mut(&mut []) };
        }
        // Otherwise, bound the end if necessary
        let end: usize = if index.end < self.slots.len() { index.end + 1 } else { self.slots.len() };
        // Return the proper slice part
        unsafe { Self::from_slots_unchecked_mut(&mut self.slots[..end]) }
    }
}

impl ToOwned for StackSlice {
    type Owned = Stack;

    #[inline]
    fn to_owned(&self) -> Stack { Stack::from_slice(&self.slots) }
}

impl<'a> IntoIterator for &'a StackSlice {
    type IntoIter = std::iter::FilterMap<std::slice::Iter<'a, StackSlot>, fn(&'a StackSlot) -> Option<&'a Value>>;
    type Item = &'a Value;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.slots.iter().filter_map(|s: &StackSlot| if s.is_value() { Some(s.as_value()) } else { None }) }
}
impl<'a> IntoIterator for &'a mut StackSlice {
    type IntoIter = std::iter::FilterMap<std::slice::IterMut<'a, StackSlot>, fn(&'a mut StackSlot) -> Option<&'a mut Value>>;
    type Item = &'a mut Value;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.slots.iter_mut().filter_map(|s: &mut StackSlot| if s.is_value() { Some(s.as_value_mut()) } else { None })
    }
}



/// The stack itself.
#[derive(Clone, Debug)]
pub struct Stack {
    /// The slots on the stack.
    slots: Vec<StackSlot>,
}

impl Stack {
    /// Constructor for the Stack.
    ///
    /// # Arguments
    /// - `size`: The size of the stack. This is actually non-configurable during execution.
    ///
    /// # Returns
    /// A new instance of a Stack with `size` slots available.
    #[inline]
    pub fn new(size: usize) -> Self { Self { slots: Vec::with_capacity(size) } }

    /// Constructor for the Slack that takes a raw StackSlot slice.
    ///
    /// # Arguments
    /// - `slots`: The slice of StackSlots to build this Stack around.
    ///
    /// # Returns
    /// A new instance of a Stack with the given slots.
    #[inline]
    fn from_slice(slice: &[StackSlot]) -> Self { Self { slots: slice.to_vec() } }

    /// Returns the top value of the stack, popping it.
    ///
    /// # Returns
    /// The top value of the stack, or None if the stack (slice) is empty.
    pub fn pop(&mut self) -> Option<Value> {
        // Pop the top value until we find a value
        while let Some(v) = self.slots.pop() {
            // Stop if it is a value
            if v.is_value() {
                return Some(v.into_value());
            }
            // Otherwise, warn
            warn!("Popping {:?} in a non-dynamic pop situation", v);
        }
        None
    }

    /// Dynamically pops from the stack until (and _not_ including) it encounters a value that is marked with a pop marker.
    ///
    /// # Returns
    /// The top X values from the stack (where X is the number of slots before a pop marked appears).
    ///
    /// # Panics
    /// This function panics if there was no pop marked at all.
    pub fn dpop(&mut self) -> Vec<Value> {
        // Pop the top value until we find a value
        let mut res: Vec<Value> = vec![];
        while let Some(v) = self.slots.pop() {
            // Stop if it is a value
            if v.is_value() {
                res.push(v.into_value());
                continue;
            }
            // Otherwise, stop
            if v.is_pop_marker() {
                break;
            }
        }
        res
    }

    /// Pushes a new value on top of the stack.
    ///
    /// # Generic arguments
    /// - `V`: The Value-compatible type of the `value`.
    ///
    /// # Arguments
    /// - `value`: The value to push onto the stack.
    ///
    /// # Errors
    /// This function may error if the stack is growing too large.
    pub fn push<V: Into<Value>>(&mut self, value: V) -> Result<(), Error> {
        // Make sure there is enough space first
        if self.slots.len() == self.slots.capacity() {
            return Err(Error::StackOverflowError { size: self.slots.capacity() });
        }

        // Push the value next
        self.slots.push(StackSlot::from(value.into()));
        Ok(())
    }

    /// Pushes a new pop marker on top of the stack.
    ///
    /// # Errors
    /// This function may error if the stack is growing too large.
    pub fn push_pop_marker(&mut self) -> Result<(), Error> {
        // Make sure there is enough space first
        if self.slots.len() == self.slots.capacity() {
            return Err(Error::StackOverflowError { size: self.slots.capacity() });
        }

        // Push the value next
        self.slots.push(StackSlot::PopMarker);
        Ok(())
    }

    /// Inserts a new value at the given position in the stack.
    ///
    /// # Generic arguments
    /// - `V`: The Value-compatible type of the `value`.
    ///
    /// # Arguments
    /// - `index`: The position in which to insert the value. Any values following (and including) this index will be shifted one place to the right.
    /// - `value`: The value to push onto the stack.
    ///
    /// # Errors
    /// This function may error if the stack is growing too large.
    pub fn insert<V: Into<Value>>(&mut self, index: usize, value: V) -> Result<(), Error> {
        // Make sure there is enough space first
        if self.slots.len() == self.slots.capacity() {
            return Err(Error::StackOverflowError { size: self.slots.capacity() });
        }

        // Insert the value next
        self.slots.insert(index, StackSlot::from(value.into()));
        Ok(())
    }
}

impl Index<usize> for Stack {
    type Output = Value;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output { self.slots[index].as_value() }
}
impl Index<Range<usize>> for Stack {
    type Output = StackSlice;

    #[inline]
    fn index(&self, index: Range<usize>) -> &Self::Output { &self[..][index] }
}
impl Index<RangeTo<usize>> for Stack {
    type Output = StackSlice;

    #[inline]
    fn index(&self, index: RangeTo<usize>) -> &Self::Output { &self[..][index] }
}
impl Index<RangeFrom<usize>> for Stack {
    type Output = StackSlice;

    #[inline]
    fn index(&self, index: RangeFrom<usize>) -> &Self::Output { &self[..][index] }
}
impl Index<RangeFull> for Stack {
    type Output = StackSlice;

    #[inline]
    fn index(&self, _index: RangeFull) -> &Self::Output { unsafe { StackSlice::from_slots_unchecked(&self.slots) } }
}
impl Index<RangeInclusive<usize>> for Stack {
    type Output = StackSlice;

    #[inline]
    fn index(&self, index: RangeInclusive<usize>) -> &Self::Output { Index::index(&**self, index) }
}
impl Index<RangeToInclusive<usize>> for Stack {
    type Output = StackSlice;

    #[inline]
    fn index(&self, index: RangeToInclusive<usize>) -> &Self::Output { Index::index(&**self, index) }
}

impl IndexMut<usize> for Stack {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output { self.slots[index].as_value_mut() }
}
impl IndexMut<Range<usize>> for Stack {
    #[inline]
    fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output { unsafe { StackSlice::from_slots_unchecked_mut(&mut self.slots[index]) } }
}
impl IndexMut<RangeTo<usize>> for Stack {
    #[inline]
    fn index_mut(&mut self, index: RangeTo<usize>) -> &mut Self::Output { &mut self[..][index] }
}
impl IndexMut<RangeFrom<usize>> for Stack {
    #[inline]
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut Self::Output { &mut self[..][index] }
}
impl IndexMut<RangeFull> for Stack {
    #[inline]
    fn index_mut(&mut self, _index: RangeFull) -> &mut Self::Output { unsafe { StackSlice::from_slots_unchecked_mut(&mut self.slots) } }
}
impl IndexMut<RangeInclusive<usize>> for Stack {
    #[inline]
    fn index_mut(&mut self, index: RangeInclusive<usize>) -> &mut Self::Output { IndexMut::index_mut(&mut **self, index) }
}
impl IndexMut<RangeToInclusive<usize>> for Stack {
    #[inline]
    fn index_mut(&mut self, index: RangeToInclusive<usize>) -> &mut Self::Output { IndexMut::index_mut(&mut **self, index) }
}

impl IntoIterator for Stack {
    type IntoIter = std::iter::FilterMap<std::vec::IntoIter<StackSlot>, fn(StackSlot) -> Option<Value>>;
    type Item = Value;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.slots.into_iter().filter_map(|s: StackSlot| if s.is_value() { Some(s.into_value()) } else { None }) }
}
impl<'a> IntoIterator for &'a Stack {
    type IntoIter = std::iter::FilterMap<std::slice::Iter<'a, StackSlot>, fn(&'a StackSlot) -> Option<&'a Value>>;
    type Item = &'a Value;

    #[inline]
    fn into_iter(self) -> Self::IntoIter { self.slots.iter().filter_map(|s: &StackSlot| if s.is_value() { Some(s.as_value()) } else { None }) }
}
impl<'a> IntoIterator for &'a mut Stack {
    type IntoIter = std::iter::FilterMap<std::slice::IterMut<'a, StackSlot>, fn(&'a mut StackSlot) -> Option<&'a mut Value>>;
    type Item = &'a mut Value;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.slots.iter_mut().filter_map(|s: &mut StackSlot| if s.is_value() { Some(s.as_value_mut()) } else { None })
    }
}

impl Borrow<StackSlice> for Stack {
    #[inline]
    fn borrow(&self) -> &StackSlice { &self[..] }
}
impl BorrowMut<StackSlice> for Stack {
    #[inline]
    fn borrow_mut(&mut self) -> &mut StackSlice { &mut self[..] }
}

impl Deref for Stack {
    type Target = StackSlice;

    #[inline]
    fn deref(&self) -> &Self::Target { &self[..] }
}
impl DerefMut for Stack {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self[..] }
}
