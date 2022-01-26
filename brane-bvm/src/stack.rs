use crate::bytecode::ClassMut;
use crate::objects::Array;
use crate::objects::Instance;
use crate::objects::Object;
use crate::builtins::BuiltinFunction;
use broom::{Handle, Heap};
use fnv::FnvHashMap;
use specifications::common::SpecClass;
use specifications::common::Value;
use specifications::common::Typed;
use std::collections::HashMap;
use std::fmt::Write;
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
    usize,
};


/* TIM */
/// Enum that provides errors for stack-related operations
#[derive(Debug)]
pub enum StackError {
    /// Error for when we expected one type to be on top of the stack, but found another
    UnexpectedType{ got: String, expected: String },
    /// Error for when we expected the stack to contain something, but it didn't
    EmptyStackError{ what: String },
}

impl std::fmt::Display for StackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StackError::UnexpectedType{ got, expected } => write!(f, "Expected to find value of type {} on top of stack, but got {}", expected, got),
            StackError::EmptyStackError{ what }         => write!(f, "Expected to find {}, but stack is empty", what),
        }
    }
}

impl std::error::Error for StackError {}
/*******/


const STACK_MAX: usize = 256;

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum Slot {
    BuiltIn(BuiltinFunction),
    ConstMinusOne,
    ConstMinusTwo,
    ConstOne,
    ConstTwo,
    ConstZero,
    False,
    Integer(i64),
    Real(f64),
    True,
    Unit,
    Object(Handle<Object>),
}

impl Slot {
    ///
    ///
    ///
    #[inline]
    pub fn as_object(&self) -> Option<Handle<Object>> {
        if let Slot::Object(object) = self {
            Some(*object)
        } else {
            None
        }
    }

    ///
    ///
    ///
    pub fn from_value(
        value: Value,
        globals: &FnvHashMap<String, Slot>,
        heap: &mut Heap<Object>,
    ) -> Self {
        match value {
            Value::Unicode(s) => {
                let string = Object::String(s);
                let handle = heap.insert(string).into_handle();

                Slot::Object(handle)
            }
            Value::Boolean(b) => match b {
                false => Slot::False,
                true => Slot::True,
            },
            Value::Integer(i) => Slot::Integer(i),
            Value::Real(r) => Slot::Real(r),
            Value::Unit => Slot::Unit,
            Value::FunctionExt(f) => {
                let function = Object::FunctionExt(f);
                let handle = heap.insert(function).into_handle();

                Slot::Object(handle)
            }
            Value::Class(c) => {
                let class: ClassMut = c.into();
                let class = class.freeze(heap);

                let handle = heap.insert(Object::Class(class)).into_handle();
                Slot::Object(handle)
            }
            Value::Struct { data_type, properties } => {
                let mut i_properties = FnvHashMap::default();
                for (name, value) in properties {
                    i_properties.insert(name.clone(), Slot::from_value(value.clone(), globals, heap));
                }

                let i_class = globals
                    .get(&data_type)
                    .unwrap_or_else(|| panic!("Expecting '{}' to be loaded as a global.", data_type))
                    .as_object()
                    .unwrap();

                let instance = Instance::new(i_class, i_properties);
                let instance = Object::Instance(instance);
                let handle = heap.insert(instance).into_handle();

                Slot::Object(handle)
            }
            Value::Array { entries, .. } => {
                let entries = entries
                    .into_iter()
                    .map(|e| Slot::from_value(e, globals, heap))
                    .collect();
                let array = Object::Array(Array::new(entries));
                let handle = heap.insert(array).into_handle();

                Slot::Object(handle)
            }
            todo => {
                dbg!(&todo);
                todo!();
            }
        }
    }

    ///
    ///
    ///
    pub fn into_value(
        self,
        heap: &Heap<Object>,
    ) -> Value {
        match self {
            Slot::BuiltIn(_) => {
                // panic!("Cannot convert built-in to value.")

                Value::Unit
            }
            Slot::ConstMinusOne => Value::Integer(-1),
            Slot::ConstMinusTwo => Value::Integer(-2),
            Slot::ConstOne => Value::Integer(1),
            Slot::ConstTwo => Value::Integer(2),
            Slot::ConstZero => Value::Integer(0),
            Slot::False => Value::Boolean(false),
            Slot::Integer(i) => Value::Integer(i),
            Slot::Real(r) => Value::Real(r),
            Slot::True => Value::Boolean(true),
            Slot::Unit => Value::Unit,
            Slot::Object(h) => match heap.get(h).unwrap() {
                Object::Array(a) => {
                    let data_type = a.element_type.clone();
                    let entries = a.elements.iter().map(|s| s.into_value(heap)).collect();

                    Value::Array { data_type, entries }
                }
                Object::Class(c) => {
                    let class = c.clone().unfreeze(heap);
                    let class: SpecClass = class.into();
                    Value::Class(class)
                }
                Object::Function(_) => panic!("Cannot convert function to value."),
                Object::FunctionExt(f) => Value::FunctionExt(f.clone()),
                Object::Instance(i) => {
                    let class = heap.get(i.class).expect("").as_class().expect("");
                    let data_type = class.name.clone();

                    let mut properties = HashMap::new();

                    for (name, slot) in &i.properties {
                        properties.insert(name.clone(), (*slot).into_value(heap));
                    }

                    Value::Struct { data_type, properties }
                }
                Object::String(s) => Value::Unicode(s.clone()),
            },
        }
    }
}

impl Display for Slot {
    fn fmt(
        &self,
        f: &mut Formatter<'_>,
    ) -> std::fmt::Result {
        let display = match self {
            Slot::BuiltIn(code) => format!("builtin<{:#04x}>", *code as u8), // TODO: More information, func or class, name?
            Slot::ConstMinusOne => String::from("-1"),
            Slot::ConstMinusTwo => String::from("-2"),
            Slot::ConstOne => String::from("1"),
            Slot::ConstTwo => String::from("2"),
            Slot::ConstZero => String::from("0"),
            Slot::False => String::from("false"),
            Slot::Integer(i) => format!("{}", i),
            Slot::Real(r) => format!("{}", r),
            Slot::True => String::from("true"),
            Slot::Unit => String::from("unit"),
            Slot::Object(h) => unsafe {
                match h.get_unchecked() {
                    Object::Array(_) => format!("array<{}>", "?"),
                    Object::Class(c) => format!("class<{}>", c.name),
                    Object::Function(f) => format!("function<{}>", f.name),
                    Object::FunctionExt(f) => format!("function<{}; {}>", f.name, f.kind),
                    Object::Instance(_) => format!("instance<{}>", "?"),
                    Object::String(s) => format!("{:?}", s),
                }
            },
        };

        write!(f, "{}", display)
    }
}

/* TIM */
impl Typed for Slot {
    fn data_type(&self) -> String {
        match self {
            Slot::BuiltIn(_)    => "BuiltIn".to_string(),
            Slot::ConstMinusOne => "Integer".to_string(),
            Slot::ConstMinusTwo => "Integer".to_string(),
            Slot::ConstOne      => "Integer".to_string(),
            Slot::ConstTwo      => "Integer".to_string(),
            Slot::ConstZero     => "Integer".to_string(),
            Slot::False         => "Boolean".to_string(),
            Slot::Integer(_)    => "Integer".to_string(),
            Slot::Real(_)       => "Real".to_string(),
            Slot::True          => "Boolean".to_string(),
            Slot::Unit          => "Unit".to_string(),
            Slot::Object(h)     => unsafe {
                match h.get_unchecked() {
                    Object::Array(a)       => format!("Array<{}>", a.element_type),
                    Object::Class(c)       => format!("Class<{}>", c.name),
                    Object::Function(f)    => format!("Function<{}>", f.name),
                    Object::FunctionExt(f) => format!("FunctionExt<{}; {}>", f.name, f.kind),
                    Object::Instance(_)    => format!("Instance<{}>", "?"),
                    Object::String(_)      => format!("String"),
                }
            },
        }
    }
}
/*******/

impl PartialEq for Slot {
    fn eq(
        &self,
        other: &Self,
    ) -> bool {
        match (self, other) {
            (Slot::BuiltIn(lhs), Slot::BuiltIn(rhs)) => lhs == rhs,
            (Slot::ConstMinusOne, Slot::ConstMinusOne) => true,
            (Slot::ConstMinusTwo, Slot::ConstMinusTwo) => true,
            (Slot::ConstOne, Slot::ConstOne) => true,
            (Slot::ConstTwo, Slot::ConstTwo) => true,
            (Slot::ConstZero, Slot::ConstZero) => true,
            (Slot::False, Slot::False) => true,
            (Slot::Integer(lhs), Slot::Integer(rhs)) => lhs == rhs,
            (Slot::Real(lhs), Slot::Real(rhs)) => lhs == rhs,
            (Slot::True, Slot::True) => true,
            (Slot::Unit, Slot::Unit) => true,
            (Slot::Object(lhs), Slot::Object(rhs)) => lhs == rhs,
            _ => false,
        }
    }
}

impl PartialOrd for Slot {
    fn partial_cmp(
        &self,
        other: &Self,
    ) -> Option<Ordering> {
        match (self, other) {
            (Slot::Integer(lhs), Slot::Integer(rhs)) => lhs.partial_cmp(rhs),
            (Slot::Integer(lhs), Slot::Real(rhs)) => (*lhs as f64).partial_cmp(rhs),
            (Slot::Real(lhs), Slot::Real(rhs)) => lhs.partial_cmp(rhs),
            (Slot::Real(lhs), Slot::Integer(rhs)) => lhs.partial_cmp(&(*rhs as f64)),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Stack {
    inner: Vec<Slot>,
    use_const: bool,
}

impl Default for Stack {
    fn default() -> Self {
        Self::new(STACK_MAX, false)
    }
}

impl Display for Stack {
    fn fmt(
        &self,
        f: &mut Formatter<'_>,
    ) -> std::fmt::Result {
        let mut display = String::from("         ");
        self.inner.iter().for_each(|v| write!(display, "[ {} ]", v).unwrap());

        write!(f, "{}", display)
    }
}

impl Stack {
    ///
    ///
    ///
    pub fn new(
        size: usize,
        use_const: bool,
    ) -> Self {
        Self {
            inner: Vec::with_capacity(size),
            use_const,
        }
    }

    ///
    ///
    ///
    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    ///
    ///
    ///
    #[inline]
    pub fn clear_from(
        &mut self,
        index: usize,
    ) {
        self.inner.truncate(index)
    }

    ///
    ///
    ///
    #[inline]
    pub fn get(
        &self,
        index: usize,
    ) -> &Slot {
        if let Some(slot) = self.inner.get(index) {
            slot
        } else {
            panic!("Expected value");
        }
    }

    ///
    ///
    ///
    #[inline]
    pub fn get_object(
        &self,
        index: usize,
    ) -> &Handle<Object> {
        if let Some(slot) = self.inner.get(index) {
            match slot {
                Slot::Object(h) => h,
                _ => panic!("Expecting a object."),
            }
        } else {
            panic!("Expecting value");
        }
    }

    ///
    ///
    ///
    #[inline]
    pub fn copy_pop(
        &mut self,
        index: usize,
    ) {
        self.inner.swap_remove(index);
    }

    ///
    ///
    ///
    #[inline]
    pub fn copy_push(
        &mut self,
        index: usize,
    ) {
        self.push_unit();

        let length = self.inner.len();
        self.inner.copy_within(index..index + 1, length - 1);
    }

    ///
    ///
    ///
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    ///
    ///
    ///
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /* TIM */
    /// **Edited: Changed to return a StackError instead of panicking.**
    ///
    /// Returns the top boolean on the stack without popping it.
    /// 
    /// **Returns**  
    /// The boolean's value if successfull, or a StackError otherwise.
    #[inline]
    pub fn peek_boolean(&mut self) -> Result<bool, StackError> {
        // Get the top value
        let top = self.inner.last();
        if let None = top { return Err(StackError::EmptyStackError{ what: "a boolean".to_string() }); }

        // Match the (hopefully) boolean value with the top one
        match top.unwrap() {
            Slot::False => Ok(false),
            Slot::True  => Ok(true),
            _           => Err(StackError::UnexpectedType{ expected: "Boolean".to_string(), got: top.unwrap().data_type().to_string() }),
        }
    }
    /*******/

    /* TIM */
    /// **Edited: Changed to return a StackError instead of panicking.**
    ///
    /// Returns the top slot of the stack.
    /// 
    /// **Returns**  
    /// The slot with its value if successfull, or a StackError otherwise. Note that it will never fail if you know the stack has at least one element, so you can safely call .unwrap() in that case.
    #[inline]
    pub fn pop(&mut self) -> Result<Slot, StackError> {
        // Try to get the last value
        let slot = self.inner.pop();
        if let None = slot { return Err(StackError::EmptyStackError{ what: "anything".to_string() }); }
        let slot = slot.unwrap();

        // We can return the slot immediately if we won't see any constants anyway
        if !self.use_const {
            return Ok(slot);
        }

        // Otherwise, wrap const-slots in integers and return that
        match slot {
            Slot::ConstMinusOne => Ok(Slot::Integer(-1)),
            Slot::ConstMinusTwo => Ok(Slot::Integer(-2)),
            Slot::ConstOne      => Ok(Slot::Integer(1)),
            Slot::ConstTwo      => Ok(Slot::Integer(2)),
            Slot::ConstZero     => Ok(Slot::Integer(0)),
            slot                => Ok(slot),
        }
    }

    /* TIM */
    /// **Edited: Changed to return a StackError instead of panicking.**
    ///
    /// Returns the top value of the stack as a boolean.
    /// 
    /// **Returns**  
    /// The boolean value if successfull, or a StackError otherwise.
    #[inline]
    pub fn pop_boolean(&mut self) -> Result<bool, StackError> {
        // Try to get the top value
        if let Some(slot) = self.inner.pop() {
            match slot {
                Slot::False => Ok(false),
                Slot::True  => Ok(true),
                _           => Err(StackError::UnexpectedType{ expected: "Boolean".to_string(), got: slot.data_type().to_string() }),
            }
        } else {
            Err(StackError::EmptyStackError{ what: "a boolean".to_string() })
        }
    }
    /*******/

    /* TIM */
    /// **Edited: Changed to return a StackError instead of panicking.**
    ///
    /// Returns the top value of the stack as an integer.
    /// 
    /// **Returns**  
    /// The value of the integer if successfull, or a StackError otherwise.
    #[inline]
    pub fn pop_integer(&mut self) -> Result<i64, StackError> {
        if let Some(slot) = self.inner.pop() {
            match slot {
                Slot::ConstMinusTwo => Ok(-2),
                Slot::ConstMinusOne => Ok(-1),
                Slot::ConstZero     => Ok(0),
                Slot::ConstOne      => Ok(1),
                Slot::ConstTwo      => Ok(2),
                Slot::Integer(n)    => Ok(n),
                _                   => Err(StackError::UnexpectedType{ expected: "Integer".to_string(), got: slot.data_type().to_string() }),
            }
        } else {
            Err(StackError::EmptyStackError{ what: "an integer".to_string() })
        }
    }
    /*******/

    /* TIM */
    /// **Edited: Changed to return a StackError instead of panicking.**
    ///
    /// Returns the top value of the stack as an object.
    /// 
    /// **Returns**  
    /// A handle to the object if successfull, or a StackError otherwise.
    #[inline]
    pub fn pop_object(&mut self) -> Result<Handle<Object>, StackError> {
        if let Some(slot) = self.inner.pop() {
            match slot {
                Slot::Object(h) => Ok(h),
                _               => Err(StackError::UnexpectedType{ expected: "Object".to_string(), got: slot.data_type().to_string() }),
            }
        } else {
            Err(StackError::EmptyStackError{ what: "an object".to_string() })
        }
    }
    /*******/

    ///
    ///
    ///
    #[inline]
    pub fn pop_real(&mut self) -> f64 {
        if let Some(slot) = self.inner.pop() {
            match slot {
                Slot::Real(r) => r,
                _ => panic!("Expecting a real."),
            }
        } else {
            panic!("Empty stack.");
        }
    }

    ///
    ///
    ///
    #[inline]
    pub fn pop_unit(&mut self) {
        if let Some(slot) = self.inner.pop() {
            match slot {
                Slot::Unit => (),
                _ => panic!("Expecting unit."),
            }
        } else {
            panic!("Empty stack.");
        }
    }

    ///
    ///
    ///
    #[inline]
    pub fn push(
        &mut self,
        slot: Slot,
    ) {
        self.inner.push(slot);
    }

    ///
    ///
    ///
    #[inline]
    pub fn push_boolean(
        &mut self,
        boolean: bool,
    ) {
        let boolean = match boolean {
            false => Slot::False,
            true => Slot::True,
        };

        self.inner.push(boolean);
    }

    ///
    ///
    ///
    #[inline]
    pub fn push_integer(
        &mut self,
        integer: i64,
    ) {
        let integer = if self.use_const {
            match integer {
                -2 => Slot::ConstMinusTwo,
                -1 => Slot::ConstMinusOne,
                0 => Slot::ConstZero,
                1 => Slot::ConstOne,
                2 => Slot::ConstTwo,
                n => Slot::Integer(n),
            }
        } else {
            Slot::Integer(integer)
        };

        self.inner.push(integer);
    }

    ///
    ///
    ///
    #[inline]
    pub fn push_object(
        &mut self,
        object: Handle<Object>,
    ) {
        self.inner.push(Slot::Object(object));
    }

    ///
    ///
    ///
    #[inline]
    pub fn push_real(
        &mut self,
        real: f64,
    ) {
        self.inner.push(Slot::Real(real));
    }

    ///
    ///
    ///
    #[inline]
    pub fn push_unit(&mut self) {
        self.inner.push(Slot::Unit);
    }

    ///
    ///
    ///
    #[inline]
    pub fn try_pop(&mut self) -> Option<Slot> {
        self.inner.pop()
    }

    ///
    ///
    ///
    #[inline]
    pub fn try_push(
        &mut self,
        slot: Option<Slot>,
    ) {
        if let Some(slot) = slot {
            self.inner.push(slot)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_pop() {
        let mut stack = Stack::default();
        stack.push(Slot::Integer(1));
        stack.push(Slot::Integer(2));
        stack.push(Slot::Integer(3));

        stack.copy_pop(0);

        assert_eq!(stack.len(), 2);
        assert_eq!(stack.pop_integer(), 2);
        assert_eq!(stack.pop_integer(), 3);
    }

    #[test]
    fn test_copy_push() {
        let mut stack = Stack::default();
        stack.push(Slot::Integer(1));
        stack.push(Slot::Integer(2));

        stack.copy_push(0);

        assert_eq!(stack.len(), 3);
        assert_eq!(stack.pop_integer(), 1);
        assert_eq!(stack.pop_integer(), 2);
        assert_eq!(stack.pop_integer(), 1);
    }
}
