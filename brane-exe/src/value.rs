//  VALUE.rs
//    by Lut99
//
//  Created:
//    20 Sep 2022, 13:44:07
//  Last edited:
//    16 Jan 2024, 15:13:18
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines Values, which are like instantiated DataTypes.
//

use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FResult};

use brane_ast::SymTable;
use brane_ast::data_type::DataType;
use brane_ast::func_id::FunctionId;
use brane_ast::spec::BuiltinClasses;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value as JValue;

pub use crate::errors::ValueError as Error;


/***** TESTS *****/
#[cfg(test)]
mod tests {
    use super::*;


    /// Helper function that checks if the given serialized map is one of the permutations of the given fields.
    ///
    /// # Arguments
    /// - `ser`: The serialized piece of data, or, at least, the Error if it failed to serialize.
    /// - `name`: The name of the Class.
    /// - `fields`: The three fields that we need to permutate.
    ///
    /// # Returns
    /// Nothing, which, it does, means the assertion succeeded.
    ///
    /// # Panics
    /// This function panics with the reason if the assertion fails.
    fn assert_eq_unordered(ser: Result<String, serde_json::Error>, name: String, fields: [String; 3]) {
        // Unwrap the serialization
        let ser: String = match ser {
            Ok(ser) => ser,
            Err(err) => {
                panic!("Serialization failed with error: {err}");
            },
        };

        // Now compare each of the six permutations
        if ser == format!("[\"{}\",{{{},{},{}}}]", name, fields[0], fields[1], fields[2]) {
            return;
        }
        if ser == format!("[\"{}\",{{{},{},{}}}]", name, fields[0], fields[2], fields[1]) {
            return;
        }
        if ser == format!("[\"{}\",{{{},{},{}}}]", name, fields[1], fields[0], fields[2]) {
            return;
        }
        if ser == format!("[\"{}\",{{{},{},{}}}]", name, fields[1], fields[2], fields[0]) {
            return;
        }
        if ser == format!("[\"{}\",{{{},{},{}}}]", name, fields[2], fields[0], fields[1]) {
            return;
        }
        if ser == format!("[\"{}\",{{{},{},{}}}]", name, fields[2], fields[1], fields[0]) {
            return;
        }
        panic!("Map serialization was not as expected:\nleft  : `{}`\nright : `[\"{}\",{{{},{},{}}}]`\n", ser, name, fields[0], fields[1], fields[2]);
    }


    #[test]
    fn test_fullvalue_serialize() {
        // Test if some values serialize like we expect

        // Booleans
        assert_eq!(serde_json::to_string(&FullValue::Boolean(true)).ok(), Some("true".into()));
        assert_eq!(serde_json::to_string(&FullValue::Boolean(false)).ok(), Some("false".into()));

        // Integers
        assert_eq!(serde_json::to_string(&FullValue::Integer(0)).ok(), Some("0".into()));
        assert_eq!(serde_json::to_string(&FullValue::Integer(42)).ok(), Some("42".into()));
        assert_eq!(serde_json::to_string(&FullValue::Integer(-42)).ok(), Some("-42".into()));
        assert_eq!(serde_json::to_string(&FullValue::Integer(i64::MAX)).ok(), Some(format!("{}", i64::MAX)));
        assert_eq!(serde_json::to_string(&FullValue::Integer(i64::MIN)).ok(), Some(format!("{}", i64::MIN)));

        // Reals
        assert_eq!(serde_json::to_string(&FullValue::Real(0.0)).ok(), Some("0.0".into()));
        assert_eq!(serde_json::to_string(&FullValue::Real(0.42)).ok(), Some("0.42".into()));
        assert_eq!(serde_json::to_string(&FullValue::Real(-0.42)).ok(), Some("-0.42".into()));
        assert_eq!(serde_json::to_string(&FullValue::Real(12345.6789)).ok(), Some("12345.6789".into()));
        assert_eq!(serde_json::to_string(&FullValue::Real(-12345.6789)).ok(), Some("-12345.6789".into()));
        assert_eq!(serde_json::to_string(&FullValue::Real(f64::MAX)).ok(), Some("1.7976931348623157e308".into()));
        assert_eq!(serde_json::to_string(&FullValue::Real(f64::MIN)).ok(), Some("-1.7976931348623157e308".into()));

        // Strings
        assert_eq!(serde_json::to_string(&FullValue::String("Hello, world!".into())).ok(), Some("\"Hello, world!\"".into()));
        assert_eq!(
            serde_json::to_string(&FullValue::String("Epic \" nested \" quotes".into())).ok(),
            Some("\"Epic \\\" nested \\\" quotes\"".into())
        );
        assert_eq!(serde_json::to_string(&FullValue::String("true".into())).ok(), Some("\"true\"".into()));
        assert_eq!(serde_json::to_string(&FullValue::String("42".into())).ok(), Some("\"42\"".into()));
        assert_eq!(serde_json::to_string(&FullValue::String("42.0".into())).ok(), Some("\"42.0\"".into()));

        // Arrays
        assert_eq!(serde_json::to_string(&FullValue::Array(vec![])).ok(), Some("[]".into()));
        assert_eq!(serde_json::to_string(&FullValue::Array(vec![FullValue::Integer(42)])).ok(), Some("[42]".into()));
        assert_eq!(
            serde_json::to_string(&FullValue::Array(vec![FullValue::Integer(42), FullValue::Integer(-42), FullValue::Integer(i64::MAX)])).ok(),
            Some(format!("[42,-42,{}]", i64::MAX))
        );
        assert_eq!(
            serde_json::to_string(&FullValue::Array(vec![FullValue::String("42".into()), FullValue::Integer(-42), FullValue::Real(-12345.6789)]))
                .ok(),
            Some("[\"42\",-42,-12345.6789]".into())
        );
        assert_eq!(
            serde_json::to_string(&FullValue::Array(vec![
                FullValue::Array(vec![FullValue::Integer(1), FullValue::Integer(2), FullValue::Integer(3)]),
                FullValue::Array(vec![FullValue::Integer(4), FullValue::Integer(5), FullValue::Integer(6)]),
                FullValue::Array(vec![FullValue::Integer(7), FullValue::Integer(8), FullValue::Integer(9)]),
            ]))
            .ok(),
            Some("[[1,2,3],[4,5,6],[7,8,9]]".into())
        );

        // Instances
        assert_eq!(serde_json::to_string(&FullValue::Instance("Test".into(), HashMap::from([]))).ok(), Some("[\"Test\",{}]".into()));
        assert_eq!(
            serde_json::to_string(&FullValue::Instance("Test".into(), HashMap::from([("one".into(), FullValue::Integer(42))]))).ok(),
            Some("[\"Test\",{\"one\":42}]".into())
        );
        assert_eq_unordered(
            serde_json::to_string(&FullValue::Instance(
                "Test".into(),
                HashMap::from([
                    ("one".into(), FullValue::Integer(42)),
                    ("two".into(), FullValue::Integer(-42)),
                    ("three".into(), FullValue::Integer(i64::MAX)),
                ]),
            )),
            "Test".into(),
            ["\"one\":42".into(), "\"two\":-42".into(), format!("\"three\":{}", i64::MAX)],
        );
        assert_eq_unordered(
            serde_json::to_string(&FullValue::Instance(
                "Test".into(),
                HashMap::from([
                    ("one".into(), FullValue::String("42".into())),
                    ("two".into(), FullValue::Integer(-42)),
                    ("three".into(), FullValue::Real(-12345.6789)),
                ]),
            )),
            "Test".into(),
            ["\"one\":\"42\"".into(), "\"two\":-42".into(), "\"three\":-12345.6789".into()],
        );
        assert_eq_unordered(
            serde_json::to_string(&FullValue::Instance(
                "Test".into(),
                HashMap::from([
                    ("one".into(), FullValue::Array(vec![FullValue::Integer(1), FullValue::Integer(2), FullValue::Integer(3)])),
                    ("two".into(), FullValue::Instance("TestNested".into(), HashMap::from([("one".into(), FullValue::Integer(42))]))),
                    (
                        "three".into(),
                        FullValue::Array(vec![
                            FullValue::Instance("TestNested1".into(), HashMap::from([("one".into(), FullValue::Integer(1))])),
                            FullValue::Instance("TestNested2".into(), HashMap::from([("two".into(), FullValue::Integer(2))])),
                            FullValue::Instance("TestNested3".into(), HashMap::from([("three".into(), FullValue::Integer(3))])),
                        ]),
                    ),
                ]),
            )),
            "Test".into(),
            [
                "\"one\":[1,2,3]".into(),
                "\"two\":[\"TestNested\",{\"one\":42}]".into(),
                "\"three\":[[\"TestNested1\",{\"one\":1}],[\"TestNested2\",{\"two\":2}],[\"TestNested3\",{\"three\":3}]]".into(),
            ],
        );

        // Data
        assert_eq!(serde_json::to_string(&FullValue::Data("testset".into())).ok(), Some("\"Data<testset>\"".into()));

        // Void
        assert_eq!(serde_json::to_string(&FullValue::Void).ok(), Some("null".into()));
    }

    #[test]
    fn test_fullvalue_deserialize() {
        // Test if some values deserialize (like we expect)

        // Booleans
        assert_eq!(serde_json::from_str::<FullValue>("true").unwrap_or_else(|err| panic!("{}", err)), FullValue::Boolean(true));
        assert_eq!(serde_json::from_str::<FullValue>("false").unwrap_or_else(|err| panic!("{}", err)), FullValue::Boolean(false));

        // Integers
        assert_eq!(serde_json::from_str::<FullValue>("0").unwrap_or_else(|err| panic!("{}", err)), FullValue::Integer(0));
        assert_eq!(serde_json::from_str::<FullValue>("42").unwrap_or_else(|err| panic!("{}", err)), FullValue::Integer(42));
        assert_eq!(serde_json::from_str::<FullValue>("-42").unwrap_or_else(|err| panic!("{}", err)), FullValue::Integer(-42));
        assert_eq!(serde_json::from_str::<FullValue>(&format!("{}", i64::MAX)).unwrap_or_else(|err| panic!("{}", err)), FullValue::Integer(i64::MAX));
        assert_eq!(serde_json::from_str::<FullValue>(&format!("{}", i64::MIN)).unwrap_or_else(|err| panic!("{}", err)), FullValue::Integer(i64::MIN));

        // Reals
        assert_eq!(serde_json::from_str::<FullValue>("0.0").unwrap_or_else(|err| panic!("{}", err)), FullValue::Real(0.0));
        assert_eq!(serde_json::from_str::<FullValue>("42.0").unwrap_or_else(|err| panic!("{}", err)), FullValue::Real(42.0));
        assert_eq!(serde_json::from_str::<FullValue>("-42.0").unwrap_or_else(|err| panic!("{}", err)), FullValue::Real(-42.0));
        assert_eq!(serde_json::from_str::<FullValue>("0.42").unwrap_or_else(|err| panic!("{}", err)), FullValue::Real(0.42));
        assert_eq!(serde_json::from_str::<FullValue>("-0.42").unwrap_or_else(|err| panic!("{}", err)), FullValue::Real(-0.42));
        assert_eq!(serde_json::from_str::<FullValue>("1.7976931348623157e308").unwrap_or_else(|err| panic!("{}", err)), FullValue::Real(f64::MAX));
        assert_eq!(serde_json::from_str::<FullValue>("-1.7976931348623157e308").unwrap_or_else(|err| panic!("{}", err)), FullValue::Real(f64::MIN));

        // Strings
        assert_eq!(
            serde_json::from_str::<FullValue>("\"Hello, world!\"").unwrap_or_else(|err| panic!("{}", err)),
            FullValue::String("Hello, world!".into())
        );
        assert_eq!(
            serde_json::from_str::<FullValue>("\"Epic \\\" nested \\\" quotes\"").unwrap_or_else(|err| panic!("{}", err)),
            FullValue::String("Epic \" nested \" quotes".into())
        );
        assert_eq!(serde_json::from_str::<FullValue>("\"true\"").unwrap_or_else(|err| panic!("{}", err)), FullValue::String("true".into()));
        assert_eq!(serde_json::from_str::<FullValue>("\"42\"").unwrap_or_else(|err| panic!("{}", err)), FullValue::String("42".into()));
        assert_eq!(serde_json::from_str::<FullValue>("\"42.0\"").unwrap_or_else(|err| panic!("{}", err)), FullValue::String("42.0".into()));

        // Arrays
        assert_eq!(serde_json::from_str::<FullValue>("[]").unwrap_or_else(|err| panic!("{}", err)), FullValue::Array(vec![]));
        assert_eq!(serde_json::from_str::<FullValue>("[42]").unwrap_or_else(|err| panic!("{}", err)), FullValue::Array(vec![FullValue::Integer(42)]));
        assert_eq!(
            serde_json::from_str::<FullValue>(&format!("[42, -42, {}]", i64::MAX)).unwrap_or_else(|err| panic!("{}", err)),
            FullValue::Array(vec![FullValue::Integer(42), FullValue::Integer(-42), FullValue::Integer(i64::MAX)])
        );
        assert_eq!(
            serde_json::from_str::<FullValue>("[\"42\",-42,-12345.6789]").unwrap_or_else(|err| panic!("{}", err)),
            FullValue::Array(vec![FullValue::String("42".into()), FullValue::Integer(-42), FullValue::Real(-12345.6789)])
        );
        assert_eq!(
            serde_json::from_str::<FullValue>("[[1,2,3],[4,5,6],[7,8,9]]").unwrap_or_else(|err| panic!("{}", err)),
            FullValue::Array(vec![
                FullValue::Array(vec![FullValue::Integer(1), FullValue::Integer(2), FullValue::Integer(3)]),
                FullValue::Array(vec![FullValue::Integer(4), FullValue::Integer(5), FullValue::Integer(6)]),
                FullValue::Array(vec![FullValue::Integer(7), FullValue::Integer(8), FullValue::Integer(9)]),
            ])
        );

        // Classes
        assert_eq!(
            serde_json::from_str::<FullValue>("[\"Test\",{}]").unwrap_or_else(|err| panic!("{}", err)),
            FullValue::Instance("Test".into(), HashMap::from([]))
        );
        assert_eq!(
            serde_json::from_str::<FullValue>("[\"Test\",{\"one\":42}]").unwrap_or_else(|err| panic!("{}", err)),
            FullValue::Instance("Test".into(), HashMap::from([("one".into(), FullValue::Integer(42))]))
        );
        assert_eq!(
            serde_json::from_str::<FullValue>(&format!("[\"Test\",{{\"one\":42,\"two\":-42,\"three\":{}}}]", i64::MAX))
                .unwrap_or_else(|err| panic!("{}", err)),
            FullValue::Instance(
                "Test".into(),
                HashMap::from([
                    ("one".into(), FullValue::Integer(42)),
                    ("two".into(), FullValue::Integer(-42)),
                    ("three".into(), FullValue::Integer(i64::MAX))
                ])
            )
        );
        assert_eq!(
            serde_json::from_str::<FullValue>("[\"Test\",{\"one\":\"42\",\"two\":-42,\"three\":-12345.6789}]")
                .unwrap_or_else(|err| panic!("{}", err)),
            FullValue::Instance(
                "Test".into(),
                HashMap::from([
                    ("one".into(), FullValue::String("42".into())),
                    ("two".into(), FullValue::Integer(-42)),
                    ("three".into(), FullValue::Real(-12345.6789))
                ])
            )
        );
        assert_eq!(
            serde_json::from_str::<FullValue>(
                "[\"Test\",{\"one\":[1,2,3],\"two\":[\"TestNested\",{\"one\":42}],\"three\":[[\"TestNested1\",{\"one\":1}],[\"TestNested2\",{\"two\"\
                 :2}],[\"TestNested3\",{\"three\":3}]]}]"
            )
            .unwrap_or_else(|err| panic!("{}", err)),
            FullValue::Instance(
                "Test".into(),
                HashMap::from([
                    ("one".into(), FullValue::Array(vec![FullValue::Integer(1), FullValue::Integer(2), FullValue::Integer(3)])),
                    ("two".into(), FullValue::Instance("TestNested".into(), HashMap::from([("one".into(), FullValue::Integer(42))]))),
                    (
                        "three".into(),
                        FullValue::Array(vec![
                            FullValue::Instance("TestNested1".into(), HashMap::from([("one".into(), FullValue::Integer(1))])),
                            FullValue::Instance("TestNested2".into(), HashMap::from([("two".into(), FullValue::Integer(2))])),
                            FullValue::Instance("TestNested3".into(), HashMap::from([("three".into(), FullValue::Integer(3))])),
                        ])
                    ),
                ])
            )
        );

        // Data
        assert_eq!(serde_json::from_str::<FullValue>("\"Data<testset>\"").unwrap_or_else(|err| panic!("{}", err)), FullValue::Data("testset".into()));

        // Void
        assert_eq!(serde_json::from_str::<FullValue>("null").unwrap_or_else(|err| panic!("{}", err)), FullValue::Void);
    }
}





/***** HELPER STRUCTS *****/
/// Custom visitor for the DataId struct.
struct DataIdVisitor;

impl Visitor<'_> for DataIdVisitor {
    type Value = DataId;

    fn expecting(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "Data identifier") }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() < 5 || &value[..5] != "Data<" || &value[value.len() - 1..] != ">" {
            return Err(E::custom("given string does not start with 'Data<'"));
        }
        Ok(DataId(value[5..value.len() - 1].into()))
    }
}

/// Custom visitor for the ResultId struct.
struct ResultIdVisitor;

impl Visitor<'_> for ResultIdVisitor {
    type Value = ResultId;

    fn expecting(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "Result identifier") }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() < 19 || &value[..19] != "IntermediateResult<" || &value[value.len() - 1..] != ">" {
            return Err(E::custom("given string does not start with 'IntermediateResult<'"));
        }
        Ok(ResultId(value[19..value.len() - 1].into()))
    }
}





/***** AUXILLARY *****/
/// Allows a Value to be displayed properly with resolved definitions and such.
#[derive(Debug)]
pub struct ValueDisplay<'a, 'b> {
    /// The value we want to display.
    value: &'a Value,
    /// The table we want to use to resolve.
    table: &'b SymTable,
}

impl Display for ValueDisplay<'_, '_> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use Value::*;
        match self.value {
            Boolean { value } => write!(f, "{value}"),
            Integer { value } => write!(f, "{value}"),
            Real { value } => write!(f, "{value}"),
            String { value } => write!(f, "{value}"),

            Array { values } => {
                write!(f, "[{}]", values.iter().map(|v| format!("{}", v.display(self.table))).collect::<Vec<std::string::String>>().join(", "))
            },
            Function { def } => write!(
                f,
                "{}({}) -> {}",
                self.table.func(FunctionId::Func(*def)).name,
                self.table.func(FunctionId::Func(*def)).args.iter().map(|a| format!("{a}")).collect::<Vec<std::string::String>>().join(","),
                self.table.func(FunctionId::Func(*def)).ret
            ),
            Instance { values, def } => write!(
                f,
                "{} {{{}{}{}}}",
                self.table.class(*def).name,
                if values.is_empty() { "" } else { " " },
                values.iter().map(|(n, v)| format!("{} := {}", n, v.display(self.table))).collect::<Vec<std::string::String>>().join(", "),
                if values.is_empty() { "" } else { " " },
            ),
            Method { cdef, fdef, .. } => write!(
                f,
                "{}::{}({}) -> {}",
                self.table.class(*cdef).name,
                self.table.func(FunctionId::Func(*fdef)).name,
                self.table.func(FunctionId::Func(*fdef)).args.iter().map(|a| format!("{a}")).collect::<Vec<std::string::String>>().join(","),
                self.table.func(FunctionId::Func(*fdef)).ret
            ),
            Data { name } => write!(f, "Data<{name}>"),
            IntermediateResult { name } => write!(f, "IntermediateResult<{name}>"),

            Void => write!(f, "()"),
        }
    }
}



/// A wrapper around the name of a data struct so that it gets parsed differently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataId(String);

impl Display for DataId {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}", self.0) }
}

impl Serialize for DataId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> { serializer.serialize_str(&format!("Data<{}>", self.0)) }
}
impl<'de> Deserialize<'de> for DataId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> { deserializer.deserialize_str(DataIdVisitor) }
}

impl AsRef<str> for DataId {
    fn as_ref(&self) -> &str { self.0.as_str() }
}

impl From<String> for DataId {
    #[inline]
    fn from(value: String) -> Self { Self(value) }
}
impl From<&String> for DataId {
    #[inline]
    fn from(value: &String) -> Self { Self::from(value.clone()) }
}
impl From<&mut String> for DataId {
    fn from(value: &mut String) -> Self { Self::from(value.as_str()) }
}
impl From<&str> for DataId {
    #[inline]
    fn from(value: &str) -> Self { Self::from(value.to_string()) }
}

impl From<DataId> for String {
    #[inline]
    fn from(value: DataId) -> Self { value.0 }
}
impl From<&DataId> for String {
    #[inline]
    fn from(value: &DataId) -> Self { value.0.clone() }
}
impl From<&mut DataId> for String {
    #[inline]
    fn from(value: &mut DataId) -> Self { value.0.clone() }
}



/// A wrapper around the name of an intermediate result struct so that it gets parsed differently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultId(String);

impl Display for ResultId {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult { write!(f, "{}", self.0) }
}

impl Serialize for ResultId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("IntermediateResult<{}>", self.0))
    }
}
impl<'de> Deserialize<'de> for ResultId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> { deserializer.deserialize_str(ResultIdVisitor) }
}

impl AsRef<str> for ResultId {
    fn as_ref(&self) -> &str { self.0.as_str() }
}

impl From<String> for ResultId {
    #[inline]
    fn from(value: String) -> Self { Self(value) }
}
impl From<&String> for ResultId {
    #[inline]
    fn from(value: &String) -> Self { Self::from(value.clone()) }
}
impl From<&mut String> for ResultId {
    fn from(value: &mut String) -> Self { Self::from(value.as_str()) }
}
impl From<&str> for ResultId {
    #[inline]
    fn from(value: &str) -> Self { Self::from(value.to_string()) }
}

impl From<ResultId> for String {
    #[inline]
    fn from(value: ResultId) -> Self { value.0 }
}
impl From<&ResultId> for String {
    #[inline]
    fn from(value: &ResultId) -> Self { value.0.clone() }
}
impl From<&mut ResultId> for String {
    #[inline]
    fn from(value: &mut ResultId) -> Self { value.0.clone() }
}





/***** LIBRARY *****/
/// Defines a single Value while executing a Workflow. That's basically an instantiated DataType.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// It's a boolean value (true/false)
    Boolean { value: bool },
    /// It's an integer value (non-fractional numbers)
    Integer { value: i64 },
    /// It's a real value (fractional numbers)
    Real { value: f64 },
    /// It's a string value (UTF-8 characters)
    String { value: String },

    /// It's an Array of values
    Array { values: Vec<Self> },
    /// It's a function object, that references a Function in the workflow table.
    Function { def: usize },
    /// It's an instance object, that maps field names to values.
    Instance { values: HashMap<String, Self>, def: usize },
    /// It's a method object, which merges a function and an instance together into one.
    Method { values: HashMap<String, Self>, cdef: usize, fdef: usize },
    /// It's a data object that contains the identifier of the dataset referenced.
    Data { name: String },
    /// It's an intermediate result object that contains the identifier of the dataset _or_ result referenced.
    IntermediateResult { name: String },

    /// No value
    Void,
}

impl Value {
    /// Returns the top value on the stack as if it was a boolean.
    ///
    /// # Returns
    /// The boolean value if it actually was a boolean, or else `None`.
    #[inline]
    pub fn try_as_bool(self) -> Option<bool> {
        use Value::*;
        match self {
            Boolean { value } => Some(value),
            _ => None,
        }
    }

    /// Returns the top value on the stack as if it was an integer.
    ///
    /// # Returns
    /// The integer value if it actually was a integer, or else `None`.
    #[inline]
    pub fn try_as_int(self) -> Option<i64> {
        use Value::*;
        match self {
            Integer { value } => Some(value),
            _ => None,
        }
    }

    /// Returns the top value on the stack as if it was a string.
    ///
    /// # Returns
    /// The string value if it actually was a string, or else `None`.
    #[inline]
    pub fn try_as_string(self) -> Option<String> {
        use Value::*;
        match self {
            String { value } => Some(value),
            _ => None,
        }
    }

    /// Returns the top value on the stack as if it was an array (of any type).
    ///
    /// # Returns
    /// An array of values if it actually was an array, or else `None`.
    #[inline]
    pub fn try_as_array(self) -> Option<Vec<Self>> {
        use Value::*;
        match self {
            Array { values } => Some(values),
            _ => None,
        }
    }

    /// Returns the top value on the stack as if it was a callable (function) of some sort (of any signature).
    ///
    /// # Returns
    /// The function's index if it actually was a callable, or else `None`.
    #[inline]
    pub fn try_as_func(self) -> Option<usize> {
        use Value::*;
        match self {
            Function { def } => Some(def),
            _ => None,
        }
    }

    /// Returns the top value on the stack as if it was an instance (of any type).
    ///
    /// # Returns
    /// A tuple with the definition and the map of field names -> values if it actually was an instance, or else `None`.
    #[inline]
    pub fn try_as_instance(self) -> Option<(HashMap<String, Self>, usize)> {
        use Value::*;
        match self {
            Instance { values, def } => Some((values, def)),
            _ => None,
        }
    }

    /// Returns the top value on the stack as if it was a method (of any type).
    ///
    /// # Returns
    /// A tuple with the definition and the map of field names -> values if it actually was an instance, or else `None`.
    #[inline]
    pub fn try_as_method(self) -> Option<(HashMap<String, Self>, usize, usize)> {
        use Value::*;
        match self {
            Method { values, cdef, fdef } => Some((values, cdef, fdef)),
            _ => None,
        }
    }

    /// Returns the top value on the stack as if it was an IntermediateResult.
    ///
    /// # Returns
    /// The name of the intermediate result, if any.
    #[inline]
    pub fn try_as_intermediate_result(self) -> Option<String> {
        use Value::*;
        match self {
            IntermediateResult { name } => Some(name),
            _ => None,
        }
    }

    /// Attempts to cast this Value to another one, according to the casting rules.
    ///
    /// # Arguments
    /// - `target`: The target type to cast to.
    /// - `table`: The VirtualSymTable that we use to resolve specific data types.
    ///
    /// # Returns
    /// A new Value that contains the casted representation of this value.
    ///
    /// # Errors
    /// This function errors if this value is not casteable to the given type.
    pub fn cast(self, target: &DataType, table: &SymTable) -> Result<Self, Error> {
        use Value::*;
        match (self, target) {
            (Boolean { value }, DataType::Any) => Ok(Self::Boolean { value }),
            (Boolean { value }, DataType::Boolean) => Ok(Self::Boolean { value }),
            (Boolean { value }, DataType::Integer) => Ok(Self::Integer { value: i64::from(value) }),
            (Boolean { value }, DataType::String) => Ok(Self::String { value: format!("{}", Self::Boolean { value }.display(table)) }),

            (Integer { value }, DataType::Any) => Ok(Self::Integer { value }),
            (Integer { value }, DataType::Boolean) => Ok(Self::Boolean { value: value != 0 }),
            (Integer { value }, DataType::Integer) => Ok(Self::Integer { value }),
            (Integer { value }, DataType::Real) => Ok(Self::Real { value: value as f64 }),
            (Integer { value }, DataType::String) => Ok(Self::String { value: format!("{}", Self::Integer { value }.display(table)) }),

            (Real { value }, DataType::Any) => Ok(Self::Real { value }),
            (Real { value }, DataType::Integer) => Ok(Self::Integer { value: value as i64 }),
            (Real { value }, DataType::Real) => Ok(Self::Real { value }),
            (Real { value }, DataType::String) => Ok(Self::String { value: format!("{}", Self::Real { value }.display(table)) }),

            (String { value }, DataType::Any) => Ok(Self::String { value }),
            (String { value }, DataType::String) => Ok(Self::String { value }),

            (Array { values }, DataType::Any) => Ok(Self::Array { values }),
            (Array { values }, DataType::String) => Ok(Self::String { value: format!("{}", Self::Array { values }.display(table)) }),
            (Array { values }, DataType::Array { elem_type }) => {
                // Cast all of the internal values
                let mut casted_values: Vec<Self> = Vec::with_capacity(values.len());
                for v in values {
                    casted_values.push(v.cast(elem_type, table)?);
                }

                // Return
                Ok(Self::Array { values: casted_values })
            },

            (Function { def }, DataType::Any) => Ok(Self::Function { def }),
            (Function { def }, DataType::Function { args, ret }) => {
                Ok(if &table.func(FunctionId::Func(def)).args == args && table.func(FunctionId::Func(def)).ret == **ret {
                    Self::Function { def }
                } else {
                    return Err(Error::CastError {
                        got:    DataType::Function {
                            args: table.func(FunctionId::Func(def)).args.clone(),
                            ret:  Box::new(table.func(FunctionId::Func(def)).ret.clone()),
                        },
                        target: target.clone(),
                    });
                })
            },
            (Function { def }, DataType::String) => Ok(Self::String { value: format!("{}", Self::Function { def }.display(table)) }),

            (Instance { values, def }, DataType::Any) => Ok(Self::Instance { values, def }),
            (Instance { values, def }, DataType::Class { name }) => Ok(if &table.class(def).name == name {
                Self::Instance { values, def }
            } else {
                return Err(Error::CastError { got: DataType::Class { name: table.class(def).name.clone() }, target: target.clone() });
            }),
            (Instance { values, def }, DataType::String) => Ok(Self::String { value: format!("{}", Self::Instance { values, def }.display(table)) }),

            (Method { values, cdef, fdef }, DataType::Any) => Ok(Self::Method { values, cdef, fdef }),
            (Method { values, cdef, fdef }, DataType::Class { name }) => Ok(if &table.class(cdef).name == name {
                Self::Method { values, cdef, fdef }
            } else {
                return Err(Error::CastError { got: DataType::Class { name: table.class(cdef).name.clone() }, target: target.clone() });
            }),
            (Method { values, cdef, fdef }, DataType::String) => {
                Ok(Self::String { value: format!("{}", Self::Method { values, cdef, fdef }.display(table)) })
            },

            (Data { name }, DataType::Any) => Ok(Self::Data { name }),
            (Data { name }, DataType::Data) => Ok(Self::Data { name }),
            (Data { name }, DataType::String) => Ok(Self::String { value: format!("{}", Self::Data { name }.display(table)) }),
            // Note that we do not actually cast Data; this because the only difference is where we get the data, and we don't actually want that to change
            (Data { name }, DataType::IntermediateResult) => Ok(Self::Data { name }),

            (IntermediateResult { name }, DataType::Any) => Ok(Self::IntermediateResult { name }),
            (IntermediateResult { name }, DataType::IntermediateResult) => Ok(Self::IntermediateResult { name }),
            (IntermediateResult { name }, DataType::String) => {
                Ok(Self::String { value: format!("{}", Self::IntermediateResult { name }.display(table)) })
            },

            // Otherwise, uncastable
            (got, target) => Err(Error::CastError { got: got.data_type(table), target: target.clone() }),
        }
    }

    /// Returns the DataType of this Value. Note that the following properties may be assumed:
    /// - The datatype is never Void (since it is a value)
    /// - Because it is runtime, it _always_ has a non-Any type (i.e., it's always resolved).
    ///
    /// # Arguments
    /// - `table`: The VirtualSymTable that we use to resolve specific data types.
    #[inline]
    pub fn data_type(&self, table: &SymTable) -> DataType {
        use Value::*;
        match self {
            Boolean { .. } => DataType::Boolean,
            Integer { .. } => DataType::Integer,
            Real { .. } => DataType::Real,
            String { .. } => DataType::String,

            Array { values } => DataType::Array { elem_type: Box::new(values.iter().next().map(|v| v.data_type(table)).unwrap_or(DataType::Any)) },
            Function { def } => DataType::Function {
                args: table.func(FunctionId::Func(*def)).args.clone(),
                ret:  Box::new(table.func(FunctionId::Func(*def)).ret.clone()),
            },
            Instance { def, .. } => {
                if table.class(*def).name == BuiltinClasses::Data.name() {
                    DataType::Data
                } else {
                    DataType::Class { name: table.class(*def).name.clone() }
                }
            },
            Method { fdef, .. } => DataType::Function {
                args: table.func(FunctionId::Func(*fdef)).args.clone(),
                ret:  Box::new(table.func(FunctionId::Func(*fdef)).ret.clone()),
            },
            Data { .. } => DataType::Data,
            IntermediateResult { .. } => DataType::IntermediateResult,

            Void => DataType::Void,
        }
    }

    /// Allows the Value to be displayed with resolved definitions.
    ///
    /// # Arguments
    /// - `table`: The VirtualSymTable to resolve the definitions with.
    ///
    /// # Returns
    /// A ValueDisplay that implements the resolving Display for a Value.
    #[inline]
    pub fn display<'a, 'b>(&'a self, table: &'b SymTable) -> ValueDisplay<'a, 'b> { ValueDisplay { value: self, table } }

    /// Converts this Value into a FullValue by resolving the necessary definitions.
    ///
    /// # Arguments
    /// - `table`: The VirtualSymTable that contains the definitions which we will resolve.
    ///
    /// # Returns
    /// A new FullValue instance that is a copy of this Value.
    #[inline]
    pub fn to_full(&self, table: &SymTable) -> FullValue {
        use Value::*;
        match self {
            Boolean { value } => FullValue::Boolean(*value),
            Integer { value } => FullValue::Integer(*value),
            Real { value } => FullValue::Real(*value),
            String { value } => FullValue::String(value.clone()),

            Array { values } => FullValue::Array(values.iter().map(|v| v.to_full(table)).collect()),
            Function { .. } => {
                panic!("Value::Function has no business being converted into a FullValue");
            },
            Instance { values, def } => {
                FullValue::Instance(table.class(*def).name.clone(), values.iter().map(|(n, v)| (n.clone(), v.to_full(table))).collect())
            },
            Method { .. } => {
                panic!("Value::Method has no business being converted into a FullValue");
            },
            Data { name } => FullValue::Data(DataId(name.clone())),
            IntermediateResult { name } => FullValue::IntermediateResult(ResultId(name.clone())),

            Void => FullValue::Void,
        }
    }

    /// Converts this Value into a FullValue by resolving the necessary definitions.
    ///
    /// This overload consumes self, allowing for a more efficient conversion in cases where object are concerned.
    ///
    /// # Arguments
    /// - `table`: The VirtualSymTable that contains the definitions which we will resolve.
    ///
    /// # Returns
    /// A new FullValue instance that is a copy of this Value.
    #[inline]
    pub fn into_full(self, table: &SymTable) -> FullValue {
        use Value::*;
        match self {
            Boolean { value } => FullValue::Boolean(value),
            Integer { value } => FullValue::Integer(value),
            Real { value } => FullValue::Real(value),
            String { value } => FullValue::String(value),

            Array { values } => FullValue::Array(values.into_iter().map(|v| v.into_full(table)).collect()),
            Function { .. } => {
                panic!("Value::Function has no business being converted into a FullValue");
            },
            Instance { values, def } => {
                FullValue::Instance(table.class(def).name.clone(), values.into_iter().map(|(n, v)| (n, v.into_full(table))).collect())
            },
            Method { .. } => {
                panic!("Value::Method has no business being converted into a FullValue");
            },
            Data { name } => FullValue::Data(DataId(name)),
            IntermediateResult { name } => FullValue::IntermediateResult(ResultId(name)),

            Void => FullValue::Void,
        }
    }
}



/// Defines a so-called 'FullValue', which is like a normal value but with direct definitions instead of references to them (which makes them ideal to share over the wire).
///
/// Note that the order of the enums is not the same as that of Value. This is done to proper disambiguate between Data and String when deserializing.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum FullValue {
    /// It's an Array of values
    Array(Vec<Self>),
    /// It's an instance object, that maps field names to values.
    Instance(String, HashMap<String, Self>),
    /// It's a data object that contains the identifier of the dataset referenced.
    Data(DataId),
    /// It's an intermediate result object that contains the identifier of the dataset or result referenced.
    IntermediateResult(ResultId),

    /// It's a boolean value (true/false)
    Boolean(bool),
    /// It's an integer value (non-fractional numbers)
    Integer(i64),
    /// It's a real value (fractional numbers)
    Real(f64),
    /// It's a string value (UTF-8 characters)
    String(String),

    /// No value
    Void,
}

impl FullValue {
    /// Force-unwraps the FullValue as a regular ol' boolean.
    ///
    /// # Returns
    /// The internal boolean value.
    ///
    /// # Panics
    /// This function panics if the given value was not actually a boolean.
    #[inline]
    pub fn bool(self) -> bool {
        if let Self::Boolean(value) = self {
            value
        } else {
            panic!("Cannot unwrap a non-FullValue::Boolean as FullValue::Boolean");
        }
    }

    /// Force-unwraps the FullValue as a regular ol' integer.
    ///
    /// # Returns
    /// The internal integer value.
    ///
    /// # Panics
    /// This function panics if the given value was not actually an integer.
    #[inline]
    pub fn int(self) -> i64 {
        if let Self::Integer(value) = self {
            value
        } else {
            panic!("Cannot unwrap a non-FullValue::Integer as FullValue::Integer");
        }
    }

    /// Force-unwraps the FullValue as a regular ol' real.
    ///
    /// # Returns
    /// The internal real value.
    ///
    /// # Panics
    /// This function panics if the given value was not actually a real.
    #[inline]
    pub fn real(self) -> f64 {
        if let Self::Real(value) = self {
            value
        } else {
            panic!("Cannot unwrap a non-FullValue::Real as FullValue::Real");
        }
    }

    /// Force-unwraps the FullValue as a regular ol' string.
    ///
    /// # Returns
    /// The internal string value.
    ///
    /// # Panics
    /// This function panics if the given value was not actually a string.
    #[inline]
    pub fn string(self) -> String {
        if let Self::String(value) = self {
            value
        } else {
            panic!("Cannot unwrap a non-FullValue::String as FullValue::String");
        }
    }

    /// Force-unwraps the FullValue as a regular ol' dataset (identifier).
    ///
    /// # Returns
    /// The internal dataset's identifier.
    ///
    /// # Panics
    /// This function panics if the given value was not actually a data.
    #[inline]
    pub fn data(self) -> String {
        if let Self::Data(value) = self {
            value.0
        } else {
            panic!("Cannot unwrap a non-FullValue::Data as FullValue::Data");
        }
    }

    /// Force-unwraps the FullValue as a regular ol' intermediate result (identifier).
    ///
    /// # Returns
    /// The internal results's identifier.
    ///
    /// # Panics
    /// This function panics if the given value was not actually a data.
    #[inline]
    pub fn result(self) -> String {
        if let Self::IntermediateResult(value) = self {
            value.0
        } else {
            panic!("Cannot unwrap a non-FullValue::IntermediateResult as FullValue::IntermediateResult");
        }
    }

    /// Returns the DataType of this Value. Note that the following properties may be assumed:
    /// - The datatype is never Void (since it is a value)
    /// - Because it is runtime, it _always_ has a non-Any type (i.e., it's always resolved).
    #[inline]
    pub fn data_type(&self) -> DataType {
        use FullValue::*;
        match self {
            Boolean(_) => DataType::Boolean,
            Integer(_) => DataType::Integer,
            Real(_) => DataType::Real,
            String(_) => DataType::String,

            Array(values) => DataType::Array { elem_type: Box::new(values.iter().next().map(|v| v.data_type()).unwrap_or(DataType::Any)) },
            Instance(name, _) => {
                if name == BuiltinClasses::Data.name() {
                    DataType::Data
                } else {
                    DataType::Class { name: name.clone() }
                }
            },
            Data(_) => DataType::Data,
            IntermediateResult(_) => DataType::IntermediateResult,

            Void => DataType::Void,
        }
    }

    /// Converts the FullValue into its lighter self by resolving its own internals to definition references.
    ///
    /// # Arguments
    /// - `table`: The VirtualTable where will reference to.
    ///
    /// # Returns
    /// A new Value with references instead of duplicate types and such.
    #[inline]
    pub fn to_value(&self, table: &SymTable) -> Value {
        use FullValue::*;
        match self {
            Boolean(value) => Value::Boolean { value: *value },
            Integer(value) => Value::Integer { value: *value },
            Real(value) => Value::Real { value: *value },
            String(value) => Value::String { value: value.clone() },

            Array(values) => Value::Array { values: values.iter().map(|v| v.to_value(table)).collect() },
            Instance(name, values) => Value::Instance {
                values: values.iter().map(|(n, v)| (n.clone(), v.to_value(table))).collect(),
                def:    table.classes.iter().enumerate().find_map(|(i, c)| if &c.name == name { Some(i) } else { None }).unwrap(),
            },
            Data(name) => Value::Data { name: name.0.clone() },
            IntermediateResult(name) => Value::IntermediateResult { name: name.0.clone() },

            Void => Value::Void,
        }
    }

    /// Converts the FullValue into its lighter self by resolving its own internals to definition references.
    ///
    /// This operator consumes self, which allows for a more efficient conversion in the case of objects.
    ///
    /// # Arguments
    /// - `table`: The VirtualTable where will reference to.
    ///
    /// # Returns
    /// A new Value with references instead of duplicate types and such.
    #[inline]
    pub fn into_value(self, table: &SymTable) -> Value {
        use FullValue::*;
        match self {
            Boolean(value) => Value::Boolean { value },
            Integer(value) => Value::Integer { value },
            Real(value) => Value::Real { value },
            String(value) => Value::String { value },

            Array(values) => Value::Array { values: values.into_iter().map(|v| v.into_value(table)).collect() },
            Instance(name, values) => Value::Instance {
                values: values.into_iter().map(|(n, v)| (n, v.into_value(table))).collect(),
                def:    table.classes.iter().enumerate().find_map(|(i, c)| if c.name == name { Some(i) } else { None }).unwrap(),
            },
            Data(name) => Value::Data { name: name.0 },
            IntermediateResult(name) => Value::IntermediateResult { name: name.0 },

            Void => Value::Void,
        }
    }
}

impl Display for FullValue {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> FResult {
        use FullValue::*;
        match self {
            Boolean(value) => write!(f, "{value}"),
            Integer(value) => write!(f, "{value}"),
            Real(value) => write!(f, "{value}"),
            String(value) => write!(f, "{value}"),

            Array(values) => write!(f, "[{}]", values.iter().map(|v| format!("{v}")).collect::<Vec<std::string::String>>().join(", ")),
            Instance(name, values) => write!(
                f,
                "{} {{{}{}{}}}",
                name,
                if values.is_empty() { "" } else { " " },
                values.iter().map(|(n, v)| format!("{n} := {v}")).collect::<Vec<std::string::String>>().join(", "),
                if values.is_empty() { "" } else { " " },
            ),
            Data(name) => write!(f, "{name}"),
            IntermediateResult(name) => write!(f, "{name}"),

            Void => write!(f, "()"),
        }
    }
}

impl TryFrom<JValue> for FullValue {
    type Error = Error;

    #[inline]
    fn try_from(value: JValue) -> Result<Self, Self::Error> {
        match serde_json::from_value(value) {
            Ok(res) => Ok(res),
            Err(err) => Err(Error::JsonError { err }),
        }
    }
}
