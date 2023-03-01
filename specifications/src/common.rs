use std::cmp::{Ordering, PartialEq, PartialOrd};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter};
use std::string::ToString;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JValue};
use serde_with::skip_serializing_none;

use crate::package::{PackageKind, Capability};
use crate::version::Version;


/***** CUSTOM TYPES *****/
/// Shortcut for defining a hashmap with string keys.
type Map<T> = std::collections::HashMap<String, T>;





/***** DSL AST STRUCTS *****/
/// Defines a function parameter in the DSL's AST.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameter {
    #[serde(rename = "type")]
    pub data_type: String,
    pub default: Option<Value>,
    pub name: String,
    pub optional: Option<bool>,
    pub secret: Option<String>,
}

impl Parameter {
    ///
    ///
    ///
    pub fn new(
        name: String,
        data_type: String,
        optional: Option<bool>,
        default: Option<Value>,
        secret: Option<String>,
    ) -> Self {
        Parameter {
            data_type,
            default,
            name,
            optional,
            secret,
        }
    }
}



/// Defines a (local) function in the DSL's AST.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Function {
    pub parameters: Vec<Parameter>,
    pub pattern: Option<CallPattern>,
    pub return_type: String,
    pub requirements: Option<HashSet<Capability>>,
}

impl Function {
    ///
    ///
    ///
    pub fn new(
        parameters: Vec<Parameter>,
        pattern: Option<CallPattern>,
        return_type: String,
        requirements: Option<HashSet<Capability>>,
    ) -> Self {
        Function {
            parameters,
            pattern,
            return_type,
            requirements,
        }
    }
}



/// Defines a callpattern for Bakery in the AST.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallPattern {
    pub infix: Option<Vec<String>>,
    pub postfix: Option<String>,
    pub prefix: Option<String>,
}

impl CallPattern {
    ///
    ///
    ///
    pub fn new(
        prefix: Option<String>,
        infix: Option<Vec<String>>,
        postfix: Option<String>,
    ) -> Self {
        CallPattern { infix, postfix, prefix }
    }
}



/// Defines a type used in the DSL's AST.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Type {
    pub name: String,
    pub properties: Vec<Property>,
}

impl Type {
    ///
    ///
    ///
    pub fn new(
        name: String,
        properties: Vec<Property>,
    ) -> Self {
        Type { name, properties }
    }
}



/// Defines a struct property field in the DSL's AST.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Property {
    #[serde(rename = "type")]
    pub data_type: String,
    pub default: Option<Value>,
    pub name: String,
    pub optional: Option<bool>,
    pub properties: Option<Vec<Property>>,
    pub secret: Option<bool>,
}

impl Property {
    ///
    ///
    ///
    pub fn new(
        name: String,
        data_type: String,
        properties: Option<Vec<Property>>,
        default: Option<Value>,
        optional: Option<bool>,
        secret: Option<bool>,
    ) -> Self {
        Property {
            data_type,
            default,
            name,
            optional,
            properties,
            secret,
        }
    }

    ///
    ///
    ///
    pub fn new_quick(
        name: &str,
        data_type: &str,
    ) -> Self {
        Property {
            data_type: data_type.to_string(),
            default: None,
            name: name.to_string(),
            optional: None,
            properties: None,
            secret: None,
        }
    }

    ///
    ///
    ///
    pub fn into_parameter(self) -> Parameter {
        Parameter::new(self.name, self.data_type, self.optional, self.default, None)
    }
}



/// Defines a special class in the DSL's AST, i.e., a custom type.
#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecClass {
    pub name: String,
    pub properties: HashMap<String, String>,
    pub methods: HashMap<String, SpecFunction>,
}

impl SpecClass {
    pub fn new(
        name: String,
        properties: HashMap<String, String>,
        methods: HashMap<String, SpecFunction>,
    ) -> Self {
        Self {
            name,
            properties,
            methods,
        }
    }
}

impl fmt::Debug for SpecClass {
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        write!(f, "class<{}>", self.name)
    }
}



/// Defines a value of some sort, which can be of multiple types.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "v", content = "c", rename_all = "camelCase")]
pub enum Value {
    Array {
        #[serde(rename = "type")]
        data_type: String,
        entries: Vec<Value>,
    },
    Boolean(bool),
    Integer(i64),
    Pointer {
        #[serde(rename = "type")]
        data_type: String,
        variable: String,
        #[serde(default = "Default::default")]
        secret: bool,
    },
    Real(f64),
    Struct {
        #[serde(rename = "type")]
        data_type: String,
        properties: Map<Value>,
    },
    Unicode(String),
    Unit,
    Class(SpecClass),
    Function(SpecFunction),
    FunctionExt(FunctionExt),
}



impl From<SpecFunction> for Value {
    fn from(function: SpecFunction) -> Self {
        Value::Function(function)
    }
}

impl From<String> for Value {
    fn from(string: String) -> Self {
        Value::Unicode(string)
    }
}

impl From<bool> for Value {
    fn from(boolean: bool) -> Self {
        Value::Boolean(boolean)
    }
}

impl From<i64> for Value {
    fn from(integer: i64) -> Self {
        Value::Integer(integer)
    }
}

impl From<f64> for Value {
    fn from(real: f64) -> Self {
        Value::Real(real)
    }
}

impl From<()> for Value {
    fn from(_: ()) -> Self {
        Value::Unit
    }
}

impl Value {
    ///
    ///
    ///
    pub fn from_json(value: &JValue) -> Self {
        match value {
            JValue::Null => Value::Unit,
            JValue::Bool(b) => Value::Boolean(*b),
            JValue::Number(n) => {
                if n.is_i64() {
                    Value::Integer(n.as_i64().unwrap())
                } else {
                    Value::Real(n.as_f64().unwrap())
                }
            }
            JValue::String(s) => Value::Unicode(s.clone()),
            JValue::Array(a) => {
                let entries: Vec<Value> = a.iter().map(Value::from_json).collect();
                let data_type = format!("{}[]", entries.first().unwrap().data_type());

                Value::Array { data_type, entries }
            }
            JValue::Object(o) => {
                let mut properties = Map::<Value>::new();
                let data_type = String::from("anonymous");

                for (name, jvalue) in o.iter() {
                    properties.insert(name.clone(), Value::from_json(jvalue));
                }

                Value::Struct { data_type, properties }
            }
        }
    }

    /* TIM */
    /// **Edited: Changed return type to String instead of &str.**
    ///
    /// Returns a string representation of the Value's type.
    pub fn data_type(&self) -> String {
        use Value::*;
        match self {
            Array { data_type, .. } => data_type.clone(),
            Boolean(_) => "boolean".to_string(),
            Integer(_) => "integer".to_string(),
            Pointer { data_type, .. } => data_type.clone(),
            Real(_) => "real".to_string(),
            Struct { data_type, .. } => data_type.clone(),
            Unicode(_) => "string".to_string(),
            Unit => "unit".to_string(),
            Function(_) => "function".to_string(),
            Class(_) => "class".to_string(),
            FunctionExt(_) => "FunctionExt".to_string(),
        }
    }
    /*******/

    ///
    ///
    ///
    pub fn as_bool(&self) -> Result<bool> {
        if let Value::Boolean(b) = self {
            Ok(*b)
        } else {
            Err(anyhow!("Value does not contain a boolean."))
        }
    }

    ///
    ///
    ///
    pub fn as_f64(&self) -> Result<f64> {
        if let Value::Real(f) = self {
            Ok(*f)
        } else {
            Err(anyhow!("Value does not contain a real (float)."))
        }
    }

    ///
    ///
    ///
    pub fn as_i64(&self) -> Result<i64> {
        if let Value::Integer(i) = self {
            Ok(*i)
        } else {
            Err(anyhow!("Value does not contain an integer."))
        }
    }

    ///
    ///
    ///
    pub fn as_string(&self) -> Result<String> {
        if let Value::Unicode(s) = self {
            Ok(s.clone())
        } else {
            Err(anyhow!("Value does not contain a string."))
        }
    }

    ///
    ///
    ///
    pub fn as_json(&self) -> JValue {
        use Value::*;
        match self {
            Array { entries, .. } => json!(entries.iter().map(|e| e.as_json()).collect::<JValue>()),
            Boolean(b) => json!(b),
            Integer(i) => json!(i),
            Pointer { .. } => unimplemented!(),
            Real(r) => json!(r),
            Struct { data_type, properties } => match data_type.as_str() {
                "Directory" | "File" => {
                    let url = properties.get("url").unwrap();
                    json!({
                        "class": data_type,
                        "path": url.as_json(),
                    })
                }
                _ => {
                    let mut object = Map::<JValue>::new();
                    for (name, value) in properties {
                        object.insert(name.clone(), value.as_json());
                    }

                    json!(object)
                }
            },
            Unicode(s) => json!(s),
            Unit => json!(null),
            _ => todo!(),
        }
    }
}

impl Display for Value {
    fn fmt(
        &self,
        f: &mut Formatter,
    ) -> fmt::Result {
        use Value::*;
        let value = match self {
            Array { entries, .. } => {
                let entries = entries
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<String>>()
                    .join(", ");
                format!("[{entries}]")
            }
            Boolean(b) => b.to_string(),
            Integer(i) => i.to_string(),
            Pointer { variable, .. } => format!("@{variable}"),
            Real(r) => r.to_string(),
            Struct { properties, data_type } => {
                let properties = properties
                    .iter()
                    .map(|(n, p)| format!("{n}: {p}"))
                    .collect::<Vec<String>>()
                    .join(", ");
                format!("{data_type} {{{properties}}}")
            }
            Unicode(s) => s.to_string(),
            Unit => String::from("unit"),
            _ => String::from("class/function: TODO"),
        };

        write!(f, "{value}")
    }
}

impl PartialEq for Value {
    ///
    ///
    ///
    fn eq(
        &self,
        other: &Self,
    ) -> bool {
        use Value::*;

        match (self, other) {
            (Array { .. }, Array { .. }) => unimplemented!(),
            (Boolean(lhs), Boolean(rhs)) => lhs.eq(rhs),
            (Integer(lhs), Integer(rhs)) => lhs.eq(rhs),
            (Pointer { .. }, Pointer { .. }) => unimplemented!(),
            (Real(lhs), Real(rhs)) => lhs.eq(rhs),
            (Struct { .. }, Struct { .. }) => unimplemented!(),
            (Unicode(lhs), Unicode(rhs)) => lhs.eq(rhs),
            (Unit, Unit) => true,
            _ => false,
        }
    }
}

impl PartialOrd for Value {
    ///
    ///
    ///
    fn partial_cmp(
        &self,
        other: &Self,
    ) -> Option<Ordering> {
        use Value::*;

        match (self, other) {
            (Boolean(lhs), Boolean(rhs)) => lhs.partial_cmp(rhs),
            (Integer(lhs), Integer(rhs)) => lhs.partial_cmp(rhs),
            (Real(lhs), Real(rhs)) => lhs.partial_cmp(rhs),
            (Unicode(lhs), Unicode(rhs)) => lhs.partial_cmp(rhs),
            _ => Option::None,
        }
    }
}



/// Defines an (external) function in the DSL's AST.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionExt {
    pub detached: bool,
    pub digest: String,
    pub kind: PackageKind,
    pub name: String,
    pub package: String,
    pub parameters: Vec<Parameter>,
    pub version: Version,
}

/* TIM */
impl std::fmt::Display for FunctionExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{}()", self.name)
    }
}
/*******/



/// Defines a special function(?) in the DSL's AST.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpecFunction {
    pub arity: u8,
    pub bytecode: Bytecode,
    pub name: String,
}



/// Defines a section of bytecode in the DSL's AST (i.e., compilation output).
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Bytecode {
    pub code: Vec<u8>,
    pub constants: Vec<Value>,
}



/// Defines a variable in the DSL's AST.
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Variable {
    #[serde(rename = "type")]
    pub data_type: String,
    pub name: String,
    pub scope: Option<String>,
    pub value: Option<Value>,
}

impl Variable {
    ///
    ///
    ///
    pub fn new(
        name: String,
        data_type: String,
        scope: Option<String>,
        value: Option<Value>,
    ) -> Self {
        Variable {
            data_type,
            name,
            scope,
            value,
        }
    }

    ///
    ///
    ///
    pub fn as_pointer(&self) -> Value {
        Value::Pointer {
            data_type: self.data_type.clone(),
            secret: false,
            variable: self.name.clone(),
        }
    }
}
