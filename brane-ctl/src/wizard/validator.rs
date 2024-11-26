/// A placeholder concrete type in cases where no validator is necessary
pub use brane_shr::input::NoValidator;
use dialoguer::InputValidator;

/// A validator that solely validates that there if *some* input was provided
#[derive(Default)]
pub struct NotEmptyValidator;

impl InputValidator<String> for NotEmptyValidator {
    type Err = String;

    fn validate(&mut self, input: &String) -> Result<(), Self::Err> {
        if input.is_empty() { Err(String::from("Value may not be empty")) } else { Ok(()) }
    }
}

/// A validator  that validates whether the provided number is a valid port number
/// Yes this is basically a check if something fits in a u16
#[derive(Default)]
pub struct PortValidator;

impl InputValidator<String> for PortValidator {
    type Err = String;

    fn validate(&mut self, input: &String) -> Result<(), Self::Err> {
        match input.parse::<u16>() {
            Ok(_) => Ok(()),
            Err(err) => Err(format!("Entered port is not valid: {err}")),
        }
    }
}

/// A validator that checks whether the provided input is a valid range. It by default uses a `-`
/// as range seperator, but this is configurable using the seperator field. It allows whitespace
/// around the range values. The segment validator validates the separate parts of the range using
/// the same instance.
pub struct RangeValidator<V>
where
    V: InputValidator<String>,
{
    pub separator: String,
    pub segment_validator: V,
    pub allow_empty: bool,
}

impl<V> Default for RangeValidator<V>
where
    V: Default,
    V: dialoguer::InputValidator<String>,
{
    fn default() -> Self { Self { separator: String::from("-"), segment_validator: Default::default(), allow_empty: false } }
}

impl<V> InputValidator<String> for RangeValidator<V>
where
    V: InputValidator<String>,
    V::Err: ToString,
{
    type Err = String;

    fn validate(&mut self, input: &String) -> Result<(), Self::Err> {
        if self.allow_empty && input.trim().is_empty() {
            return Ok(());
        }

        let Some((start, end)) = input.split_once(&self.separator) else {
            return Err(format!("No range separator {} found", self.separator));
        };

        self.segment_validator.validate(&String::from(start.trim())).map_err(|err| err.to_string())?;
        self.segment_validator.validate(&String::from(end.trim())).map_err(|err| err.to_string())?;

        Ok(())
    }
}

/// The map validator can validate mappings from between different types of values. By default
/// these values are separated by a `:`, but this is configurable using the `separator` field.
pub struct MapValidator<V1, V2>
where
    V1: InputValidator<String>,
    V2: InputValidator<String>,
{
    pub separator: String,
    pub left_validator: V1,
    pub right_validator: V2,
    pub allow_empty: bool,
}

impl<V1, V2> Default for MapValidator<V1, V2>
where
    V1: Default,
    V1: dialoguer::InputValidator<String>,
    V2: Default,
    V2: dialoguer::InputValidator<String>,
{
    fn default() -> Self {
        Self { separator: String::from(":"), left_validator: Default::default(), right_validator: Default::default(), allow_empty: false }
    }
}

impl<V1, V2> InputValidator<String> for MapValidator<V1, V2>
where
    V1: InputValidator<String>,
    V1::Err: ToString,
    V2: InputValidator<String>,
    V2::Err: ToString,
{
    type Err = String;

    fn validate(&mut self, input: &String) -> Result<(), Self::Err> {
        if self.allow_empty && input.is_empty() {
            return Ok(());
        }

        let Some((left, right)) = input.split_once(&self.separator) else {
            return Err(format!("No separator {} found", self.separator));
        };

        self.left_validator.validate(&String::from(left.trim())).map_err(|err| err.to_string())?;
        self.right_validator.validate(&String::from(right.trim())).map_err(|err| err.to_string())?;

        Ok(())
    }
}

/// The validator is a wrapper for all types that implement [`std::str::FromStr`], it uses `FromStr` to validate if
/// the provided input is correct. This assumes that the `Result` that `FromStr` provides correctly
/// distinguishes correct from incorrect inputs. If your `FromStr` implementation is expensive,
/// this might come at a performance hit.
pub struct FromStrValidator<T>
where
    T: std::str::FromStr,
{
    pub field_name: &'static str,
    _fd: std::marker::PhantomData<T>,
}

impl<T> Default for FromStrValidator<T>
where
    T: std::str::FromStr,
{
    fn default() -> Self {
        let field_name_raw = std::any::type_name::<T>();
        let field_name = match field_name_raw.rsplit_once("::") {
            Some((_, segment)) => segment,
            None => field_name_raw,
        };
        Self { _fd: std::marker::PhantomData, field_name }
    }
}

impl<T> InputValidator<String> for FromStrValidator<T>
where
    T: std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    type Err = String;

    fn validate(&mut self, input: &String) -> Result<(), Self::Err> {
        match T::from_str(input) {
            Ok(_) => Ok(()),
            Err(err) => Err(format!("Input is not a legal {}: {err}", self.field_name)),
        }
    }
}

/// Implenents a validator for optional fields. This either inputs that are valid for the wrapped
/// validator or empty string (and whitespace characters)
// Unfortunately, due to the orphan rule we cannot simply implement this for Option<V>, so we have
// to wrap it.
pub struct OptionValidator<T, V>
where
    T: std::str::FromStr,
    V: InputValidator<T>,
{
    pub validator: V,
    _fd: std::marker::PhantomData<T>,
}

impl<T, V> InputValidator<T> for OptionValidator<T, V>
where
    V: InputValidator<T>,
    T: ToString,
    T: std::str::FromStr,
{
    type Err = V::Err;

    fn validate(&mut self, input: &T) -> Result<(), Self::Err> {
        if input.to_string().trim().is_empty() {
            return Ok(());
        }

        return self.validator.validate(input);
    }
}

impl<T, V> Default for OptionValidator<T, V>
where
    T: std::str::FromStr,
    V: InputValidator<T>,
    V: Default,
{
    fn default() -> Self { Self { validator: Default::default(), _fd: std::marker::PhantomData } }
}
