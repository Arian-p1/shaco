use std::error::Error;
use std::fmt;
#[derive(Debug)] // Allow the use of "{:?}" format specifier
pub enum CustomError {
    UnknownUUID,
}
// Allow the use of "{}" format specifier
impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CustomError::UnknownUUID => write!(f, "Unknown UUID"),
        }
    }
}
// Allow this type to be treated like an error
impl Error for CustomError {
    fn description(&self) -> &str {
        match *self {
            CustomError::UnknownUUID => "Unknown UUID",
        }
    }
    fn cause(&self) -> Option<&dyn Error> {
        match *self {
            CustomError::UnknownUUID => None,
        }
    }
}