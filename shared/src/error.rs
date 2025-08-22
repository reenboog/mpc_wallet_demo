use std::fmt;

#[derive(Debug)]
pub enum Error {
	Io(String),
}
