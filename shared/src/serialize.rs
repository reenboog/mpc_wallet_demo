use serde::{Deserialize, Serialize};

// this module helps to easily switch from one format to another: json for tests, maybe bincode on prod

#[derive(Debug)]
pub struct Error(String);

impl ToString for Error {
	fn to_string(&self) -> String {
		self.0.clone()
	}
}

impl From<serde_json::Error> for Error {
	fn from(er: serde_json::Error) -> Self {
		Self(er.to_string())
	}
}

pub fn to_vec<T>(val: &T) -> Result<Vec<u8>, Error>
where
	T: Serialize,
{
	Ok(serde_json::to_vec(val)?)
}

pub fn from_slice<T>(val: &[u8]) -> Result<T, Error>
where
	T: for<'de> Deserialize<'de>,
{
	Ok(serde_json::from_slice::<T>(val)?)
}

pub fn to_base64<T>(val: &T) -> Result<String, Error>
where
	T: Serialize,
{
	Ok(base64::encode_config(
		&to_vec(val)?,
		base64::URL_SAFE_NO_PAD,
	))
}

pub fn from_base64<T>(val: &str) -> Result<T, Error>
where
	T: for<'de> Deserialize<'de>,
{
	Ok(from_slice::<T>(
		&base64::decode_config(val, base64::URL_SAFE_NO_PAD).map_err(|e| Error(e.to_string()))?,
	)?)
}

#[cfg(test)]
mod tests {
	use crate::serialize;
	use serde::{Deserialize, Serialize};

	#[test]
	fn test_serialize_deserialize() {
		#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
		struct MyType {
			msg: Vec<u8>,
		}

		let msg = MyType {
			msg: b"hi there".to_vec(),
		};
		let serialized = serialize::to_vec(&msg).unwrap();
		let deserialized = serialize::from_slice::<MyType>(&serialized).unwrap();

		assert_eq!(msg, deserialized);
	}
}
