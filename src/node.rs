use actix_web::{self, client, HttpMessage};
use futures::prelude::{async, await};
use openssl::sha::sha256;
use secp256k1::SecretKey;
use json;
use openssl::{rand, symm};
use std::str;
use std::str::FromStr;
use num_bigint::BigInt;
use std::convert::TryFrom;
use json::Value;
use actix_web::client::ClientRequestBuilder;
use std::borrow::Cow;
use actix_web::client::SendRequestError;
use openssl::symm::Cipher;
use std::error::Error;

use Empty;
use serde::{Serialize};
use actix_web::error::PayloadError;
use actix_web::http::StatusCode;

#[derive(Debug)]
pub enum ServiceError {
    /// Something wrong went during RPC call.
    Generic(GenericError),
    /// Real service error.
    Service(Box<dyn Error>),
}

impl From<GenericError> for ServiceError {
    fn from(err: GenericError) -> Self {
        ServiceError::Generic(err)
    }
}

#[derive(Debug)]
pub enum GenericError {
    /// Error while serializing request message.
    RequestSerialization(Box<dyn Error>),
    /// Error while encoding serialized request message.
    RequestEncoding(Box<dyn Error>),
    /// General purpose transport error.
    Transport(actix_web::Error),
    /// Error while sending request to a server.
    RequestSend(SendRequestError),
    /// Error that can occur during response payload parsing.
    ResponseRecv(PayloadError),
    /// Error while decoding response message.
    ResponseDecoding(Box<dyn Error>),
    /// Error while deserializing response message into a typed struct.
    ResponseDeserialization(Box<dyn Error>),
}

impl From<actix_web::Error> for GenericError {
    fn from(err: actix_web::Error) -> Self {
        GenericError::Transport(err)
    }
}

impl From<SendRequestError> for GenericError {
    fn from(err: SendRequestError) -> Self {
        GenericError::RequestSend(err)
    }
}

impl From<PayloadError> for GenericError {
    fn from(err: PayloadError) -> Self {
        GenericError::ResponseRecv(err)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Balance {
    live_snm: BigInt,
    side_snm: BigInt,
    live_eth: BigInt,
}

impl Balance {
    #[inline]
    pub fn live_snm(&self) -> &BigInt {
        &self.live_snm
    }

    #[inline]
    pub fn side_snm(&self) -> &BigInt {
        &self.side_snm
    }

    #[inline]
    pub fn live_eth(&self) -> &BigInt {
        &self.live_eth
    }
}

impl TryFrom<Value> for Balance {
    type Error = Box<dyn Error>;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let live_snm = value["liveBalance"]
            .as_str()
            .ok_or("`liveBalance` field is required")?;
        let side_snm = value["sideBalance"]
            .as_str()
            .ok_or("`sideBalance` field is required")?;
        let live_eth = value["liveEthBalance"]
            .as_str()
            .ok_or("`liveEthBalance` field is required")?;

        let balance = Balance {
            live_snm: BigInt::from_str(live_snm)?,
            side_snm: BigInt::from_str(side_snm)?,
            live_eth: BigInt::from_str(live_eth)?,
        };

        Ok(balance)
    }
}

#[derive(Clone, Copy)]
pub struct AES256Cipher {
    cipher: Cipher,
    key: [u8; 32],
}

impl AES256Cipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: symm::Cipher::aes_256_cfb128(),
            key,
        }
    }
    pub fn encode(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut iv = vec![0u8; 16];
        rand::rand_bytes(&mut iv[..])?;

        let encrypted_message = symm::encrypt(self.cipher, &self.key, Some(&iv[..]), data)?;

        let mut result = iv;
        result.extend(encrypted_message.iter());
        Ok(result)
    }

    pub fn decode(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let result = symm::decrypt(self.cipher, &self.key, Some(&data[..16]), &data[16..])?;

        Ok(result)
    }
}

/// Node API.
#[derive(Clone)]
pub struct Node {
    secret: SecretKey,
    base_uri: Cow<'static, str>,
    cipher: AES256Cipher,
}

impl Node {
    pub fn new(secret: SecretKey) -> Self {
        Self {
            secret,
            base_uri: "http://localhost:15031".into(),
            cipher: AES256Cipher::new(sha256(&secret[..])),
        }
    }

    /// Returns current account's balance.
    #[async]
    pub fn balance(self) -> Result<Balance, ServiceError> {
        let request = Empty{};
        let response = await!(self.execute("TokenManagementServer/Balance".into(), request))?;

        Ok(response)
    }

    #[async]
    fn execute<T, R>(self, path: Cow<'static, str>, request: T) -> Result<R, ServiceError>
    where
        T: Serialize + 'static,
        R: TryFrom<Value, Error = Box<dyn Error>>,
    {
        let body = json::to_vec(&request).map_err(|err| GenericError::RequestSerialization(err.into()))?;
        let body = self.cipher.encode(&body).map_err(GenericError::RequestEncoding)?;

        let request = self.make_request(&path)
            .body(body)
            .map_err(GenericError::Transport)?;
        let response = await!(request.send())
            .map_err(GenericError::RequestSend)?;

        let body = await!(response.body()).map_err(GenericError::ResponseRecv)?;
        let body = self.cipher.decode(&body).map_err(GenericError::ResponseDecoding)?;

        if let StatusCode::OK = response.status() {
            let value: Value = json::from_slice(&body).map_err(|err| GenericError::ResponseDeserialization(err.into()))?;
            let response = R::try_from(value).map_err(|err| GenericError::ResponseDeserialization(err))?;

            Ok(response)
        } else {
            Err(ServiceError::Service(String::from_utf8(body).unwrap_or("<invalid UTF8>".into()).into()))
        }
    }

    #[inline]
    fn make_request(&self, path: &str) -> ClientRequestBuilder {
        client::post(format!("{}/{}", self.base_uri, path))
    }
}
