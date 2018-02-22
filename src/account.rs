use crypto::aessafe::AesSafe128Encryptor;
use crypto::blockmodes::CtrMode;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::scrypt::{self, ScryptParams};
use crypto::symmetriccipher::Decryptor;
use hex::{FromHex, FromHexError};
use json;
use keccak::Keccak;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Json(json::Error),
    FromHexError(FromHexError),
    InvalidCipher(String),
    InvalidPassphrase,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<json::Error> for Error {
    fn from(err: json::Error) -> Self {
        Error::Json(err)
    }
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Self {
        Error::FromHexError(err)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct KDFParams {
    dklen: u32,
    n: u32,
    p: u32,
    r: u32,
    salt: String,
}

impl KDFParams {
    #[inline]
    fn log2n(&self) -> u8 {
        (32 - self.n.leading_zeros() - 1) as u8
    }
}

#[derive(Clone, Debug, Deserialize)]
struct CipherParams {
    iv: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Crypto {
    cipher: String,
    ciphertext: String,
    cipherparams: CipherParams,
    kdf: String,
    kdfparams: KDFParams,
    mac: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Account {
    address: String,
    crypto: Crypto,
    id: String,
    version: i32,
}

impl Account {
    pub fn from_rd<R: Read>(rd: R, password: &str) -> Result<Self, Error> {
        let account: Account = json::from_reader(rd)?;

        match account.version {
            3 => decrypt_v3(&account.crypto, password)?,
            _ => unimplemented!(),
        };

        Ok(account)
    }

    pub fn load<P: AsRef<Path>>(path: P, password: &str) -> Result<Self, Error> {
        let rd = File::open(path)?;
        Self::from_rd(rd, password)
    }

    #[inline]
    pub fn id(&self) -> &str {
        &self.id
    }
}

fn decrypt_v3(crypto: &Crypto, password: &str) -> Result<Vec<u8>, Error> {
    match crypto.cipher.as_str() {
        "aes-128-ctr" => {
            let salt = crypto.kdfparams.salt.from_hex()?;
            let params = ScryptParams::new(crypto.kdfparams.log2n(), crypto.kdfparams.r, crypto.kdfparams.p);
            let mut derived_key = vec![0u8; crypto.kdfparams.dklen as usize];
            scrypt::scrypt(password.as_bytes(), &salt, &params, &mut derived_key);

            let ciphertext = crypto.ciphertext.from_hex()?;
            let mut keccak = Keccak::new_keccak256();
            let mut mac = [0u8; 32];
            keccak.update(&derived_key[16..32]);
            keccak.update(&ciphertext);
            keccak.finalize(&mut mac);

            if mac == crypto.mac.from_hex()?.as_ref() {
                let iv = crypto.cipherparams.iv.from_hex()?;
                let mut buf = vec![0u8; ciphertext.len()];
                let mut encrypt = CtrMode::new(AesSafe128Encryptor::new(&derived_key[..16]), iv.to_vec());
                encrypt.decrypt(&mut RefReadBuffer::new(&ciphertext), &mut RefWriteBuffer::new(&mut buf), true).unwrap();

                Ok(buf)
            } else {
                Err(Error::InvalidPassphrase)
            }
        }
        cipher => Err(Error::InvalidCipher(cipher.into())),
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn open_account() {
        let buf = r#"{"address":"8125721c2413d99a33e351e1f6bb4e56b6b633fd","crypto":{"cipher":"aes-128-ctr","ciphertext":"ee00310ad9ab03f7b85cbabf72b919c7ed15f80b71f9531c167823995b28057a","cipherparams":{"iv":"67365b4d1ba21d457f3dbb22e46b627a"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":4096,"p":6,"r":8,"salt":"0b28c47f7b5cf61be98e157c1f12d52e039120c28f42d50291f4674dc262ef8f"},"mac":"5f370bb0bcc879ed0db74716cbd24861ab0a9839e6985b82f9c2b48a127b6453"},"id":"c0137aac-b22c-42f0-9b42-192af24fe103","version":3}"#;
        let account = Account::from_rd(buf.as_bytes(), "any").unwrap();

        assert_eq!("c0137aac-b22c-42f0-9b42-192af24fe103", account.id());
    }
}
