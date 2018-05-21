use std::io::{self, Read};

use crypto::symmetriccipher::SymmetricCipherError;
use crypto::aessafe::AesSafe128Encryptor;
use crypto::blockmodes::CtrMode;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::scrypt::{self, ScryptParams};
use crypto::symmetriccipher::Decryptor;
use hex::{FromHex, FromHexError};
use json;
use keccak::Keccak;
use secp256k1::{self, Secp256k1, SecretKey};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// Error that is returned when failed to deserialize the account from JSON.
    Json(json::Error),
    FromHexError(FromHexError),
    InvalidCipher(String),
    InvalidPassphrase,
    /// Unknown account version.
    ///
    /// The linked id contains actual version number.
    InvalidVersion(i32),
    Secp256k1(secp256k1::Error),
    CipherError(SymmetricCipherError),
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

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Self {
        Error::Secp256k1(err)
    }
}

impl From<SymmetricCipherError> for Error {
    fn from(err: SymmetricCipherError) -> Self {
        Error::CipherError(err)
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
    /// The name of a symmetric AES algorithm.
    cipher: String,
    /// Your Ethereum private key encrypted using the "cipher" algorithm above.
    ciphertext: String,
    /// The parameters required for the "cipher" algorithm above.
    cipherparams: CipherParams,
    /// A Key Derivation Function used to let you encrypt your keystore file with a password.
    kdf: String,
    /// The parameters required for the "kdf" algorithm above.
    kdfparams: KDFParams,
    /// A code used to verify your password.
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
    pub fn from_rd<R: Read>(rd: R) -> Result<Self, Error> {
        let account = json::from_reader(rd)?;
        Ok(account)
    }

    #[inline]
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn decrypt(&self, password: &str) -> Result<SecretKey, Error> {
        match self.version {
            3 => {
                let key = decrypt_v3(&self.crypto, password)?;
                let secp = Secp256k1::new();
                let secret = SecretKey::from_slice(&secp, &key)?;

                Ok(secret)
            }
            version => Err(Error::InvalidVersion(version)),
        }
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
                encrypt.decrypt(&mut RefReadBuffer::new(&ciphertext), &mut RefWriteBuffer::new(&mut buf), true)?;

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
    use hex::FromHex;
    use secp256k1;
    use super::*;

    #[test]
    fn open_account() {
        let buf = r#"{"address":"8125721c2413d99a33e351e1f6bb4e56b6b633fd","crypto":{"cipher":"aes-128-ctr","ciphertext":"ee00310ad9ab03f7b85cbabf72b919c7ed15f80b71f9531c167823995b28057a","cipherparams":{"iv":"67365b4d1ba21d457f3dbb22e46b627a"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":4096,"p":6,"r":8,"salt":"0b28c47f7b5cf61be98e157c1f12d52e039120c28f42d50291f4674dc262ef8f"},"mac":"5f370bb0bcc879ed0db74716cbd24861ab0a9839e6985b82f9c2b48a127b6453"},"id":"c0137aac-b22c-42f0-9b42-192af24fe103","version":3}"#;
        let account = Account::from_rd(buf.as_bytes()).unwrap();

        assert_eq!("c0137aac-b22c-42f0-9b42-192af24fe103", account.id());

        let secret = account.decrypt("any").unwrap();
        let x = secp256k1::Secp256k1::new();
        assert_eq!(SecretKey::from_slice(&x, &"a5dd45e0810ca83e21f1063e6bf055bd13544398f280701cbfda1346bcf3ae64"[..].from_hex().unwrap()).unwrap(), secret);
    }
}
