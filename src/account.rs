use std::io::Read;

use crypto::symmetriccipher::SymmetricCipherError;
use crypto::aessafe::AesSafe128Encryptor;
use crypto::blockmodes::CtrMode;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::scrypt::{self, ScryptParams};
use crypto::symmetriccipher::Decryptor;
use hex::{FromHex, ToHex};
use json;
use keccak::Keccak;
use secp256k1::{self, Secp256k1, SecretKey};
use std::fmt::{self, Display, Formatter};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug)]
pub enum Error {
    /// Error that is returned when failed to deserialize the account from JSON.
    Json(json::Error),
    /// Unknown account version.
    ///
    /// The linked id contains actual version number.
    InvalidVersion(i32),
    /// Invalid cipher type.
    ///
    /// The returned string contains actual cipher specified.
    InvalidCipher(String),
    /// Failed to decrypt the account, because of invalid passphrase.
    InvalidPassphrase,
    /// Failed to decrypt ciphertext.
    CipherError(SymmetricCipherError),
    /// An ECDSA error.
    Secp256k1(secp256k1::Error),
}

impl Display for Error {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), fmt::Error> {
        match self {
            Error::Json(err) => write!(fmt, "failed to parse account: {}", err),
            Error::InvalidVersion(v) => write!(fmt, "invalid account version: {}", v),
            Error::InvalidCipher(v) => write!(fmt, "unknown cipher: {}", v),
            Error::InvalidPassphrase => fmt.write_str("invalid passphrase"),
            Error::CipherError(err) => write!(fmt, "failed to decrypt ciphertext: {:?}", err),
            Error::Secp256k1(err) => write!(fmt, "failed to load private key from decoded ciphertext: {}", err),
        }
    }
}

impl From<json::Error> for Error {
    fn from(err: json::Error) -> Self {
        Error::Json(err)
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

/// Helper wrapper for serializing/deserializing hex strings with format checks.
#[derive(Clone, Debug)]
struct Hex(Vec<u8>);

impl Hex {
    /// Returns the slice representing this hex value.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Hex(data) => &data
        }
    }
}

impl Serialize for Hex {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Hex(data) => serializer.serialize_str(&data.to_hex())
        }
    }
}

impl<'de> Deserialize<'de> for Hex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v: String = Deserialize::deserialize(deserializer)?;
        let s = v.from_hex().map_err(|err| de::Error::custom(format!("failed to deserialize from hex: {}", err)))?;
        Ok(Hex(s))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct KDFParams {
    dklen: u32,
    n: u32,
    p: u32,
    r: u32,
    salt: Hex,
}

impl KDFParams {
    #[inline]
    fn log2n(&self) -> u8 {
        (32 - self.n.leading_zeros() - 1) as u8
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CipherParams {
    iv: Hex,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Crypto {
    /// The name of a symmetric AES algorithm.
    cipher: String,
    /// Your Ethereum private key encrypted using the "cipher" algorithm above.
    ciphertext: Hex,
    /// The parameters required for the "cipher" algorithm above.
    cipherparams: CipherParams,
    /// A Key Derivation Function used to let you encrypt your keystore file with a password.
    kdf: String,
    /// The parameters required for the "kdf" algorithm above.
    kdfparams: KDFParams,
    /// A code used to verify your password.
    mac: Hex,
}

impl Crypto {
    fn decrypt_v3(&self, password: &str) -> Result<Vec<u8>, Error> {
        match self.cipher.as_str() {
            "aes-128-ctr" => {
                let params = ScryptParams::new(self.kdfparams.log2n(), self.kdfparams.r, self.kdfparams.p);
                let mut derived_key = vec![0u8; self.kdfparams.dklen as usize];
                scrypt::scrypt(password.as_bytes(), self.kdfparams.salt.as_bytes(), &params, &mut derived_key);

                let ciphertext = self.ciphertext.as_bytes();
                let mut keccak = Keccak::new_keccak256();
                let mut mac = [0u8; 32];
                keccak.update(&derived_key[16..32]);
                keccak.update(&ciphertext);
                keccak.finalize(&mut mac);

                if mac == self.mac.as_bytes() {
                    let iv = self.cipherparams.iv.as_bytes();
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Account {
    address: String,
    crypto: Crypto,
    id: String,
    version: i32,
}

impl Account {
    /// Loads the account from the specified reader.
    ///
    /// The content must be in JSON format.
    pub fn from_rd<R: Read>(rd: R) -> Result<Self, Error> {
        let account = json::from_reader(rd)?;
        Ok(account)
    }

    /// Returns this's account ID.
    #[inline]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Decrypts the account using specified password.
    pub fn decrypt(&self, password: &str) -> Result<SecretKey, Error> {
        match self.version {
            3 => {
                let key = self.crypto.decrypt_v3(password)?;
                let secp = Secp256k1::new();
                let secret = SecretKey::from_slice(&secp, &key)?;

                Ok(secret)
            }
            version => Err(Error::InvalidVersion(version)),
        }
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

    #[test]
    fn open_account_fail_non_hex_iv() {
        let buf = r#"{"address":"8125721c2413d99a33e351e1f6bb4e56b6b633fd","crypto":{"cipher":"aes-128-ctr","ciphertext":"ee00310ad9ab03f7b85cbabf72b919c7ed15f80b71f9531c167823995b28057a","cipherparams":{"iv":"zzz"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":4096,"p":6,"r":8,"salt":"0b28c47f7b5cf61be98e157c1f12d52e039120c28f42d50291f4674dc262ef8f"},"mac":"5f370bb0bcc879ed0db74716cbd24861ab0a9839e6985b82f9c2b48a127b6453"},"id":"c0137aac-b22c-42f0-9b42-192af24fe103","version":3}"#;
        let account = Account::from_rd(buf.as_bytes());

        assert!(account.is_err());
        assert_eq!("failed to parse account: failed to deserialize from hex: Invalid character 'z' at position 0 at line 1 column 194", format!("{}", account.err().unwrap()));
    }
}
