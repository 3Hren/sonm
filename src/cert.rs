use ethereum_types::{Address, Public};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::sha;
use openssl::x509::{X509, X509Name};
use openssl::x509::extension::{ExtendedKeyUsage, SubjectAlternativeName};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use tiny_keccak::Keccak;

pub mod account;

pub trait Keccak256<T> {
    fn keccak256(&self) -> T where T: Sized;
}

pub trait AsAddr {
    fn as_addr(&self) -> Address;
}

impl AsAddr for Public {
    #[inline]
    fn as_addr(&self) -> Address {
        let hash = self.keccak256();
        Address::from_slice(&hash[12..])
    }
}

impl<T> Keccak256<[u8; 32]> for T where T: AsRef<[u8]> {
    fn keccak256(&self) -> [u8; 32] {
        let mut keccak = Keccak::new_keccak256();
        let mut result = [0u8; 32];
        keccak.update(self.as_ref());
        keccak.finalize(&mut result);
        result
    }
}

fn double_hash(data: &[u8]) -> [u8; 32] {
    sha::sha256(&sha::sha256(data))
}

pub fn generate(secret: SecretKey) -> Result<(X509, PKey<Private>), ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let private_key = PKey::from_rsa(rsa)?;
    let rsa_public_key_encoded = private_key.public_key_to_der()?;

    let x = Secp256k1::new();
    let sign = x.sign(&Message::from_slice(&double_hash(&rsa_public_key_encoded)).unwrap(), &secret).unwrap();

    let public_key = PublicKey::from_secret_key(&x, &secret).unwrap();
    let cn = base64::encode(&public_key.serialize()[..]) + "@" + &base64::encode(&sign.serialize_der(&x));

    let mut name = X509Name::builder()?;
    name.append_entry_by_nid(Nid::COMMONNAME, &cn)?;
    let name = name.build();

    let mut builder = X509::builder()?;

    builder.set_version(2)?;
    builder.set_serial_number(&&BigNum::from_u32(100)?.to_asn1_integer()?)?;
    builder.set_subject_name(&name)?;
    builder.set_not_before(&&Asn1Time::days_from_now(0)?)?;
    builder.set_not_after(&&Asn1Time::days_from_now(1)?)?;
    builder.append_extension(ExtendedKeyUsage::new()
        .client_auth()
        .server_auth()
        .build()?
    )?;

    let dns = Public::from_slice(&public_key.serialize()[1..]).as_addr();

    let subject_alt_name = SubjectAlternativeName::new()
        .dns(&format!("{:x}", dns))
        .build(&builder.x509v3_context(None, None))?;
    builder.append_extension(subject_alt_name)?;

    Ok((builder.build(), private_key))
}