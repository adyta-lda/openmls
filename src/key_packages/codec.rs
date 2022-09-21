use crate::config::{Config, ProtocolVersion};
use crate::{extensions::*, ciphersuite};
use crate::key_packages::*;

impl Codec for KeyPackage {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.append(&mut self.unsigned_payload()?);
        self.signature.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let protocol_version = ProtocolVersion::decode(cursor)?;
        let ciphersuite_name = CiphersuiteName::decode(cursor)?;
        let hpke_init_key = HPKEPublicKey::decode(cursor)?;
        let credential = Credential::decode(cursor)?;
        let extensions = extensions_vec_from_cursor(cursor)?;
        let signature: Signature;
        let ciphersuite: &Ciphersuite;

        if ciphersuite_name.eq(&CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521) {
            signature = Signature::new_empty();
            ciphersuite = Config::ciphersuite(CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256)?; //all we need for now is to pass through the function
        } else{
            signature = Signature::decode(cursor)?;
            ciphersuite = Config::ciphersuite(ciphersuite_name)?;
        }

        let kp = KeyPackage {
            protocol_version,
            ciphersuite,
            ciphersuite_name,
            hpke_init_key,
            credential,
            extensions,
            signature,
        };

        if ciphersuite_name.eq(&CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521) {
            return Ok(kp);
        }
        if kp.verify().is_err() {
            log::error!("Error verifying a key package after decoding\n{:?}", kp);
            return Err(CodecError::DecodingError);
        }
        Ok(kp)
    }
}
