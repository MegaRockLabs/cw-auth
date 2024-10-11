#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo};
use saa_common::{AuthError, Binary, CredentialId, Verifiable};
use saa_schema::wasm_serde;

#[cfg(any(feature = "cosmwasm", feature = "native"))]
use saa_common::hashes::sha256;

#[wasm_serde]
pub struct Ed25519 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
}


impl Verifiable for Ed25519 {

    fn id(&self) -> CredentialId {
        self.pubkey.0.clone()
    }

    fn human_id(&self) -> String {
        self.pubkey.to_base64()
    }

    fn validate(&self) -> Result<(), AuthError> {
        if !(self.signature.len() > 0 &&
            self.message.len() > 0 && 
            self.pubkey.len() > 0) {
            return Err(AuthError::MissingData("Empty credential data".to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        let res = saa_common::crypto::ed25519_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        if !res {
            return Err(AuthError::Signature("Signature verification failed".to_string()));
        }
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(&self, api: &dyn Api, _: &Env, _: &Option<MessageInfo>) -> Result<Self, AuthError> {
        let res = api.ed25519_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        if !res {
            return Err(AuthError::Signature("Signature verification failed".to_string()));
        }
        Ok(self.clone())
    }
}