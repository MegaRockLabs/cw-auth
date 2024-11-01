#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env};
use saa_schema::wasm_serde;

use saa_common::{
    CredentialInfo, CredentialName, CredentialId, 
    AuthError, Binary, ToString, Verifiable, ensure
};


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


    fn info(&self) -> CredentialInfo {
        CredentialInfo {
            name: CredentialName::Ed25519,
            extension: None,
            hrp: None
        }
    }

    fn message(&self) -> Binary {
        self.message.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        ensure!(
            self.signature.len() > 0 &&
                self.message.len() > 0 && 
                self.pubkey.len() > 0,
            AuthError::MissingData("Empty credential data".to_string())
        );
        Ok(())
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        let success = saa_common::crypto::ed25519_verify(
            &saa_common::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(success, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(&self, api: &dyn Api, _: &Env) -> Result<(), AuthError> {
        let success = api.ed25519_verify(
            &saa_common::hashes::sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        ensure!(success, AuthError::Signature("Signature verification failed".to_string()));
        Ok(())
    }

}