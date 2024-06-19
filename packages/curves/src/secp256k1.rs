#[cfg(feature = "cosmwasm")]
use saa_common::cosmwasm::{Api, Env, MessageInfo};

use saa_schema::wasm_serde;

use saa_common::{
    ToString, Binary,
    AuthError, Verifiable, CredentialId,
    hashes::sha256
};



#[wasm_serde]
pub struct Secp256k1 {
    pub pubkey:    Binary,
    pub message:   Binary,
    pub signature: Binary,
    pub hrp:       Option<String>
}



impl Verifiable for Secp256k1 {

    fn id(&self) -> CredentialId {
        self.pubkey.0.clone()
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
        saa_common::crypto::secp256k1_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;
        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(&self, api: &dyn Api, _: &Env, _: &Option<MessageInfo>) -> Result<Self, AuthError> {

        api.secp256k1_verify(
            &sha256(&self.message), 
            &self.signature, 
            &self.pubkey
        )?;

        Ok(self.clone())
    }
}
