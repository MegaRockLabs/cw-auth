#[cfg(feature = "cosmwasm")]
use saa_common::{Api, Env, MessageInfo, to_json_binary};
use saa_common::{hashes::sha256, AuthError, CredentialId, Verifiable};
use saa_schema::*;

use super::utils::{preamble_msg_arb_036, pubkey_to_account};


#[wasm_serde]
pub struct CosmosArbitrary {
    pub pubkey:    Vec<u8>,
    pub message:   Vec<u8>,
    pub signature: Vec<u8>,
    pub hrp:       Option<String>
}


impl Verifiable for CosmosArbitrary {

    fn id(&self) -> CredentialId {
        self.pubkey.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        if !(self.signature.len() > 0 &&
            self.message.len() > 0 && 
            self.pubkey.len() > 0) {
            return Err(AuthError::InvalidLength("Empty credential data".to_string()));
        }
        Ok(())
    }

    fn verify(&self) -> Result<(), AuthError> {
        if self.hrp.is_none() {
            return Err(AuthError::Generic("Must provice prefix of the chain".to_string()));
        }

        let addr = pubkey_to_account(&self.pubkey, &self.hrp.as_ref().unwrap());

        let digest = sha256(
            &preamble_msg_arb_036(
                addr.as_str(), 
                &data_encoding::BASE64.encode(&self.message)
            ).as_bytes()
        );

        let res = saa_common::cosmwasm_crypto::secp256k1_verify(
            &digest,
            &self.signature,
            &self.pubkey
        )?;

        if !res {
            return Err(AuthError::Signature("Signature verification failed".to_string()));
        }

        Ok(())
    }


    #[cfg(feature = "cosmwasm")]
    fn verify_cosmwasm(
        &mut self, 
        api:  &dyn Api, 
        _:  &Env,
        _: &MessageInfo
    ) -> Result<(), AuthError> {
        use super::utils::pubkey_to_canonical;

        let canonical = pubkey_to_canonical(&self.pubkey);
        let addr = api.addr_humanize(&canonical)?;

        let data = to_json_binary(&self.message)?.to_base64();

        let digest = sha256(
            &preamble_msg_arb_036(
                addr.as_str(), 
                data.as_str()
            ).as_bytes()
        );

        let res = api.secp256k1_verify(
            &digest,
            &self.signature,
            &self.pubkey
        )?;

        if !res {
            return Err(AuthError::Signature("Signature verification failed".to_string()));
        }

        Ok(())
    }
}