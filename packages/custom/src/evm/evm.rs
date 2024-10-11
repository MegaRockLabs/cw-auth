#[cfg(feature = "cosmwasm")]
use cosmwasm_std::{Api, Env, MessageInfo};

#[cfg(feature = "native")] 
use saa_common::crypto::secp256k1_recover_pubkey;

use saa_schema::wasm_serde;

use saa_common::{
    hashes::keccak256_fixed, AuthError, Binary, CredentialId, String, Verifiable 
};

use super::utils::{get_recovery_param, preamble_msg_eth};


#[wasm_serde]
pub struct EvmCredential {
    pub message:   Binary,
    pub signature: Binary,
    pub signer:    String,
}


impl Verifiable for EvmCredential {

    fn id(&self) -> CredentialId {
        self.signer.as_bytes().to_vec()
    }

    fn human_id(&self) -> String {
        self.signer.clone()
    }

    fn validate(&self) -> Result<(), AuthError> {
        if self.signature.len() < 65 {
            return Err(AuthError::MissingData("Signature must be at least 65 bytes".to_string()));
        }

        let signer_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;

        if signer_bytes.len() != 20 {
            return Err(AuthError::MissingData("Signer must be 20 bytes".to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "native")] 
    fn verify(&self) -> Result<(), AuthError> {
        let key_data = secp256k1_recover_pubkey(
            &preamble_msg_eth(&self.message), 
            &self.signature.0[..64], 
            get_recovery_param(self.signature.0[64])?
        )?;
    
        let hash = keccak256_fixed(&key_data[1..]);
        let recovered = String::from_utf8(
            hash[12..].to_vec()
        ).map_err(|_| AuthError::RecoveryMismatch)?;
    
        if self.signer == recovered {
            Ok(())
        } else {
            Err(AuthError::RecoveryMismatch)
        }
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(&self, api: &dyn Api, _: &Env, _: &Option<MessageInfo>) -> Result<Self, AuthError> {

        let key_data = api.secp256k1_recover_pubkey(
            &preamble_msg_eth(&self.message), 
            &self.signature.0[..64], 
            get_recovery_param(self.signature.0[64])?
        )?;
    
        let hash = keccak256_fixed(&key_data[1..]);

        let addr_bytes = hex::decode(&self.signer[2..])
            .map_err(|e| AuthError::generic(e.to_string()))?;
        
        if addr_bytes == hash[12..] {
            Ok(self.clone())
        } else {
            Err(AuthError::RecoveryMismatch)
        }
    }
}

