#![allow(unreachable_code)]
use saa_common::{to_json_binary, AuthError, Binary, CredentialId, CredentialInfo, CredentialName, Verifiable};
use saa_auth::caller::Caller;
use saa_schema::wasm_serde;

#[cfg(feature = "curves")]
use saa_curves::{ed25519::Ed25519, secp256k1::Secp256k1, secp256r1::Secp256r1};

#[cfg(all(not(feature = "curves"), feature = "ed25519" ))]
use saa_curves::ed25519::Ed25519;

#[cfg(feature = "passkeys")]
use saa_auth::passkey::PasskeyCredential;

#[cfg(feature = "ethereum")]
use saa_auth::eth::EthPersonalSign;

#[cfg(feature = "cosmos")]
use saa_auth::cosmos::CosmosArbitrary;

#[cfg(feature = "wasm")]
use saa_common::cosmwasm::{Api, Addr, Env, MessageInfo};

#[cfg(all(feature = "wasm", feature = "storage"))]
use saa_common::{storage::*, cosmwasm::Storage, messages::*, ensure, from_json};


#[wasm_serde]
pub enum Credential {
    Caller(Caller),

    #[cfg(feature = "ethereum")]
    EthPersonalSign(EthPersonalSign),

    #[cfg(feature = "cosmos")]
    CosmosArbitrary(CosmosArbitrary),

    #[cfg(feature = "passkeys")]
    Passkey(PasskeyCredential),

    #[cfg(feature = "curves")]
    Secp256k1(Secp256k1),

    #[cfg(feature = "curves")]
    Secp256r1(Secp256r1),
    
    #[cfg(any(feature = "curves", feature = "ed25519" ))]
    Ed25519(Ed25519),
}


impl Credential {

    pub fn name(&self) -> CredentialName {
        match self {
            Credential::Caller(_) => CredentialName::Caller,
            #[cfg(feature = "passkeys")]
            Credential::Passkey(_) => CredentialName::Passkey,
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(_) => CredentialName::EthPersonalSign,
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(_) => CredentialName::CosmosArbitrary,
            #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
            Credential::Ed25519(_) => CredentialName::Ed25519,
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(_) => CredentialName::Secp256k1,
                    Credential::Secp256r1(_) => CredentialName::Secp256r1,
                    Credential::Ed25519(_) => CredentialName::Ed25519,
                    _ => unreachable!(),
                }
            },
        }
    }

    fn value(&self) -> &dyn Verifiable {
        match self {
            Credential::Caller(c) => c,
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c,
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c,
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c,
            #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
            Credential::Ed25519(c) => c,
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c,
                    Credential::Secp256r1(c) => c,
                    Credential::Ed25519(c) => c,
                    _ => unreachable!(),
                }
            },
        }
    }

    pub fn message(&self) -> Vec<u8> {
        match self {
            Credential::Caller(_) => Vec::new(),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.message.to_vec(),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.message.to_vec(),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => {
                let base64 =  saa_auth::passkey::utils::url_to_base64(&c.client_data.challenge);
                Binary::from_base64(&base64).unwrap().to_vec()
            },
            #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
            Credential::Ed25519(c) => c.message.to_vec(),
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.message.to_vec(),
                    Credential::Secp256r1(c) => c.message.to_vec(),
                    Credential::Ed25519(c) => c.message.to_vec(),
                    _ => unreachable!(),
                }
            },
        }
    }

    pub fn extension(&self) -> Result<Option<Binary>, AuthError> {
        #[cfg(feature = "passkeys")]
        if let Credential::Passkey(c) = self {
            use saa_auth::passkey::*;
            return Ok(Some(to_json_binary(&PasskeyExtension {
                origin: c.client_data.origin.clone(),
                cross_origin: c.client_data.cross_origin.clone(),
                pubkey: c.pubkey.clone(),
                user_handle: c.user_handle.clone(),
            })?));
        }
        Ok(None)
    }

    pub fn info(&self) -> CredentialInfo {
        CredentialInfo {
            name: self.name(),
            hrp: self.hrp(),
            extension: self.extension().unwrap_or(None),
        }
    }

    #[cfg(feature = "wasm")]
    pub fn is_cosmos_derivable(&self) -> bool {
        self.hrp().is_some()
    }

    #[cfg(feature = "wasm")]
    pub fn cosmos_address(&self, api: &dyn Api) -> Result<Addr, AuthError> {
        let name = self.name();
        if name == CredentialName::Caller {
            let address =  String::from_utf8(self.id())
                    .map(|s| Addr::unchecked(s))?;
            return Ok(address)
        }
        #[cfg(all(feature = "injective", feature="ethereum"))]
        {
            if name == CredentialName::EthPersonalSign {
                return Ok(Addr::unchecked(
                    saa_common::utils::pubkey_to_address(
                        &self.id(), "inj"
                    )?
                ))
            } 
        }
        Ok(match self.hrp() {
            Some(hrp) => Addr::unchecked(
                saa_common::utils::pubkey_to_address(&self.id(), &hrp)?
            ),
            None => {
                let canon = saa_common::utils::pubkey_to_canonical(&self.id());
                let addr = api.addr_humanize(&canon)?;
                addr
            }
        })
    }


    #[cfg(all(feature = "wasm", feature = "storage"))]
    pub fn assert_cosmwasm(
        &self, 
        api     :  &dyn Api, 
        storage :  &dyn Storage,
        env     :  &Env, 
    ) -> Result<(), AuthError> 
        where Self: Sized
    {   
        ensure!(has_credential(storage, &self.id()), AuthError::NotFound);
        self.verify_cosmwasm(api)?;
        #[cfg(feature = "replay")]
        {
            let msg : MsgDataToVerify = from_json(&self.message())?;
            msg.validate_cosmwasm(storage, env)?;
        }
        Ok(())
    }

    
    #[cfg(all(feature = "wasm", feature = "storage"))]
    pub fn save_cosmwasm(&self, 
        api: &dyn Api, 
        storage: &mut dyn Storage,
        env:  &Env,
        info: &MessageInfo
    ) -> Result<(), AuthError> {
        self.assert_cosmwasm(api, storage, env)?;
        save_credential(storage, &self.id(), &self.info())?;
        #[cfg(feature = "replay")]
        increment_account_number(storage)?;
        if let Credential::Caller(_) = self {
            CALLER.save(storage, &Some(info.sender.to_string()))?;
        }
        Ok(())
    }

    
}

impl Verifiable for Credential {

    fn id(&self) -> CredentialId {
        self.value().id()
    }

    fn hrp(&self) -> Option<String> {
        self.value().hrp()
    }

    fn validate(&self) -> Result<(), AuthError> {
        self.value().validate()
    }

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError> {
        self.value().verify()
    }

    #[cfg(feature = "wasm")]
    fn verify_cosmwasm(&self,  api:  &dyn Api) -> Result<(), AuthError>  
        where Self: Sized
    {
        self.validate()?;
        match self {
            Credential::Caller(c) => c.verify_cosmwasm(api),
            #[cfg(feature = "passkeys")]
            Credential::Passkey(c) => c.verify_cosmwasm(api),
            #[cfg(feature = "ethereum")]
            Credential::EthPersonalSign(c) => c.verify_cosmwasm(api),
            #[cfg(feature = "cosmos")]
            Credential::CosmosArbitrary(c) => c.verify_cosmwasm(api),
            #[cfg(all(not(feature = "curves"), feature = "ed25519"))]
            Credential::Ed25519(c) => c.verify_cosmwasm(api),
            #[cfg(feature = "curves")]
            curve => {
                match curve {
                    Credential::Secp256k1(c) => c.verify_cosmwasm(api),
                    Credential::Secp256r1(c) => c.verify_cosmwasm(api),
                    Credential::Ed25519(c) => c.verify_cosmwasm(api),
                    _ => unreachable!(),
                }
            },
        }
    }

}






