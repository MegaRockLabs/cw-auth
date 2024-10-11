#![cfg_attr(not(feature = "std"), no_std)]


mod identity;
mod binary;
mod errors;
pub mod hashes;
pub use errors::*;

pub use binary::{Binary, to_json_binary, from_json};


#[cfg(any(feature = "std", not(feature = "substrate")))]
pub use std::{
    string::{ToString, String},
    vec, vec::Vec, 
    format
};

#[cfg(all(not(feature = "std"), feature = "substrate"))]
pub use ink::prelude::{
    string::{ToString, String},
    vec, vec::Vec, 
    format, 
};



#[cfg(feature = "native")]
pub mod crypto {
    pub use cosmwasm_crypto::*;    
} 



#[cfg(feature = "cosmwasm")]
pub mod cosmwasm {
    pub use cosmwasm_std::{
        Api, Env, Addr, CanonicalAddr, MessageInfo, Binary,
        from_json, to_json_binary, ensure, ensure_eq, ensure_ne
    };
}


#[cfg(feature = "substrate")]
pub mod substrate {
    pub use ink::env as ink_env;
    pub use {
        ink_env::Environment as InkEnvironment,
        ink::EnvAccess as InkApi,
    };

    pub mod default {
        use ink::env as ink_env;
        pub use ink_env::DefaultEnvironment;
        pub type AccountId = <DefaultEnvironment as ink_env::Environment>::AccountId;
        pub type EnvAccess<'a> = ink::EnvAccess<'a, DefaultEnvironment>;
    }
}

/* #[cfg(feature = "cosmwasm")]
use cosmwasm::*;
#[cfg(feature = "substrate")]
use substrate::*;
 */


#[macro_export]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            return Err(core::convert::From::from($e));
        }
    };
}




pub trait Verifiable   {

    fn id(&self) -> CredentialId;

    fn human_id(&self) -> String {
        Binary(self.id()).to_base64()
    }

    fn validate(&self) -> Result<(), AuthError>;

    #[cfg(feature = "native")]
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "substrate")]
    fn verified_ink<'a>(
        &self,  
        _ : substrate::InkApi<'a, 
        impl substrate::InkEnvironment + Clone>
    ) -> Result<Self, AuthError> 
        where Self: Clone
    {
        #[cfg(feature = "native")]
        self.verify()?;
        #[cfg(feature = "native")]
        return Ok(self.clone());

        #[cfg(not(feature = "native"))]
        return Err(AuthError::generic("Not implemented"));
    }

    
    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(
        &self, 
        _:  &dyn cosmwasm::Api, 
        _:  &cosmwasm::Env, 
        _:  &Option<cosmwasm::MessageInfo>
    ) -> Result<Self, AuthError> 
        where Self: Clone
    {
        #[cfg(feature = "native")]
        self.verify()?;
        #[cfg(feature = "native")]
        return Ok(self.clone());

        #[cfg(not(feature = "native"))]
        return Err(AuthError::generic("Not implemented"));
    }
}


pub type CredentialId = Vec<u8>;



