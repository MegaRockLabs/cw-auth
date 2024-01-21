mod errors;
pub mod hashes;
pub use errors::*;
pub use cosmwasm_crypto;


pub type CredentialId = Vec<u8>;

#[cfg(feature = "cosmwasm")]
pub use cosmwasm_std::{
    Api, Env, Binary, Addr, CanonicalAddr, MessageInfo,
    from_json, to_json_binary,
};


#[cfg(feature = "substrate")]
pub use ink::{
    env::{
        account_id, caller,
        Environment, DefaultEnvironment
    },
    primitives::AccountId
};

#[cfg(feature = "substrate")]
pub type EnvAccess = ink::EnvAccess<'static, DefaultEnvironment>;


pub trait Verifiable {
    fn id(&self) -> CredentialId;
    fn validate(&self) -> Result<(), AuthError>;
    fn verify(&self) -> Result<(), AuthError>;


    #[cfg(feature = "substrate")]
    fn verified_ink(&self, _: &EnvAccess) -> Result<Self, AuthError> 
        where Self: Sized + Clone
    {
        self.verify()?;
        Ok(self.clone())
    }

    #[cfg(feature = "cosmwasm")]
    fn verified_cosmwasm(& self, _:  &dyn Api, _:  &Env, _: &MessageInfo) -> Result<Self, AuthError> 
        where Self: Sized + Clone
    {
        self.verify()?;
        Ok(self.clone())
    }
}