#![cfg_attr(not(feature = "std"), no_std)]

use saa_macros_proto;
pub use saa_macros_proto::wasm_serde;


pub use {serde, schemars};

#[cfg(feature = "solana")]
pub use borsh;

#[cfg(feature = "substrate")]
pub use scale;

#[cfg(all(feature = "std", feature = "substrate"))]
pub use scale_info;
