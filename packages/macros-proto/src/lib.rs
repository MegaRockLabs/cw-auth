use quote::ToTokens;
use syn::{parse_quote, parse_macro_input, DeriveInput};


#[proc_macro_attribute]
pub fn wasm_serde(
    _attr: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let expanded : DeriveInput = match input.data {
        syn::Data::Struct(_) => parse_quote! {
            #[derive(
                ::std::clone::Clone,
                ::std::fmt::Debug,
                ::std::cmp::PartialEq
            )]
            #[cfg_attr(feature = "cosmwasm", 
                derive(
                    ::cosmwasm_schema::serde::Serialize,
                    ::cosmwasm_schema::serde::Deserialize,
                    ::cosmwasm_schema::schemars::JsonSchema
                ),
                schemars(crate = "::cosmwasm_schema::schemars"),
                serde(deny_unknown_fields, crate = "::cosmwasm_schema::serde")
            )]
            #[cfg_attr(feature = "solana", derive(
                ::borsh_derive::BorshSerialize, 
                ::borsh_derive::BorshDeserialize
            ))]
            #[cfg_attr(feature = "substrate", derive(
                ::scale::Encode, 
                ::scale::Decode, 
                ::scale_info::TypeInfo)
            )]
            #[allow(clippy::derive_partial_eq_without_eq)]
            #input
        },
        syn::Data::Enum(_) => parse_quote! {
            #[derive(
                ::std::clone::Clone,
                ::std::fmt::Debug,
                ::std::cmp::PartialEq
            )]
            #[cfg_attr(feature = "cosmwasm", 
                derive(
                    ::cosmwasm_schema::serde::Serialize,
                    ::cosmwasm_schema::serde::Deserialize,
                    ::cosmwasm_schema::schemars::JsonSchema
                ),
                schemars(crate = "::cosmwasm_schema::schemars"),
                serde(deny_unknown_fields, rename_all = "snake_case", crate = "::cosmwasm_schema::serde")
            )]
            #[cfg_attr(feature = "solana", derive(
                ::borsh_derive::BorshSerialize, 
                ::borsh_derive::BorshDeserialize
            ))]
            #[cfg_attr(feature = "substrate", derive(
                ::scale::Encode, 
                ::scale::Decode, 
                ::scale_info::TypeInfo)
            )]
            #[allow(clippy::derive_partial_eq_without_eq)]
            #input
        },
        syn::Data::Union(_) => panic!("unions are not supported"),
    };

    let stream = expanded.into_token_stream();

    proc_macro::TokenStream::from(stream)
}