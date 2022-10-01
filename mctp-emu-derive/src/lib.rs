// MIT License
//
// Copyright © 2022-present, Justin Simon <jls5177@gmail.com>.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use proc_macro;
use proc_macro2;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_attribute]
pub fn add_binary_derives(
    _metadata: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input: proc_macro2::TokenStream = input.into();
    let output = quote! {
        #[derive(serde::Serialize, serde::Deserialize, mctp_emu_derive::FromBinary)]
        #input
    };
    output.into()
}

#[proc_macro_derive(FromBinary)]
pub fn derive(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl From<#ident> for Vec<u8> {
            fn from(t: #ident) -> Self {
                bincode::serialize(&t).unwrap()
            }
        }

        impl From<#ident> for bytes::Bytes {
            fn from(t: #ident) -> Self {
                bytes::Bytes::from(bincode::serialize(&t).unwrap())
            }
        }

        impl TryFrom<Vec<u8>> for #ident {
            type Error = ParseError;
            fn try_from(vec: Vec<u8>) -> std::result::Result<Self, Self::Error> {
                let struct_size = std::mem::size_of::<#ident>();
                if vec.len() < struct_size {
                    return Err(ParseError::InvalidPayloadSize {
                        expected: struct_size.to_string(),
                        found: vec.len().to_string(),
                    });
                }
                bincode::deserialize(&vec[..])
                    .context("Failed deserializing message")
                    .map_err(|err| ParseError::Other(err))
            }
        }

        impl TryFrom<bytes::Bytes> for #ident {
            type Error = ParseError;
            fn try_from(bytes: bytes::Bytes) -> std::result::Result<Self, Self::Error> {
                let struct_size = std::mem::size_of::<#ident>();
                if bytes.len() < struct_size {
                    return Err(ParseError::InvalidPayloadSize {
                        expected: struct_size.to_string(),
                        found: bytes.len().to_string(),
                    });
                }
                bincode::deserialize(bytes.as_ref())
                    .context("Failed deserializing message")
                    .map_err(|err| ParseError::Other(err))
            }
        }
    };
    output.into()
}

#[proc_macro_attribute]
pub fn add_from_control_payload_derives(
    _metadata: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input: proc_macro2::TokenStream = input.into();
    let output = quote! {
        #[derive(serde::Serialize, serde::Deserialize, mctp_emu_derive::FromControlPayload)]
        #input
    };
    output.into()
}

#[proc_macro_derive(AddControlMsgResponse)]
pub fn derive_control_msg_response(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl crate::control::ControlMsgReponseStatus for #ident {
            fn is_success(&self) -> anyhow::Result<()> {
                if CompletionCode::from(self.completion_code) != CompletionCode::Success {
                    return Err(Error::msg(format!(
                        "Response returned an error code: {:?}",
                        self.completion_code
                    )));
                }
                Ok(())
            }

            fn completion_code(&self) -> CompletionCode {
                self.completion_code.into()
            }
        }
    };
    output.into()
}

#[proc_macro_derive(FromControlPayload)]
pub fn derive_control_payload(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl From<#ident> for Vec<u8> {
            fn from(t: #ident) -> Self {
                bincode::serialize(&t).unwrap()
            }
        }

        impl From<#ident> for bytes::Bytes {
            fn from(t: #ident) -> Self {
                let ser = bincode::serialize(&t).unwrap();
                println!("DEBUG: {:#?}", ser);
                bytes::Bytes::from(ser)
            }
        }

        impl TryFrom<bytes::Bytes> for #ident {
            type Error = ParseError;
            fn try_from(bytes: bytes::Bytes) -> std::result::Result<Self, Self::Error> {
                let struct_size = std::mem::size_of::<#ident>();
                if bytes.len() < struct_size {
                    return Err(ParseError::InvalidPayloadSize {
                        expected: struct_size.to_string(),
                        found: bytes.len().to_string(),
                    });
                }
                bincode::deserialize(bytes.as_ref())
                    .context("Failed deserializing message")
                    .map_err(|err| ParseError::Other(err))
            }
        }

        impl TryFrom<ControlPayload> for #ident {
            type Error = ParseError;
            fn try_from(msg: ControlPayload) -> std::result::Result<Self, Self::Error> {
                let struct_size = std::mem::size_of::<#ident>();
                if msg.payload.len() < struct_size {
                    return Err(ParseError::InvalidPayloadSize {
                        expected: struct_size.to_string(),
                        found: msg.payload.len().to_string(),
                    });
                }
                bincode::deserialize(msg.payload.as_ref())
                    .context("Failed deserializing message")
                    .map_err(|err| ParseError::Other(err))
            }
        }
    };
    output.into()
}

#[proc_macro_derive(DeserializeU8Enum)]
pub fn derive_deserialize_u8_enum(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl<'de> serde::Deserialize<'de> for #ident {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let val = u8::deserialize(deserializer)?;
                Ok(#ident::from(val))
            }
        }
    };
    output.into()
}

#[proc_macro_derive(SerializeU8Enum)]
pub fn derive_serialize_u8_enum(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input);
    let output = quote! {
        impl serde::Serialize for #ident {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_u8(*self as u8)
            }
        }
    };
    output.into()
}
