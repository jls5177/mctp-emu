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
//! Provides a configurable MCTP network emulation framework to emulate MCTP endpoints and
//! bridged networks.
#![allow(dead_code, unused)]

#[macro_use]
extern crate c2rust_bitfields;

use std::{io, result};
use tokio::sync::{mpsc, oneshot};

pub mod endpoint;
pub mod hex_dump;
pub mod network;
pub mod phys;

#[derive(Debug, thiserror::Error)]
pub enum MctpEmuError {
    #[error("Base library failed")]
    Base(#[from] mctp_base_lib::base::MctpBaseLibError),

    #[error("Physical transport failed")]
    Phys(#[from] crate::phys::Error),

    #[error("Network failed")]
    Network(#[from] crate::network::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),

    #[non_exhaustive]
    #[error("unknown error")]
    Unknown,
}

/// Result type used when return value is needed from methods in library.
pub type MctpEmuResult<T> = std::result::Result<T, MctpEmuError>;

/// Result type used when return value is _NOT_ needed from methods in library.
pub type MctpEmuEmptyResult = std::result::Result<(), MctpEmuError>;

pub type OneshotResponder<T> = oneshot::Sender<io::Result<T>>;
pub type Responder<T> = mpsc::Sender<io::Result<T>>;
