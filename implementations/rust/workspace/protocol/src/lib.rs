// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! The core library for the VoteSecure project.
//!
//! This library provides state machine implementations of the e-voting protocol
//! for all participants. It is designed to be integrated into host applications
//! that will provide the necessary networking and user interface layers.
//!
//! The primary entry point for each participant is a top-level actor, which
//! manages the state for all that participant's subprotocols.

// Only necessary for custom_warning_macro
#![feature(stmt_expr_attributes)]
// Only necessary for custom_warning_macro
#![feature(proc_macro_hygiene)]

// --- Public Modules ---
// These modules contain the data structures that are passed to and from the actor.

// Disable unused imports warning as the cryptography utils are used by the VSerializable macro
// but clippy can't figure that out.
#[allow(unused_imports)]
use ::cryptography::utils;

/// Contains messages and structure relevant to interacting with the Authentication Service (AS).
pub mod auth_service;
/// Contains all Public Bulletin Board entry structures.
pub mod bulletins;
/// Contains common cryptographic data structures.
pub mod cryptography;
/// Contains election data structures and ballot representations.
pub mod elections;
/// Contains all non-trustee message structures.
pub mod messages;
/// Contains the protocol participant actor implementations.
pub mod participants;
/// Contains all trustee-related implementation, including actors and message structures.
pub mod trustee_protocols;

// --- Public API Exports ---
// Re-export important types for convenient access by the library user.

pub use custom_warning_macro::warning;
pub use elections::Ballot;
