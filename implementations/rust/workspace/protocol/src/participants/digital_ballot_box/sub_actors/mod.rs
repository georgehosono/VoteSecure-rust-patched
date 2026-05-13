// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! Sub-actor implementations for the Digital Ballot Box.
//!
//! Each sub-actor handles one type of protocol interaction:
//! - `submission` - Ballot submission protocol
//! - `casting` - Ballot casting protocol
//! - `checking` - Ballot checking protocol (forwarding between BCA and VA)

/// Ballot casting sub-actor.
pub mod casting;
/// Ballot checking sub-actor.
pub mod checking;
/// Ballot submission sub-actor.
pub mod submission;
