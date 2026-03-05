// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This module contains the implementations for each of the subprotocol actors.

// Declare the modules for each concrete sub-actor.
/// Voter authentication sub-actor.
pub mod authentication;
/// Ballot casting sub-actor.
pub mod casting;
/// Ballot checking sub-actor.
pub mod checking;
/// Ballot submission sub-actor.
pub mod submission;
