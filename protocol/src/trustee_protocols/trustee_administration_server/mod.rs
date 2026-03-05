// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This module contains the implementation for the Trustee Administration Server.

/// Internal TAS state handlers and dispatch wrappers.
pub(crate) mod handlers;
/// Top-level Trustee Administration Server actor and public API.
pub mod top_level_actor;
