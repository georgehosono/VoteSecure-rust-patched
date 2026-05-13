// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Free & Fair
// See LICENSE.md for details

//! This module includes messages and functions pertaining to interacting
//! with the Authentication Service (AS).

use crate::cryptography::VerifyingKey;
use crate::elections::ElectionHash;

/// Authentication session record.
#[derive(Debug, Clone)]
pub struct AuthSessionRecord {
    /// Hash of the unique election configuration item.
    pub election_hash: ElectionHash,

    /// Public key from the initial request message.
    pub voter_verifying_key: VerifyingKey,

    /// Token from the token-return message.
    pub token: String,

    /// Session identifier from the token-return message.
    pub session_id: String,
}

/// Initiate authentication request message.
#[derive(Debug, Clone)]
pub struct InitAuthReqMsg {
    /// Identifier used by the external authentication service to select
    /// the verification flow for created authentication sessions.
    pub project_id: String,

    /// Authentication-service API key used by the EAS.
    pub api_key: String,
}

/// Token return message.
#[derive(Debug, Clone)]
pub struct TokenReturnMsg {
    /// Token used by the client to start an authentication session.
    pub token: String,

    /// Session identifier used by the server to query authentication
    /// session information tied to the associated token.
    pub session_id: String,
}

/// Authentication Service query message.
#[derive(Debug, Clone)]
pub struct AuthServiceQueryMsg {
    /// Session ID retrieved from EAS storage for the voter session.
    pub session_id: String,

    /// Authentication-service API key used by the EAS.
    pub api_key: String,
}

/// Authentication Service report message.
///
/// The protocol spec gives a tentative JSON format, but the exact payload
/// depends on the Authentication Service provider. Biographical data is
/// therefore represented as an opaque `String`.
#[derive(Debug, Clone)]
pub struct AuthServiceReportMsg {
    /// Token associated with the authentication session.
    pub token: String,

    /// Session ID used in the authentication-service query.
    pub session_id: String,

    /// Biographical information associated with the authenticated voter.
    ///
    /// May be [`None`] if [`AuthServiceReportMsg::authenticated`] is `false`.
    pub biographical_info: Option<String>,

    /// Whether the user successfully authenticated.
    pub authenticated: bool,
}

/// Enumeration of possible Authentication Service messages.
#[derive(Debug, Clone)]
pub enum AuthServiceMsg {
    /// Initiate an authentication request.
    InitAuthReq(InitAuthReqMsg),
    /// Return an authentication token and session ID.
    TokenReturn(TokenReturnMsg),
    /// Query status of an authentication session.
    AuthServiceQuery(AuthServiceQueryMsg),
    /// Report authentication status and optional biographical data.
    AuthServiceReport(AuthServiceReportMsg),
}
