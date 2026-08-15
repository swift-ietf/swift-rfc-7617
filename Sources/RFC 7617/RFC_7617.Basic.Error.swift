// ===----------------------------------------------------------------------===//
//
// This source file is part of the swift-rfc-7617 open source project
//
// Copyright (c) 2025 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

extension RFC_7617.Basic {
    /// Errors that can occur during Basic authentication operations
    ///
    /// ## Error Cases
    ///
    /// - `empty`: Input was empty
    /// - `invalidUserID`: User-ID contains invalid characters (colon)
    /// - `invalidFormat`: Format doesn't match RFC 7617 specification
    /// - `invalidEncoding`: Base64 encoding/decoding failed
    /// - `invalidCharset`: Charset parameter is not UTF-8
    public enum Error: Swift.Error, Sendable, Equatable {
        /// Input was empty
        case empty

        /// User-ID contains invalid characters
        ///
        /// Per RFC 7617 Section 2, user-id cannot contain colon character.
        case invalidUserID(_ value: String, reason: String)

        /// Format doesn't match RFC 7617 specification
        ///
        /// This includes missing "Basic " prefix, missing colon separator, etc.
        case invalidFormat(_ value: String, reason: String)

        /// Base64 encoding or decoding failed
        case invalidEncoding(_ value: String, reason: String)

        /// Charset parameter is not UTF-8
        ///
        /// Per RFC 7617 Section 2.1, only "UTF-8" is allowed.
        case invalidCharset(_ value: String)
    }
}

extension RFC_7617.Basic.Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .empty:
            return "Input cannot be empty"

        case .invalidUserID(let value, let reason):
            return "Invalid user-id '\(value)': \(reason)"

        case .invalidFormat(let value, let reason):
            return "Invalid format '\(value)': \(reason)"

        case .invalidEncoding(let value, let reason):
            return "Invalid encoding '\(value)': \(reason)"

        case .invalidCharset(let value):
            return "Invalid charset '\(value)': only UTF-8 is supported"
        }
    }
}
