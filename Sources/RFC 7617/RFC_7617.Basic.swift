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

public import ASCII_Serializer_Primitives
public import INCITS_4_1986
internal import RFC_4648

extension RFC_7617 {
    /// HTTP Basic Authentication credentials per RFC 7617
    ///
    /// ## ABNF Grammar (RFC 7617 Section 2)
    ///
    /// ```
    /// credentials = "Basic" 1*SP token68
    /// token68     = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
    /// ```
    ///
    /// The token68 is Base64-encoded user-pass:
    ///
    /// ```
    /// user-pass   = user-id ":" password
    /// user-id     = *( %x00-39 / %x3B-FF )  ; any char except ":"
    /// password    = *TEXT
    /// ```
    ///
    /// ## Constraints
    ///
    /// Per RFC 7617 Section 2:
    /// - user-id MUST NOT contain a colon character
    /// - Both user-id and password are encoded using UTF-8 (when charset=UTF-8)
    ///
    /// ## Example
    ///
    /// ```swift
    /// let credentials = try RFC_7617.Basic(userID: "Aladdin", password: "open sesame")
    /// let header = String(credentials)  // "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    /// ```
    public struct Basic: Sendable, Codable {
        /// The user identifier (cannot contain colon)
        public let userID: String

        /// The password
        public let password: String

        /// Creates Basic credentials WITHOUT validation
        ///
        /// Private to ensure all public construction goes through validation.
        private init(__unchecked: Void, userID: String, password: String) {
            self.userID = userID
            self.password = password
        }

        /// Creates Basic authentication credentials with validation
        ///
        /// - Parameters:
        ///   - userID: The user identifier (cannot contain colon)
        ///   - password: The password
        /// - Throws: `Error.invalidUserID` if userID contains colon
        public init(userID: String, password: String) throws(Error) {
            // Per RFC 7617 Section 2: user-id = *( %x00-39 / %x3B-FF )
            // This means any octet except 0x3A which is ":"
            guard !userID.utf8.contains(0x3A) else {
                throw Error.invalidUserID(userID, reason: "user-id cannot contain colon")
            }
            self.init(__unchecked: (), userID: userID, password: password)
        }
    }
}

extension [UInt8] {
    /// "Basic" prefix bytes (mixed case as commonly serialized)
    static let basic: Self = [.ascii.B, .ascii.a, .ascii.s, .ascii.i, .ascii.c]

    /// "basic" lowercase prefix bytes (for case-insensitive comparison)
    static let basicLower: Self = [.ascii.b, .ascii.a, .ascii.s, .ascii.i, .ascii.c]
}

// MARK: - Binary.ASCII.Serializable

extension RFC_7617.Basic: Binary.ASCII.Serializable {
    public static func serialize<Buffer>(
        ascii credentials: RFC_7617.Basic,
        into buffer: inout Buffer
    ) where Buffer: RangeReplaceableCollection, Buffer.Element == UInt8 {
        // "Basic "
        buffer.append(contentsOf: [UInt8].basic)  // "Basic "
        buffer.append(.ascii.space)  // "Basic "

        // Base64 encode user-id:password (RFC 4648)
        let userPass = "\(credentials.userID):\(credentials.password)"
        let base64 = RFC_4648.Base64.encode(Array(userPass.utf8))
        buffer.append(contentsOf: base64)
    }

    /// Parses Basic credentials from Authorization header value
    ///
    /// ## Category Theory
    ///
    /// Parsing transformation:
    /// - **Domain**: [UInt8] (ASCII bytes of "Basic <base64>")
    /// - **Codomain**: RFC_7617.Basic (structured credentials)
    ///
    /// Minimizes allocations via single-pass validation and slice-based parsing:
    /// ```
    /// [UInt8] ─validate─→ Slice ─decode─→ [UInt8] ─split─→ (String, String)
    /// ```
    ///
    /// ## Example
    ///
    /// ```swift
    /// let credentials = try RFC_7617.Basic(ascii: "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==".utf8)
    /// ```
    ///
    /// - Parameter bytes: Authorization header value as ASCII bytes
    /// - Throws: `Error` if parsing fails
    public init<Bytes: Collection>(
        ascii bytes: Bytes,
        in context: Void = ()
    ) throws(Error)
    where Bytes.Element == UInt8 {
        // Validate minimum length without allocation: "Basic " (6) + at least 1 base64 char
        guard bytes.count > 6 else {
            if bytes.isEmpty {
                throw Error.empty
            }
            throw Error.invalidFormat(String(decoding: bytes, as: UTF8.self), reason: "too short")
        }

        // Single-pass prefix validation using iterator (no allocation)
        var iterator = bytes.makeIterator()

        // Check "Basic " prefix case-insensitively (inline comparison, no arrays)
        guard let b0 = iterator.next(), b0.ascii.lowercased() == .ascii.b,
            let b1 = iterator.next(), b1.ascii.lowercased() == .ascii.a,
            let b2 = iterator.next(), b2.ascii.lowercased() == .ascii.s,
            let b3 = iterator.next(), b3.ascii.lowercased() == .ascii.i,
            let b4 = iterator.next(), b4.ascii.lowercased() == .ascii.c,
            let b5 = iterator.next(), b5 == .ascii.space
        else {
            throw Error.invalidFormat(
                String(decoding: bytes, as: UTF8.self),
                reason: "must start with 'Basic '"
            )
        }

        // Extract Base64 portion as slice (no allocation)
        let base64Bytes = bytes.dropFirst(6)
        guard !base64Bytes.isEmpty else {
            throw Error.invalidFormat(
                String(decoding: bytes, as: UTF8.self),
                reason: "missing credentials"
            )
        }

        // Decode Base64 directly from bytes (single allocation for decoded output)
        guard let decoded = RFC_4648.Base64.decode(base64Bytes) else {
            throw Error.invalidEncoding(
                String(decoding: bytes, as: UTF8.self),
                reason: "invalid Base64"
            )
        }

        // Find first colon separator (0x3A = ':')
        guard let colonIndex = decoded.firstIndex(of: 0x3A) else {
            throw Error.invalidFormat(
                String(decoding: decoded, as: UTF8.self),
                reason: "credentials must contain colon separator"
            )
        }

        // Create final strings directly from slices (2 unavoidable allocations)
        let userID = String(decoding: decoded[..<colonIndex], as: UTF8.self)
        let password = String(decoding: decoded[decoded.index(after: colonIndex)...], as: UTF8.self)

        // Delegate to public validating init
        try self.init(userID: userID, password: password)
    }
}

// MARK: - Protocol Conformances

extension RFC_7617.Basic: Binary.ASCII.RawRepresentable {
    public typealias RawValue = String
}

extension RFC_7617.Basic: CustomStringConvertible {}

extension RFC_7617.Basic: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(userID)
        hasher.combine(password)
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.userID == rhs.userID && lhs.password == rhs.password
    }
}
