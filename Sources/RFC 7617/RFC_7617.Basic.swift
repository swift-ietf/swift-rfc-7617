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
public import Binary_Serializable_Primitives
internal import INCITS_4_1986
public import Parseable_ASCII_Primitives
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

extension Array where Element == ASCII_Primitives.ASCII.Code {
    /// "Basic" prefix bytes (mixed case as commonly serialized)
    static let basic: Self = [.B, .a, .s, .i, .c]

    /// "basic" lowercase prefix bytes (for case-insensitive comparison)
    static let basicLower: Self = [.b, .a, .s, .i, .c]
}

// MARK: - ASCII Read

extension RFC_7617.Basic: ASCII.Parseable {
    /// Creates Basic credentials by validating `string`'s UTF-8 bytes as ASCII.
    public init(_ string: some StringProtocol) throws(Error) {
        try self.init(ascii: [Byte](string.utf8))
    }

    /// Parses Basic credentials from Authorization header value
    ///
    /// ## Category Theory
    ///
    /// Parsing transformation:
    /// - **Domain**: [Byte] (ASCII bytes of "Basic <base64>")
    /// - **Codomain**: RFC_7617.Basic (structured credentials)
    ///
    /// Minimizes allocations via single-pass validation and slice-based parsing:
    /// ```
    /// [Byte] ─validate─→ Slice ─decode─→ [UInt8] ─split─→ (String, String)
    /// ```
    ///
    /// ## Example
    ///
    /// ```swift
    /// let credentials = try RFC_7617.Basic(ascii: [Byte]("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==".utf8))
    /// ```
    ///
    /// - Parameter bytes: Authorization header value as ASCII bytes
    /// - Throws: `Error` if parsing fails
    public init<Bytes: Collection>(
        ascii bytes: Bytes
    ) throws(Error)
    where Bytes.Element == Byte {
        // Validate minimum length without allocation: "Basic " (6) + at least 1 base64 char
        guard bytes.count > 6 else {
            if bytes.isEmpty {
                throw Error.empty
            }
            throw Error.invalidFormat(String(decoding: bytes, as: UTF8.self), reason: "too short")
        }

        // Type-up: lift to ASCII.Code at the entry boundary so the body works
        // against ASCII.Code constants directly (RFC 7617 grammar is strict ASCII;
        // non-ASCII bytes are fail-state).
        let asciiBytes: [ASCII.Code]
        do {
            asciiBytes = try [ASCII.Code](bytes)
        } catch {
            throw Error.invalidFormat(
                String(decoding: bytes, as: UTF8.self),
                reason: "non-ASCII byte"
            )
        }
        var iterator = asciiBytes.makeIterator()

        // Check "Basic " prefix case-insensitively (inline comparison, no arrays)
        guard let b0 = iterator.next(), b0.lowercased() == ASCII.Code.b,
            let b1 = iterator.next(), b1.lowercased() == ASCII.Code.a,
            let b2 = iterator.next(), b2.lowercased() == ASCII.Code.s,
            let b3 = iterator.next(), b3.lowercased() == ASCII.Code.i,
            let b4 = iterator.next(), b4.lowercased() == ASCII.Code.c,
            let b5 = iterator.next(), b5 == ASCII.Code.space
        else {
            throw Error.invalidFormat(
                String(decoding: bytes, as: UTF8.self),
                reason: "must start with 'Basic '"
            )
        }

        // Extract Base64 portion as [ASCII.Code] (rfc-4648 decode consumes ASCII codes)
        let base64Codes = Array(asciiBytes.dropFirst(6))
        guard !base64Codes.isEmpty else {
            throw Error.invalidFormat(
                String(decoding: bytes, as: UTF8.self),
                reason: "missing credentials"
            )
        }

        // Decode Base64 (rfc-4648: [ASCII.Code] -> [Byte]?)
        guard let decoded = RFC_4648.Base64.decode(base64Codes) else {
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

// MARK: - ASCII Serialization

extension RFC_7617.Basic: ASCII.Serializable, Binary.Serializable {
    /// Own `ASCII.Serializable` verb ([FAM-012]) — the RFC 7617 `"Basic" SP
    /// token68` Authorization credentials form. The Base64 leaf
    /// (`RFC_4648.Base64.encode`) already yields `[ASCII.Code]`, so it composes
    /// directly into the `ASCII.Code` buffer (evergreen same-format composition;
    /// no byte-detour). Output is identical to the Binary witness body
    /// (`serializeBytes`).
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == ASCII.Code {
        // "Basic "
        buffer.append(contentsOf: [ASCII.Code].basic)  // "Basic"
        buffer.append(ASCII.Code.space)  // " "

        // Base64 encode user-id:password (RFC 4648: [Byte] -> [ASCII.Code])
        let userPass = "\(value.userID):\(value.password)"
        let base64 = RFC_4648.Base64.encode([Byte](userPass.utf8))
        buffer.append(contentsOf: base64)
    }

    /// Explicit `Binary.Serializable` witness disambiguating the two
    /// constraint-incomparable defaults.
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        serializeBytes(value, into: &buffer)
    }

    /// Byte-domain serialization body (RFC 7617 `"Basic" SP token68`).
    private static func serializeBytes<Buffer: RangeReplaceableCollection>(
        _ credentials: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // "Basic "
        buffer.append(contentsOf: [ASCII.Code].basic)  // "Basic"
        buffer.append(ASCII.Code.space)  // " "

        // Base64 encode user-id:password (RFC 4648: [Byte] -> [ASCII.Code])
        let userPass = "\(credentials.userID):\(credentials.password)"
        let base64 = RFC_4648.Base64.encode([Byte](userPass.utf8))
        buffer.append(contentsOf: base64)
    }
}

// MARK: - Protocol Conformances

extension RFC_7617.Basic: Swift.RawRepresentable {
    /// The credentials' ASCII serialization as a `String` (computed; the
    /// rawValue is derived from serialization, not stored).
    public var rawValue: String {
        String(decoding: serialized.underlying, as: UTF8.self)
    }

    public init?(rawValue: String) { try? self.init(rawValue) }
}

extension RFC_7617.Basic: CustomStringConvertible {
    /// The credentials' ASCII serialization decoded as a `String`.
    public var description: String {
        String(decoding: serialized.underlying, as: UTF8.self)
    }
}

extension RFC_7617.Basic: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(userID)
        hasher.combine(password)
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.userID == rhs.userID && lhs.password == rhs.password
    }
}
