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

extension RFC_7617.Basic {
    /// A Basic authentication challenge for WWW-Authenticate header
    ///
    /// ## ABNF Grammar (RFC 7617 Section 2)
    ///
    /// ```
    /// challenge   = "Basic" 1*SP realm [ 1*SP "charset" "=" "UTF-8" ]
    /// realm       = "realm" "=" quoted-string
    /// ```
    ///
    /// ## Parameters
    ///
    /// Per RFC 7617 Section 2:
    /// - `realm`: Required protection space identifier
    /// - `charset`: Optional, only "UTF-8" is valid (case-insensitive)
    ///
    /// ## Example
    ///
    /// ```swift
    /// let challenge = try RFC_7617.Basic.Challenge(realm: "WallyWorld")
    /// let header = String(challenge)  // "Basic realm=\"WallyWorld\""
    ///
    /// let withCharset = try RFC_7617.Basic.Challenge(realm: "foo", charset: "UTF-8")
    /// // "Basic realm=\"foo\", charset=\"UTF-8\""
    /// ```
    public struct Challenge: Sendable, Codable {
        /// The protection space identifier (required)
        public let realm: String

        /// The character encoding (optional, only "UTF-8" is valid)
        public let charset: String?

        /// Creates a Challenge WITHOUT validation
        ///
        /// Private to ensure all public construction goes through validation.
        private init(__unchecked: Void, realm: String, charset: String?) {
            self.realm = realm
            self.charset = charset
        }

        /// Creates a Basic authentication challenge with validation
        ///
        /// - Parameters:
        ///   - realm: The protection space identifier
        ///   - charset: Optional character encoding (only "UTF-8" is valid per RFC 7617)
        /// - Throws: `Error.invalidCharset` if charset is not UTF-8
        public init(realm: String, charset: String? = nil) throws(RFC_7617.Basic.Error) {
            // Per RFC 7617 Section 2.1: charset must be "UTF-8" if present (case-insensitive)
            if let charset = charset {
                guard charset.lowercased() == "utf-8" else {
                    throw RFC_7617.Basic.Error.invalidCharset(charset)
                }
            }
            self.init(__unchecked: (), realm: realm, charset: charset)
        }
    }
}

// MARK: - Binary.ASCII.Serializable

extension RFC_7617.Basic.Challenge: Binary.ASCII.Serializable {
    public static func serialize<Buffer>(
        ascii challenge: RFC_7617.Basic.Challenge,
        into buffer: inout Buffer
    ) where Buffer: RangeReplaceableCollection, Buffer.Element == UInt8 {
        // "Basic realm=\""
        buffer.append(contentsOf: "Basic realm=".utf8)
        buffer.append(UInt8.ascii.quotationMark)

        // Escape realm value and append
        for byte in challenge.realm.utf8 {
            if byte == UInt8.ascii.quotationMark || byte == UInt8.ascii.reverseSolidus {
                buffer.append(UInt8.ascii.reverseSolidus)
            }
            buffer.append(byte)
        }
        buffer.append(UInt8.ascii.quotationMark)

        // Optional charset parameter
        if let charset = challenge.charset {
            buffer.append(contentsOf: ", charset=".utf8)
            buffer.append(UInt8.ascii.quotationMark)
            buffer.append(contentsOf: charset.utf8)
            buffer.append(UInt8.ascii.quotationMark)
        }
    }

    /// Parses a Basic challenge from WWW-Authenticate header value
    ///
    /// ## Category Theory
    ///
    /// Parsing transformation:
    /// - **Domain**: [UInt8] (ASCII bytes of "Basic realm=...")
    /// - **Codomain**: RFC_7617.Basic.Challenge (structured challenge)
    ///
    /// ## Example
    ///
    /// ```swift
    /// let challenge = try RFC_7617.Basic.Challenge(ascii: "Basic realm=\"WallyWorld\"".utf8)
    /// ```
    ///
    /// - Parameter bytes: WWW-Authenticate header value as ASCII bytes
    /// - Throws: `Error` if parsing fails
    public init<Bytes: Collection>(
        ascii bytes: Bytes,
        in context: Void = ()
    ) throws(RFC_7617.Basic.Error)
    where Bytes.Element == UInt8 {
        let byteArray = Array(bytes)
        guard !byteArray.isEmpty else { throw RFC_7617.Basic.Error.empty }

        // Must start with "Basic " (case-insensitive)
        guard byteArray.count > 6 else {
            throw RFC_7617.Basic.Error.invalidFormat(
                String(decoding: byteArray, as: UTF8.self),
                reason: "too short"
            )
        }

        let prefixBytes = Array(byteArray.prefix(5))
        let prefixLower = prefixBytes.map { $0.ascii.lowercased() }
        let basicLower: [UInt8] = [0x62, 0x61, 0x73, 0x69, 0x63]  // "basic"
        guard prefixLower == basicLower && byteArray[5] == 0x20 else {
            throw RFC_7617.Basic.Error.invalidFormat(
                String(decoding: byteArray, as: UTF8.self),
                reason: "must start with 'Basic '"
            )
        }

        // Parse parameters after "Basic " at byte level
        let paramBytes = Array(byteArray.dropFirst(6))

        var realm: String?
        var charset: String?

        // Split on comma, then parse key=value
        var start = 0
        func parseParam(_ lo: Int, _ hi: Int) {
            // Trim OWS
            var a = lo, b = hi
            while a < b && (paramBytes[a] == 0x20 || paramBytes[a] == 0x09) { a &+= 1 }
            while b > a && (paramBytes[b &- 1] == 0x20 || paramBytes[b &- 1] == 0x09) { b &-= 1 }
            guard a < b else { return }

            // Find '='
            var eqIdx: Int? = nil
            for j in a..<b where paramBytes[j] == 0x3D {
                eqIdx = j
                break
            }
            guard let eq = eqIdx else { return }

            let key = String(decoding: paramBytes[a..<eq], as: UTF8.self).lowercased()

            // Value — strip quotes if present
            var vlo = eq &+ 1, vhi = b
            if vhi > vlo && paramBytes[vlo] == 0x22 && paramBytes[vhi &- 1] == 0x22 {
                vlo &+= 1; vhi &-= 1
            }
            let value = String(decoding: paramBytes[vlo..<vhi], as: UTF8.self)

            switch key {
            case "realm": realm = value
            case "charset": charset = value
            default: break
            }
        }

        for idx in 0..<paramBytes.count {
            if paramBytes[idx] == 0x2C {  // ','
                parseParam(start, idx)
                start = idx &+ 1
            }
        }
        parseParam(start, paramBytes.count)

        guard let realmValue = realm else {
            throw RFC_7617.Basic.Error.invalidFormat(
                String(decoding: byteArray, as: UTF8.self),
                reason: "realm parameter is required"
            )
        }

        // Delegate to public validating init
        try self.init(realm: realmValue, charset: charset)
    }
}

// MARK: - Protocol Conformances

extension RFC_7617.Basic.Challenge: Binary.ASCII.RawRepresentable {
    public typealias RawValue = String
}

extension RFC_7617.Basic.Challenge: CustomStringConvertible {}

extension RFC_7617.Basic.Challenge: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(realm)
        hasher.combine(charset?.lowercased())
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.realm == rhs.realm && lhs.charset?.lowercased() == rhs.charset?.lowercased()
    }
}

// MARK: - Byte Serialization

extension [UInt8] {
    /// Creates ASCII bytes from RFC_7617.Basic.Challenge
    ///
    /// ## Category Theory
    ///
    /// Natural transformation: RFC_7617.Basic.Challenge → [UInt8]
    /// ```
    /// Challenge → [UInt8] (ASCII) → String (UTF-8)
    /// ```
    public init(_ challenge: RFC_7617.Basic.Challenge) {
        self = []
        RFC_7617.Basic.Challenge.serialize(ascii: challenge, into: &self)
    }
}
