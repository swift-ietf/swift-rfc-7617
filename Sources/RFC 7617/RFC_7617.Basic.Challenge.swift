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

// MARK: - ASCII Read

extension RFC_7617.Basic.Challenge: ASCII.Parseable {
    /// Creates a challenge by validating `string`'s UTF-8 bytes as ASCII.
    public init(_ string: some StringProtocol) throws(RFC_7617.Basic.Error) {
        try self.init(ascii: [Byte](string.utf8))
    }

    /// Parses a Basic challenge from WWW-Authenticate header value
    ///
    /// ## Category Theory
    ///
    /// Parsing transformation:
    /// - **Domain**: [Byte] (ASCII bytes of "Basic realm=...")
    /// - **Codomain**: RFC_7617.Basic.Challenge (structured challenge)
    ///
    /// ## Example
    ///
    /// ```swift
    /// let challenge = try RFC_7617.Basic.Challenge(ascii: [Byte]("Basic realm=\"WallyWorld\"".utf8))
    /// ```
    ///
    /// - Parameter bytes: WWW-Authenticate header value as ASCII bytes
    /// - Throws: `Error` if parsing fails
    public init<Bytes: Collection>(
        ascii bytes: Bytes
    ) throws(RFC_7617.Basic.Error)
    where Bytes.Element == Byte {
        // Type-up: lift to ASCII.Code at the entry boundary so the body works
        // against ASCII.Code constants directly (RFC 7617 grammar is strict ASCII;
        // non-ASCII bytes are fail-state).
        let byteArray: [ASCII.Code]
        do throws(ASCII.Code.Error) {
            byteArray = try [ASCII.Code](bytes)
        } catch {
            throw RFC_7617.Basic.Error.invalidFormat(
                String(decoding: bytes, as: UTF8.self),
                reason: "non-ASCII byte"
            )
        }
        guard !byteArray.isEmpty else { throw RFC_7617.Basic.Error.empty }

        // Must start with "Basic " (case-insensitive)
        guard byteArray.count > 6 else {
            throw RFC_7617.Basic.Error.invalidFormat(
                String(decoding: byteArray, as: UTF8.self),
                reason: "too short"
            )
        }

        let prefixBytes = Array(byteArray.prefix(5))
        let prefixLower = prefixBytes.map { $0.lowercased() }
        let basicLower: [ASCII.Code] = [.b, .a, .s, .i, .c]
        guard prefixLower == basicLower && byteArray[5] == ASCII.Code.space else {
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
            var a = lo
            var b = hi
            while a < b && (paramBytes[a] == ASCII.Code.space || paramBytes[a] == ASCII.Code.htab) {
                a &+= 1
            }
            while b > a
                && (paramBytes[b &- 1] == ASCII.Code.space || paramBytes[b &- 1] == ASCII.Code.htab)
            { b &-= 1 }
            guard a < b else { return }

            // Find '='
            var eqIdx: Int? = nil
            for j in a..<b where paramBytes[j] == ASCII.Code.equalsSign {
                eqIdx = j
                break
            }
            guard let eq = eqIdx else { return }

            let key = String(decoding: paramBytes[a..<eq], as: UTF8.self).lowercased()

            // Value — strip quotes if present
            var vlo = eq &+ 1
            var vhi = b
            if vhi > vlo && paramBytes[vlo] == ASCII.Code.quotationMark
                && paramBytes[vhi &- 1] == ASCII.Code.quotationMark
            {
                vlo &+= 1
                vhi &-= 1
            }
            let value = String(decoding: paramBytes[vlo..<vhi], as: UTF8.self)

            switch key {
            case "realm": realm = value
            case "charset": charset = value
            default: break
            }
        }

        for idx in 0..<paramBytes.count {
            if paramBytes[idx] == ASCII.Code.comma {
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

// MARK: - ASCII Serialization

extension RFC_7617.Basic.Challenge: ASCII.Serializable, Binary.Serializable {
    /// Own `ASCII.Serializable` verb ([FAM-012]) — the RFC 7617 `challenge =
    /// "Basic" SP realm [ SP "charset" "=" "UTF-8" ]` form, with the realm
    /// quoted-string escape re-expressed over `ASCII.Code` (evergreen
    /// same-format composition; no byte-detour). Output is identical to the
    /// Binary witness body (`serializeBytes`).
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == ASCII.Code {
        // "Basic realm=\""
        buffer.append(contentsOf: "Basic realm=".utf8.map { ASCII.Code(unchecked: Byte($0)) })
        buffer.append(ASCII.Code.quotationMark)

        // Escape realm value and append
        for byte in value.realm.utf8 {
            let code = ASCII.Code(byte)
            if code == ASCII.Code.quotationMark || code == ASCII.Code.reverseSolidus {
                buffer.append(ASCII.Code.reverseSolidus)
            }
            buffer.append(code)
        }
        buffer.append(ASCII.Code.quotationMark)

        // Optional charset parameter
        if let charset = value.charset {
            buffer.append(contentsOf: ", charset=".utf8.map { ASCII.Code(unchecked: Byte($0)) })
            buffer.append(ASCII.Code.quotationMark)
            buffer.append(contentsOf: charset.utf8.map { ASCII.Code(unchecked: Byte($0)) })
            buffer.append(ASCII.Code.quotationMark)
        }
    }

    /// Explicit `Binary.Serializable` witness disambiguating the two
    /// constraint-incomparable defaults.
    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        serializeBytes(value, into: &buffer)
    }

    /// Byte-domain serialization body (RFC 7617 `challenge = "Basic" SP realm
    /// [ SP "charset" "=" "UTF-8" ]`).
    private static func serializeBytes<Buffer: RangeReplaceableCollection>(
        _ challenge: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        // "Basic realm=\""
        buffer.append(contentsOf: "Basic realm=".utf8)
        buffer.append(ASCII.Code.quotationMark)

        // Escape realm value and append
        for byte in challenge.realm.utf8 {
            let code = ASCII.Code(byte)
            if code == ASCII.Code.quotationMark || code == ASCII.Code.reverseSolidus {
                buffer.append(ASCII.Code.reverseSolidus)
            }
            buffer.append(code)
        }
        buffer.append(ASCII.Code.quotationMark)

        // Optional charset parameter
        if let charset = challenge.charset {
            buffer.append(contentsOf: ", charset=".utf8)
            buffer.append(ASCII.Code.quotationMark)
            buffer.append(contentsOf: charset.utf8)
            buffer.append(ASCII.Code.quotationMark)
        }
    }
}

// MARK: - Protocol Conformances

extension RFC_7617.Basic.Challenge: Swift.RawRepresentable {
    /// The challenge's ASCII serialization as a `String` (computed; the
    /// rawValue is derived from serialization, not stored).
    public var rawValue: String {
        String(decoding: serialized.underlying, as: UTF8.self)
    }

    public init?(rawValue: String) { try? self.init(rawValue) }
}

extension RFC_7617.Basic.Challenge: CustomStringConvertible {
    /// The challenge's ASCII serialization decoded as a `String`.
    public var description: String {
        String(decoding: serialized.underlying, as: UTF8.self)
    }
}

extension RFC_7617.Basic.Challenge: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(realm)
        hasher.combine(charset?.lowercased())
    }

    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.realm == rhs.realm && lhs.charset?.lowercased() == rhs.charset?.lowercased()
    }
}
