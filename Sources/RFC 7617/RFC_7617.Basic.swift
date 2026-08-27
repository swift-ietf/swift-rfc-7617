public import ASCII_Serializer
public import Binary_Serializable
internal import INCITS_4_1986
public import Parseable_ASCII
internal import RFC_4648

extension RFC_7617 {

    public struct Basic: Sendable, Codable {

        public let userID: String

        public let password: String

        private init(__unchecked: Void, userID: String, password: String) {
            self.userID = userID
            self.password = password
        }

        public init(userID: String, password: String) throws(Error) {

            guard !userID.utf8.contains(0x3A) else {
                throw Error.invalidUserID(userID, reason: "user-id cannot contain colon")
            }

            self.init(__unchecked: (), userID: userID, password: password)
        }
    }
}

extension Array where Element == ASCII.ASCII.Code {

    static let basic: Self = [.B, .a, .s, .i, .c]

    static let basicLower: Self = [.b, .a, .s, .i, .c]
}

extension RFC_7617.Basic: ASCII.Parseable {

    public init(_ string: some StringProtocol) throws(Error) {
        try self.init(ascii: [Byte](string.utf8))
    }

    public init<Bytes: Swift.Collection>(
        ascii bytes: Bytes
    ) throws(Error)
    where Bytes.Element == Byte {

        guard bytes.count > 6 else {
            if bytes.isEmpty {
                throw Error.empty
            }
            throw Error.invalidFormat(String(decoding: bytes, as: UTF8.self), reason: "too short")
        }

        let asciiBytes: [ASCII.Code]
        do throws(ASCII.Code.Error) {
            asciiBytes = try [ASCII.Code](bytes)
        } catch {
            throw Error.invalidFormat(
                String(decoding: bytes, as: UTF8.self),
                reason: "non-ASCII byte"
            )
        }
        var iterator = asciiBytes.makeIterator()

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

        let base64Codes = Array(asciiBytes.dropFirst(6))
        guard !base64Codes.isEmpty else {
            throw Error.invalidFormat(
                String(decoding: bytes, as: UTF8.self),
                reason: "missing credentials"
            )
        }

        guard let decoded = RFC_4648.Base64.decode(base64Codes) else {
            throw Error.invalidEncoding(
                String(decoding: bytes, as: UTF8.self),
                reason: "invalid Base64"
            )
        }

        guard let colonIndex = decoded.firstIndex(of: 0x3A) else {
            throw Error.invalidFormat(
                String(decoding: decoded, as: UTF8.self),
                reason: "credentials must contain colon separator"
            )
        }

        let userID = String(decoding: decoded[..<colonIndex], as: UTF8.self)
        let password = String(decoding: decoded[decoded.index(after: colonIndex)...], as: UTF8.self)

        try self.init(userID: userID, password: password)
    }
}

extension RFC_7617.Basic: ASCII.Serializable, Binary.Serializable {

    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == ASCII.Code {

        buffer.append(contentsOf: [ASCII.Code].basic)
        buffer.append(ASCII.Code.space)

        let userPass = "\(value.userID):\(value.password)"
        let base64 = RFC_4648.Base64.encode([Byte](userPass.utf8))
        buffer.append(contentsOf: base64)
    }

    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        serializeBytes(value, into: &buffer)
    }

    private static func serializeBytes<Buffer: RangeReplaceableCollection>(
        _ credentials: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {

        buffer.append(contentsOf: [ASCII.Code].basic)
        buffer.append(ASCII.Code.space)

        let userPass = "\(credentials.userID):\(credentials.password)"
        let base64 = RFC_4648.Base64.encode([Byte](userPass.utf8))
        buffer.append(contentsOf: base64)
    }
}

extension RFC_7617.Basic {

    public func authorizationHeaderValue() -> String {
        String(decoding: serialized.underlying, as: UTF8.self)
    }
}

extension RFC_7617.Basic: Swift.RawRepresentable {

    public var rawValue: String {
        String(decoding: serialized.underlying, as: UTF8.self)
    }

    public init?(rawValue: String) {
        do throws(Error) {
            try self.init(rawValue)
        } catch {
            return nil
        }
    }
}

extension RFC_7617.Basic: CustomStringConvertible {

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
