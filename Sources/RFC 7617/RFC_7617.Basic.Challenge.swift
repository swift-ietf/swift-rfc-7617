public import ASCII_Serializer_Primitives
public import Binary_Serializable_Primitives
internal import INCITS_4_1986
public import Parseable_ASCII_Primitives

extension RFC_7617.Basic {

    public struct Challenge: Sendable, Codable {

        public let realm: String

        public let charset: String?

        private init(__unchecked: Void, realm: String, charset: String?) {
            self.realm = realm
            self.charset = charset
        }

        public init(realm: String, charset: String? = nil) throws(RFC_7617.Basic.Error) {

            if let charset {
                guard charset.lowercased() == "utf-8" else {
                    throw RFC_7617.Basic.Error.invalidCharset(charset)
                }
            }

            self.init(__unchecked: (), realm: realm, charset: charset)
        }
    }
}

extension RFC_7617.Basic.Challenge: ASCII.Parseable {

    public init(_ string: some StringProtocol) throws(RFC_7617.Basic.Error) {
        try self.init(ascii: [Byte](string.utf8))
    }

    public init<Bytes: Swift.Collection>(
        ascii bytes: Bytes
    ) throws(RFC_7617.Basic.Error)
    where Bytes.Element == Byte {

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

        let paramBytes = Array(byteArray.dropFirst(6))

        var realm: String?
        var charset: String?

        var start = 0
        func parseParam(_ lo: Int, _ hi: Int) {

            var a = lo
            var b = hi
            while a < b && (paramBytes[a] == ASCII.Code.space || paramBytes[a] == ASCII.Code.htab) {
                a &+= 1
            }
            while b > a
                && (paramBytes[b &- 1] == ASCII.Code.space || paramBytes[b &- 1] == ASCII.Code.htab)
            { b &-= 1 }
            guard a < b else { return }

            guard let eq = (a..<b).first(where: { paramBytes[$0] == ASCII.Code.equalsSign })
            else { return }

            let key = String(decoding: paramBytes[a..<eq], as: UTF8.self).lowercased()

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

        paramBytes.indices.forEach { idx in
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

        try self.init(realm: realmValue, charset: charset)
    }
}

extension RFC_7617.Basic.Challenge: ASCII.Serializable, Binary.Serializable {

    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == ASCII.Code {

        buffer.append(contentsOf: "Basic realm=".utf8.map { ASCII.Code(unchecked: Byte($0)) })
        buffer.append(ASCII.Code.quotationMark)

        for byte in value.realm.utf8 {
            let code = ASCII.Code(byte)
            if code == ASCII.Code.quotationMark || code == ASCII.Code.reverseSolidus {
                buffer.append(ASCII.Code.reverseSolidus)
            }
            buffer.append(code)
        }
        buffer.append(ASCII.Code.quotationMark)

        if let charset = value.charset {
            buffer.append(contentsOf: ", charset=".utf8.map { ASCII.Code(unchecked: Byte($0)) })
            buffer.append(ASCII.Code.quotationMark)
            buffer.append(contentsOf: charset.utf8.map { ASCII.Code(unchecked: Byte($0)) })
            buffer.append(ASCII.Code.quotationMark)
        }
    }

    public static func serialize<Buffer: RangeReplaceableCollection>(
        _ value: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {
        serializeBytes(value, into: &buffer)
    }

    private static func serializeBytes<Buffer: RangeReplaceableCollection>(
        _ challenge: Self,
        into buffer: inout Buffer
    ) where Buffer.Element == Byte {

        buffer.append(contentsOf: "Basic realm=".utf8)
        buffer.append(ASCII.Code.quotationMark)

        for byte in challenge.realm.utf8 {
            let code = ASCII.Code(byte)
            if code == ASCII.Code.quotationMark || code == ASCII.Code.reverseSolidus {
                buffer.append(ASCII.Code.reverseSolidus)
            }
            buffer.append(code)
        }
        buffer.append(ASCII.Code.quotationMark)

        if let charset = challenge.charset {
            buffer.append(contentsOf: ", charset=".utf8)
            buffer.append(ASCII.Code.quotationMark)
            buffer.append(contentsOf: charset.utf8)
            buffer.append(ASCII.Code.quotationMark)
        }
    }
}

extension RFC_7617.Basic.Challenge: Swift.RawRepresentable {

    public var rawValue: String {
        String(decoding: serialized.underlying, as: UTF8.self)
    }

    public init?(rawValue: String) {
        do throws(RFC_7617.Basic.Error) {
            try self.init(rawValue)
        } catch {
            return nil
        }
    }
}

extension RFC_7617.Basic.Challenge: CustomStringConvertible {

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
