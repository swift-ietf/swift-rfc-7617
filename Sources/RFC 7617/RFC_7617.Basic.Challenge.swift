public import ASCII
public import Binary
internal import INCITS_4_1986

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
        try self.init(ascii: string.utf8.map(Byte.init(bitPattern:)))
    }

    public init<Bytes: Swift.Collection>(
        ascii bytes: Bytes
    ) throws(RFC_7617.Basic.Error)
    where Bytes.Element == Byte {

        let byteArray: [ASCII.Code]
        do throws(ASCII.Code.Error) {
            byteArray = try bytes.map { byte throws(ASCII.Code.Error) in try ASCII.Code(byte) }
        } catch {
            throw RFC_7617.Basic.Error.invalidFormat(
                String(decoding: bytes, as: UTF8.self),
                reason: "non-ASCII byte"
            )
        }
        guard !byteArray.isEmpty else { throw RFC_7617.Basic.Error.empty }

        guard byteArray.count > 6 else {
            throw RFC_7617.Basic.Error.invalidFormat(
                String(ascii: byteArray),
                reason: "too short"
            )
        }

        let prefixBytes = Array(byteArray.prefix(5))
        let prefixLower = prefixBytes.map { $0.lowercased() }
        let basicLower: [ASCII.Code] = [.b, .a, .s, .i, .c]
        guard prefixLower == basicLower && byteArray[5] == ASCII.Code.space else {
            throw RFC_7617.Basic.Error.invalidFormat(
                String(ascii: byteArray),
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

            let key = String(ascii: paramBytes[a..<eq]).lowercased()

            var vlo = eq &+ 1
            var vhi = b
            var isQuoted = false
            if vhi &- vlo >= 2 && paramBytes[vlo] == ASCII.Code.quotationMark
                && paramBytes[vhi &- 1] == ASCII.Code.quotationMark
            {
                vlo &+= 1
                vhi &-= 1
                isQuoted = true
            }
            var codes: [ASCII.Code] = []
            var escaped = false
            for code in paramBytes[vlo..<vhi] {
                if isQuoted && !escaped && code == ASCII.Code.reverseSolidus {
                    escaped = true
                } else {
                    codes.append(code)
                    escaped = false
                }
            }
            let value = String(ascii: codes[...])

            switch key {
            case "realm": realm = value
            case "charset": charset = value
            default: break
            }
        }

        var inQuotes = false
        var escaped = false
        for idx in paramBytes.indices {
            let code = paramBytes[idx]
            if escaped {
                escaped = false
            } else if inQuotes && code == ASCII.Code.reverseSolidus {
                escaped = true
            } else if code == ASCII.Code.quotationMark {
                inQuotes.toggle()
            } else if code == ASCII.Code.comma && !inQuotes {
                parseParam(start, idx)
                start = idx &+ 1
            }
        }
        parseParam(start, paramBytes.count)

        guard let realmValue = realm else {
            throw RFC_7617.Basic.Error.invalidFormat(
                String(ascii: byteArray),
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

        buffer.append(contentsOf: [Byte](utf8: "Basic realm="))
        buffer.append(ASCII.Code.quotationMark.byte)

        for byte in challenge.realm.utf8 {
            let code = ASCII.Code(byte)
            if code == ASCII.Code.quotationMark || code == ASCII.Code.reverseSolidus {
                buffer.append(ASCII.Code.reverseSolidus.byte)
            }
            buffer.append(code.byte)
        }
        buffer.append(ASCII.Code.quotationMark.byte)

        if let charset = challenge.charset {
            buffer.append(contentsOf: [Byte](utf8: ", charset="))
            buffer.append(ASCII.Code.quotationMark.byte)
            buffer.append(contentsOf: [Byte](utf8: charset))
            buffer.append(ASCII.Code.quotationMark.byte)
        }
    }
}

extension RFC_7617.Basic.Challenge: Swift.RawRepresentable {

    public var rawValue: String {
        String(decoding: serialized, as: UTF8.self)
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
        String(decoding: serialized, as: UTF8.self)
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
