public import Parser

extension RFC_7617.Basic {

    public struct Parse<Input: Collection.Slice.`Protocol`>: Sendable
    where Input: Sendable, Input.Element == UInt8 {
        @inlinable
        public init() {}
    }
}

extension RFC_7617.Basic.Parse {
    public typealias Error = __RFC_7617_Basic_Parse_Error
}

extension RFC_7617.Basic.Parse: Parser.`Protocol` {
    public typealias Failure = __RFC_7617_Basic_Parse_Error
    public typealias Body = Never

    @inlinable
    public func parse(_ input: inout Input) throws(Failure) -> Output {

        var idx = input.startIndex
        guard idx < input.endIndex else { throw .expectedBasicPrefix }

        guard input[idx] == 0x42 || input[idx] == 0x62 else { throw .expectedBasicPrefix }
        input.formIndex(after: &idx)
        guard idx < input.endIndex else { throw .expectedBasicPrefix }

        guard input[idx] == 0x61 || input[idx] == 0x41 else { throw .expectedBasicPrefix }
        input.formIndex(after: &idx)
        guard idx < input.endIndex else { throw .expectedBasicPrefix }

        guard input[idx] == 0x73 || input[idx] == 0x53 else { throw .expectedBasicPrefix }
        input.formIndex(after: &idx)
        guard idx < input.endIndex else { throw .expectedBasicPrefix }

        guard input[idx] == 0x69 || input[idx] == 0x49 else { throw .expectedBasicPrefix }
        input.formIndex(after: &idx)
        guard idx < input.endIndex else { throw .expectedBasicPrefix }

        guard input[idx] == 0x63 || input[idx] == 0x43 else { throw .expectedBasicPrefix }
        input.formIndex(after: &idx)

        guard idx < input.endIndex, input[idx] == 0x20 else { throw .expectedSpace }

        while idx < input.endIndex && input[idx] == 0x20 {
            input.formIndex(after: &idx)
        }

        let tokenStart = idx
        while idx < input.endIndex {
            let byte = input[idx]
            guard Self._isToken68Char(byte) else { break }
            input.formIndex(after: &idx)
        }

        while idx < input.endIndex && input[idx] == 0x3D {
            input.formIndex(after: &idx)
        }

        guard idx > tokenStart else { throw .emptyToken }

        let token68 = input[tokenStart..<idx]
        input = input[idx...]
        return Output(token68: token68)
    }

    @inlinable
    package static func _isToken68Char(_ byte: UInt8) -> Bool {
        return switch byte {
        case 0x41...0x5A: true
        case 0x61...0x7A: true
        case 0x30...0x39: true
        case 0x2D: true
        case 0x2E: true
        case 0x5F: true
        case 0x7E: true
        case 0x2B: true
        case 0x2F: true
        default: false
        }
    }
}
