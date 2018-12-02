using System;

namespace SysadminsLV.Asn1Parser.Utils {
    static class ErrorCode {
        public const Int32 FileNotFoundException = unchecked((Int32)0x80070002);
        public const Int32 AccessDeniedException = unchecked((Int32)0x80070005);
        public const Int32 InvalidHandleException = unchecked((Int32)0x80070006);
        public const Int32 InvalidDataException = unchecked((Int32)0x8007000d);
        public const Int32 InvalidParameterException = unchecked((Int32)0x80070057);
        public const Int32 AlreadyInitializedException = unchecked((Int32)0x800704df);
    }
}
