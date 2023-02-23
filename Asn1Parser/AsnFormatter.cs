using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SysadminsLV.Asn1Parser {
    /// <summary>
    /// This class contains methods to convert Base64, Hex and Binary strings to byte array and vice versa.
    /// </summary>
    public static class AsnFormatter {
        static readonly Char[] _delimiters = { ' ', '-', ':', '\t', '\n', '\r' };

        /// <summary>
        /// Converts and formats byte array to a string. See <see cref="EncodingType"/> for encoding examples.
        /// </summary>
        /// <param name="rawData">Byte array to format.</param>
        /// <param name="encoding">Specifies the encoding for formatting. Default is <strong>HexRaw</strong></param>
        /// <param name="format">
        /// 	Specifies the encoding options. The default behavior is to use a carriage return/line feed
        /// 	(CR/LF) pair (0x0D/0x0A) to represent a new line.
        /// </param>
        /// <param name="start">Specifies the start position of the byte array to format. Default is zero.</param>
        /// <param name="count">Specifies how many bytes must be formatted. If zero, entire byte array will be encoded.</param>
        /// <param name="forceUpperCase">
        /// Specifies whether the force hex octet representation in upper case. Default is lower case.
        /// <para>
        /// This parameter has effect only when hex encoding is selected in the <strong>encoding</strong> parameter:
        /// <strong>Hex</strong>, <strong>HexRaw</strong>, <strong>HexAddress</strong>, <strong>HexAscii</strong>
        /// and <strong>HexAsciiAddress</strong>. For other values, this parameter is silently ignored.
        /// </para>
        /// </param>
        /// <exception cref="ArgumentException">An invalid encoding type was specified.</exception>
        /// <returns>Encoded and formatted string.</returns>
        /// <remarks>
        /// This method do not support the following encoding types:
        /// <list type="bullet">
        /// <item><description>Binary</description></item>
        /// <item><description>Base64Any</description></item>
        /// <item><description>StringAny</description></item>
        /// <item><description>HexAny</description></item>
        /// </list>
        /// </remarks>
        public static String BinaryToString(Byte[] rawData, EncodingType encoding = EncodingType.HexRaw, EncodingFormat format = EncodingFormat.CRLF, Int32 start = 0, Int32 count = 0, Boolean forceUpperCase = false) {
            if (rawData == null || rawData.Length == 0) {
                return String.Empty;
            }
            switch (encoding) {
                case EncodingType.Base64:
                case EncodingType.Base64Header:
                case EncodingType.Base64CrlHeader:
                case EncodingType.Base64RequestHeader:
                    return BinaryToStringFormatter.ToBase64(rawData, encoding, format, start, count);
                case EncodingType.Hex:
                    return BinaryToStringFormatter.ToHex(rawData, format, start, count, forceUpperCase);
                case EncodingType.HexAddress:
                    return BinaryToStringFormatter.ToHexAddress(rawData, format, start, count, forceUpperCase);
                case EncodingType.HexAscii:
                    return BinaryToStringFormatter.ToHexAscii(rawData, format, start, count, forceUpperCase);
                case EncodingType.HexAsciiAddress:
                    return BinaryToStringFormatter.ToHexAddressAndAscii(rawData, format, start, count, forceUpperCase);
                case EncodingType.HexRaw:
                    return BinaryToStringFormatter.ToHexRaw(rawData, start, count, forceUpperCase);
                default:
                    throw new ArgumentException("Specified encoding is invalid.");
            }
        }
        /// <summary>
        /// Converts and formats current position af the <see cref="Asn1Reader"/> object.
        /// </summary>
        /// <param name="asn"><see cref="Asn1Reader"/> object in the desired state.</param>
        /// <param name="encoding">Specifies the encoding for formatting. Default is <strong>HexRaw</strong></param>
        /// <param name="format">
        ///		Specifies the encoding options. The default behavior is to use a carriage return/line feed
        ///		(CR/LF) pair (0x0D/0x0A) to represent a new line.
        /// </param>
        /// <param name="forceUpperCase">
        /// Specifies whether the force hex octet representation in upper case. Default is lower case.
        ///  <para>
        /// This parameter has effect only when hex encoding is selected in the <strong>encoding</strong> parameter:
        /// <strong>Hex</strong>, <strong>HexRaw</strong>, <strong>HexAddress</strong>, <strong>HexAscii</strong>
        /// and <strong>HexAsciiAddress</strong>. For other values, this parameter is silently ignored.
        ///  </para>
        ///  </param>
        /// <exception cref="ArgumentException">An invalid encoding type was specified.</exception>
        /// <returns>Encoded and formatted string.</returns>
        /// <remarks>
        /// This method do not support the following encoding types:
        /// <list type="bullet">
        /// <item><description>Binary</description></item>
        /// <item><description>Base64Any</description></item>
        /// <item><description>StringAny</description></item>
        /// <item><description>HexAny</description></item>
        /// </list>
        /// </remarks>
        public static String BinaryToString(Asn1Reader asn, EncodingType encoding = EncodingType.HexRaw, EncodingFormat format = EncodingFormat.CRLF, Boolean forceUpperCase = false) {
            if (asn == null) { throw new ArgumentNullException(nameof(asn)); }
            if (asn.PayloadLength == 0) { return String.Empty; }
            switch (encoding) {
                case EncodingType.Base64:
                case EncodingType.Base64Header:
                case EncodingType.Base64CrlHeader:
                case EncodingType.Base64RequestHeader:
                    return BinaryToStringFormatter.ToBase64(asn.GetRawData(), encoding, format, asn.PayloadStartOffset, asn.PayloadLength);
                case EncodingType.Hex:
                    return BinaryToStringFormatter.ToHex(asn.GetRawData(), format, asn.PayloadStartOffset, asn.PayloadLength, forceUpperCase);
                case EncodingType.HexAddress:
                    return BinaryToStringFormatter.ToHexAddress(asn.GetRawData(), format, asn.PayloadStartOffset, asn.PayloadLength, forceUpperCase);
                case EncodingType.HexAscii:
                    return BinaryToStringFormatter.ToHexAscii(asn.GetRawData(), format, asn.PayloadStartOffset, asn.PayloadLength, forceUpperCase);
                case EncodingType.HexAsciiAddress:
                    return BinaryToStringFormatter.ToHexAddressAndAscii(asn.GetRawData(), format, asn.PayloadStartOffset, asn.PayloadLength, forceUpperCase);
                case EncodingType.HexRaw:
                    return BinaryToStringFormatter.ToHexRaw(asn.GetRawData(), asn.PayloadStartOffset, asn.PayloadLength, forceUpperCase);
                default:
                    throw new ArgumentException("Specified encoding is invalid.");
            }
        }
        /// <summary>
        /// Converts previously formatted string back to a byte array.
        /// </summary>
        /// <param name="input">Formatted string</param>
        /// <param name="encoding">Specifies the string encoding</param>
        /// <exception cref="ArgumentException">And invalid encoding is specified.</exception>
        /// <exception cref="InvalidDataException">The string cannot be decoded.</exception>
        /// <returns>Original byte array.</returns>
        /// <remarks>This method may not be fully compatible with
        /// <see cref="BinaryToString(Byte[],EncodingType,EncodingFormat,Int32,Int32,Boolean)">BinaryToString</see>
        /// method.
        /// </remarks>
        public static Byte[] StringToBinary(String input, EncodingType encoding = EncodingType.Base64) {
            Byte[] rawData;
            switch (encoding) {
                case EncodingType.Binary: rawData = fromBinary(input); break;
                case EncodingType.Base64: rawData = fromBase64(input); break;
                case EncodingType.Base64Header: rawData = fromBase64Header(input); break;
                case EncodingType.Base64CrlHeader: rawData = fromBase64Crl(input); break;
                case EncodingType.Base64RequestHeader: rawData = fromBase64Request(input); break;
                case EncodingType.Base64Any: rawData = fromBase64Any(input); break;
                case EncodingType.StringAny: rawData = fromStringAny(input); break;
                case EncodingType.Hex:
                case EncodingType.HexRaw: rawData = fromHex(input); break;
                case EncodingType.HexAddress: rawData = fromHexAddr(input); break;
                case EncodingType.HexAscii: rawData = fromHexAscii(input); break;
                case EncodingType.HexAsciiAddress: rawData = fromHexAddrAscii(input); break;
                case EncodingType.HexAny: rawData = fromHexAny(input); break;
                default:
                    throw new ArgumentException("Invalid encoding type is specified.");
            }
            if (rawData == null) {
                throw new InvalidDataException("The data is invalid.");
            }
            return rawData;
        }
        /// <summary>
        /// Attempts to determine input string format.
        /// </summary>
        /// <param name="input">Formatted string to process.</param>
        /// <returns>
        /// Resolved input string format. If format cannot be determined, <string>Binary</string> type is returned.
        /// </returns>
        public static EncodingType TestInputString(String input) {
            Byte[] rawBytes = fromBase64Crl(input);
            if (rawBytes != null) {
                return EncodingType.Base64CrlHeader;
            }
            rawBytes = fromBase64Request(input);
            if (rawBytes != null) {
                return EncodingType.Base64RequestHeader;
            }
            rawBytes = fromBase64Header(input);
            if (rawBytes != null) {
                return EncodingType.Base64Header;
            }
            rawBytes = fromBase64(input);
            if (rawBytes != null) {
                return EncodingType.Base64;
            }
            rawBytes = fromHexAddr(input);
            if (rawBytes != null) {
                return EncodingType.HexAddress;
            }
            rawBytes = fromHexAddrAscii(input);
            if (rawBytes != null) {
                return EncodingType.HexAsciiAddress;
            }
            rawBytes = fromHex(input);
            if (rawBytes != null) {
                return EncodingType.Hex;
            }
            rawBytes = fromHexAscii(input);
            return rawBytes != null ? EncodingType.HexAscii : EncodingType.Binary;
        }

        

        static Byte[] fromBase64(String input) {
            try {
                return Convert.FromBase64String(input.Trim());
            } catch {
                return null;
            }
        }
        // accept any header, not only certificate
        static Byte[] fromBase64Header(String input) {
            const String header = "-----BEGIN ";
            const String footer = "-----END ";
            if (!input.ToUpper().Contains(header) || !input.Contains(footer)) {
                return null;
            }
            Int32 start = input.IndexOf(header, StringComparison.Ordinal) + 10;
            Int32 headerEndPos = input.IndexOf("-----", start, StringComparison.Ordinal) + 5;
            Int32 footerStartPos = input.IndexOf(footer, StringComparison.Ordinal);
            try {
                return Convert.FromBase64String(input.Substring(headerEndPos, footerStartPos - headerEndPos));
            } catch {
                return null;
            }
        }
        static Byte[] fromBase64Crl(String input) {
            String header = PemHeaders.GetCrlHeader();
            String footer = PemHeaders.GetCrlFooter();
            if (!input.ToUpper().Contains(header) || !input.Contains(footer)) {
                return null;
            }
            Int32 start = input.IndexOf(header, StringComparison.Ordinal) + 10;
            Int32 headerEndPos = input.IndexOf("-----", start, StringComparison.Ordinal) + 5;
            Int32 footerStartPos = input.IndexOf(footer, StringComparison.Ordinal);
            try {
                return Convert.FromBase64String(input.Substring(headerEndPos, footerStartPos - headerEndPos));
            } catch {
                return null;
            }
        }
        static Byte[] fromBase64Request(String input) {
            String header;
            String footer;
            if (input.ToUpper().Contains(PemHeaders.GetCertReqNewHeader())) {
                header = PemHeaders.GetCertReqNewHeader();
                footer = PemHeaders.GetCertReqNewFooter();
            } else if (input.ToUpper().Contains(PemHeaders.GetCertReqHeader())) {
                header = PemHeaders.GetCertReqHeader();
                footer = PemHeaders.GetCertReqFooter();
            } else {
                return null;
            }
            Int32 start = input.IndexOf(header, StringComparison.Ordinal) + 10;
            Int32 headerEndPos = input.IndexOf("-----", start, StringComparison.Ordinal) + 5;
            Int32 footerStartPos = input.IndexOf(footer, StringComparison.Ordinal);
            try {
                return Convert.FromBase64String(input.Substring(headerEndPos, footerStartPos - headerEndPos));
            } catch {
                return null;
            }
        }
        static Byte[] fromBinary(String input) {
            Byte[] rawBytes = new Byte[input.Length];
            for (Int32 i = 0; i < input.Length; i++) {
                try {
                    rawBytes[i] = (Byte)input[i];
                } catch { return null; }
            }
            return rawBytes;
        }
        // the same decoder for Hex and HexRaw
        /* Rules:
         * 1) hex octet must be paired with hex chars, e.g. 0f, 08, not 8, f.
         * 2) each octet is separated by one or more delimiter chars
         */
        static Byte[] fromHex(String input) {
            var bytes = new List<Byte>(input.Length / 2);
            for (Int32 i = 0; i < input.Length; i++) {
                if (testHexChar(input[i])) {
                    if (i + 1 == input.Length || !testHexChar(input[i + 1])) {
                        return null;
                    }
                    bytes.Add((Byte)(hexCharToByte(input[i]) << 4 | hexCharToByte(input[i + 1])));
                    i++;
                } else if (!testDelimiter(input[i])) {
                    return null;
                }
            }
            return bytes.ToArray();
        }
        /* Rules:
         * 1) same rules as for 'fromHex' method
         * 2) address field must be 4, 6 or 8 chars only. Must contain only hex chars
         * 3) address can follow and followed by one or more delimiter chars.
         * 4) next address field may appear only when 16 octets are calculated in previous line.
         * 5) address field may be the only field in the line.
         */
        static Byte[] fromHexAddr(String input) {
            Byte octetCount = 0;
            Boolean addressReached = false;
            var bytes = new List<Byte>(input.Length / 3);
            for (Int32 i = 0; i < input.Length; i++) {
                if (octetCount == 0 && !addressReached) {
                    // attempt to resolve if address octet is reached
                    if (testHexChar(input[i])) {
                        Int32 remaining = input.Length - i - 1;
                        Boolean eof = false;
                        if (remaining >= 8) {
                            remaining = 8;
                        } else {
                            // last line and we may expect only address field without any hex data
                            eof = true;
                        }
                        if (i + 4 < input.Length) {
                            Int32 addrEndIndex = input.IndexOfAny(_delimiters, i, remaining);
                            // if there are no valid whitespace within 8 chars, invalidate string
                            if (addrEndIndex < 0) {
                                // we reached end of file and there is address field without hex bytes
                                if (eof) {
                                    i = i + remaining;
                                    continue;
                                }
                                return null;
                            }
                            for (Int32 n = i; n < addrEndIndex; n++) {
                                // invalidate string if address field do not contain valid hex char
                                if (!testHexChar(input[n])) {
                                    return null;
                                }
                            }
                            // if we reached so far, move pointer to first whitespace char after address field
                            i = addrEndIndex;
                            addressReached = true;
                        }
                    } else if (!testWhitespaceLimited(input[i])) {
                        // invalidate the string if address field do not contain hex or limited whitespace char
                        return null;
                    }
                } if (octetCount == 16) {
                    // allow only ' ', '\t' and '\r'  Wait for '\n' and reset octet count.
                    if (input[i] == '\n') {
                        octetCount = 0;
                        addressReached = false;
                    } else if (!testWhitespaceLimited(input[i])) {
                        return null;
                    }
                } else {
                    if (testHexChar(input[i]) && i + 1 < input.Length && testHexChar(input[i + 1])) {
                        bytes.Add((Byte)(hexCharToByte(input[i]) << 4 | hexCharToByte(input[i + 1])));
                        // octet pair must be followed by delimiter.
                        if (i + 2 < input.Length) {
                            if (!testDelimiter(input[i + 2])) { return null; }
                        }
                        octetCount++;
                        i++;
                    } else if (!testDelimiter(input[i])) {
                        return null;
                    }
                }
            }
            return bytes.ToArray();
        }
        /* Rules:
         * 1) if line is full (16 octets) loop until first non whitespace character. Once reached, start ascii decoding
         * 2) before and after ascii only whitespace chars are allowed. EOL = true
         * 3) ascii must not contain symbols <32 or >126
         * 4) new line appears after first \n char. EOL = false
         * 5) if read octet count less than three (3) and hex is followed by hex char -- invalidate the string
         * 6) if hex is followed by non-whitespace char, start ascii decoding
         * 7) if line is not complete, but faced non-delimiter char, consider this as a start of ascii and start decoding
         * 8) only whitespace chars are allowed after required number of ascii chars. EOF=true.
         * 9) invalidate string if any non-whitespace occured after EOF.
         * 10) ascii char count must be less or equals to octetCount
         */
        static Byte[] fromHexAscii(String input) {
            Byte octetCount = 0;
            Boolean asciiReached = false;
            String ascii = String.Empty;
            var bytes = new List<Byte>(input.Length / 3);
            for (Int32 i = 0; i < input.Length; i++) {
                // do not allow more hex octets after full line. Treat them as ascii characters.
                if (octetCount == 16) {
                    // rule 1
                    if (asciiReached) {
                        if (input[i] >= 32 && input[i] < 127) {
                            ascii += input[i];
                            // rule 10
                            if (ascii.TrimEnd().Length > octetCount) {
                                return null;
                            }
                        } else if (input[i] == '\n') {
                            asciiReached = false;
                            ascii = String.Empty;
                            octetCount = 0;
                        } else if (!testWhitespace(input[i])) {
                            return null;
                        }
                    } else {
                        if (!testWhitespace(input[i])) {
                            ascii += input[i];
                            asciiReached = true;
                        }
                    }
                } else {
                    if (asciiReached) {
                        if (input[i] >= 32 && input[i] < 127) {
                            ascii += input[i];
                            // rule 10
                            if (ascii.TrimEnd(_delimiters).Length > octetCount) {
                                return null;
                            }
                        } else if (!testWhitespace(input[i])) {
                            // rule 9
                            return null;
                        }
                    } else if (testHexChar(input[i]) && i + 1 < input.Length && testHexChar(input[i + 1])) {
                        bytes.Add((Byte)(hexCharToByte(input[i]) << 4 | hexCharToByte(input[i + 1])));
                        octetCount++;
                        i++;
                        if (i + 1 < input.Length) {
                            // rule 5
                            if (octetCount < 3 && testHexChar(input[i + 1])) {
                                return null;
                            }
                            // rule 6
                            if (!testDelimiter(input[i + 1])) {
                                asciiReached = true;
                            }
                        }
                    } else if (!testDelimiter(input[i])) {
                        asciiReached = true;
                    }
                }
            }
            return bytes.ToArray();
        }
        /* Rules:
         * same for 'fromHexAddr' and 'fromHexAddrAscii'
         */
        static Byte[] fromHexAddrAscii(String input) {
            Byte octetCount = 0;
            Boolean addressReached = false, asciiReached = false;
            String ascii = String.Empty;
            var bytes = new List<Byte>(input.Length / 3);
            for (Int32 i = 0; i < input.Length; i++) {
                if (octetCount == 0 && !addressReached) {
                    // attempt to resolve if address octet is reached
                    if (testHexChar(input[i])) {
                        Int32 remaining = input.Length - i - 1;
                        Boolean eof = false;
                        if (remaining >= 8) {
                            remaining = 8;
                        } else {
                            // last line and we may expect only address field without any hex data
                            eof = true;
                        }
                        if (i + 4 < input.Length) {
                            Int32 addrEndIndex = input.IndexOfAny(_delimiters, i, remaining);
                            // if there are no valid whitespace within 8 chars, invalidate string
                            if (addrEndIndex < 0) {
                                // we reached end of file and there is address field without hex bytes
                                if (eof) {
                                    i = i + remaining;
                                    continue;
                                }
                                return null;
                            }
                            for (Int32 n = i; n < addrEndIndex; n++) {
                                // invalidate string if address field do not contain valid hex char
                                if (!testHexChar(input[n])) {
                                    return null;
                                }
                            }
                            // if we reached so far, move pointer to first whitespace char after address field
                            i = addrEndIndex;
                            addressReached = true;
                        }
                    } else if (!testWhitespaceLimited(input[i])) {
                        // invalidate the string if address field do not contain hex or limited whitespace char
                        return null;
                    }
                } else if (octetCount == 16) {
                    if (asciiReached) {
                        if (input[i] >= 32 && input[i] < 127) {
                            ascii += input[i];
                            // rule 10
                            if (ascii.TrimEnd().Length > octetCount) { return null; }
                        } else if (input[i] == '\n') {
                            asciiReached = false;
                            addressReached = false;
                            ascii = String.Empty;
                            octetCount = 0;
                        } else if (!testWhitespace(input[i])) {
                            return null;
                        }
                    } else {
                        if (!testWhitespace(input[i])) {
                            ascii += input[i];
                            asciiReached = true;
                        }
                    }
                } else {
                    if (asciiReached) {
                        if (input[i] >= 32 && input[i] < 127) {
                            ascii += input[i];
                            // rule 10
                            if (ascii.TrimEnd(_delimiters).Length > octetCount) { return null; }
                        } else if (!testWhitespace(input[i])) {
                            // rule 9
                            return null;
                        }
                    } else if (testHexChar(input[i]) && i + 1 < input.Length && testHexChar(input[i + 1])) {
                        bytes.Add((Byte)(hexCharToByte(input[i]) << 4 | hexCharToByte(input[i + 1])));
                        octetCount++;
                        i++;
                        if (i + 1 < input.Length) {
                            // rule 5
                            if (octetCount < 3 && testHexChar(input[i + 1])) {
                                return null;
                            }
                            // rule 6
                            if (!testDelimiter(input[i + 1])) {
                                asciiReached = true;
                            }
                        }
                    } else if (!testDelimiter(input[i])) {
                        asciiReached = true;
                    }
                }
            }
            return bytes.ToArray();
        }

        static Byte[] fromBase64Any(String input) {
            return fromBase64Header(input) ?? fromBase64(input);
        }
        static Byte[] fromStringAny(String input) {
            return fromBase64Header(input) ?? fromBase64(input) ?? input.Select(Convert.ToByte).ToArray();
        }
        static Byte[] fromHexAny(String input) {
            return fromHexAddr(input) ??
                fromHexAddrAscii(input) ??
                fromHex(input) ??
                fromHexAscii(input);
        }

        // unchecked.
        static Byte hexCharToByte(Char c) {
            return c >= '0' && c <= '9'
                ? (Byte) (c - '0')
                : (c >= 'a' && c <= 'f'
                    ? (Byte) (c - 'a' + 10)
                    : (Byte) (c - 'A' + 10));
        }

        
        static Boolean testWhitespace(Char c) {
            return c == ' '  ||
                   c == '\t' ||
                   c == '\r' ||
                   c == '\n';
        }
        static Boolean testWhitespaceLimited(Char c) {
            return c == ' '  ||
                   c == '\t' ||
                   c == '\r';
        }
        static Boolean testDelimiter(Char c) {
            return c == ' '  ||
                   c == '-'  ||
                   c == ':'  ||
                   c == '\t' ||
                   c == '\n' ||
                   c == '\r';
        }
        static Boolean testHexChar(Char c) {
            // valid chars: 0-9, A-F, a-f
            return (c >= '0' && c <= '9') ||
                   (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F');
        }
    }
}
