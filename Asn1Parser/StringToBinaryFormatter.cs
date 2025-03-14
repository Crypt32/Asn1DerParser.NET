using System;
using System.Collections.Generic;

namespace SysadminsLV.Asn1Parser;
static class StringToBinaryFormatter {
    static readonly Char[] _delimiters = [' ', '-', ':', '\t', '\n', '\r'];

    /// <summary>
    /// Converts the specified string, which encodes binary data as base-64 digits, to
    /// an equivalent 8-bit unsigned integer array.
    /// </summary>
    /// <param name="input">The string to convert.</param>
    /// <returns>An array of 8-bit unsigned integers that is equivalent to <strong>input</strong>.</returns>
    public static Byte[]? FromBase64(String input) {
        try {
            return Convert.FromBase64String(input.Trim());
        } catch {
            return null;
        }
    }

    /// <summary>
    /// Attempts to convert the specified string, which encodes binary data as base-64 digits with PEM header and footer,
    /// to an equivalent 8-bit unsigned integer array.
    /// </summary>
    /// <param name="input">The string to convert.</param>
    /// <param name="headerName">
    ///     Specifies the header name. This parameter MUS NOT include 5-dash sequence and BEGIN/END constants.
    ///     This parameter is ignored if <strong>skipHeaderValidation</strong> parameter is set to <c>true</c>.
    /// </param>
    /// <param name="skipHeaderValidation">
    ///     Skips strict PEM header and footer check. By default, this method checks for exact PEM header and footer
    ///     specified in <strong>header</strong> parameter, which includes only name, without fixed (5-dash sequences,
    ///     BEGIN and END constants).
    ///     <para>
    ///     When this parameter is set to <c>true</c>, then <strong>headerName</strong> parameter is ignored and method will
    ///     attempt to find any properly PEM formatted header and footer, even if PEM header and footer names don't match.
    ///     For example, the following sequence would also be considered valid:
    ///     <code>
    /// -----BEGIN CERTIFICATE-----
    /// MIIDBjCCAm8CAQAwcTERMA8GA1UEAxMIcXV1eC5jb20xDzANBgNVBAsTBkJyYWlu
    /// czEWMBQGA1UEChMNRGV2ZWxvcE1lbnRvcjERMA8GA1UEBxMIVG9ycmFuY2UxEzAR
    /// BgNVBAgTCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVTMIGfMA0GCSqGSIb3DQEBAQUA
    /// &lt;...&gt;
    /// -----END X509 CRL-----
    ///     </code>
    ///     </para>
    /// </param>
    /// <returns>An array of 8-bit unsigned integers that is equivalent to input, or <c>null</c> if no valid PEM header was found.</returns>
    public static Byte[]? FromBase64Header(String input, String headerName, Boolean skipHeaderValidation = false) {
        String header, footer;
        if (skipHeaderValidation) {
            header = "-----BEGIN ";
            footer = "-----END ";
        } else {
            header = $"-----BEGIN {headerName.Trim()}-----";
            footer = $"-----END {headerName.Trim()}-----";
        }
        // search for header (uppercase) start position
        Int32 start = input.IndexOf(header, StringComparison.Ordinal);
        if (start < 0) {
            // if we don't find header, then it is not valid PEM header. End here.
            return null;
        }
        Int32 headerEndPos = skipHeaderValidation
            // 10 is the length of mandatory '-----BEGIN' header part. Seek after mandatory part and look where
            // terminating 5-dash sequence begins and append the length of 5-dash. This is the end of header and
            // where body begins.
            ? input.IndexOf("-----", start + 10, StringComparison.Ordinal) + 5
            : start + header.Length;
        // search for footer starting with  header end position. Empty 
        Int32 footerStartPos = input.IndexOf(footer, headerEndPos, StringComparison.Ordinal);
        if (footerStartPos < 0) {
            // we found PEM header, but no PEM footer, or the order is wrong (footer defined before header)
            return null;
        }
        
        try {
            return Convert.FromBase64String(input.Substring(headerEndPos, footerStartPos - headerEndPos));
        } catch {
            return null;
        }
    }
    /// <summary>
    /// Attempts to convert input string into a 8bit byte array. This method converts each character of input
    /// string to its 8bit numerical representation.
    /// </summary>
    /// <param name="input">String to convert.</param>
    /// <returns>Decoded byte array. This method returns <c>null</c> if input string contains non-8bit characters.</returns>
    public static Byte[]? FromBinary(String input) {
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
    public static Byte[]? FromHex(String input) {
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
    public static Byte[]? FromHexAddr(String input) {
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
                                i += remaining;
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
            }
            if (octetCount == 16) {
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
    public static Byte[]? FromHexAscii(String input) {
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
    public static Byte[]? FromHexAddrAscii(String input) {
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

    /// <summary>
    /// Attempts to convert the specified string, which encodes binary data as base64 digits with
    /// or without PEM header and footer, to an equivalent 8-bit unsigned integer array.
    /// </summary>
    /// <param name="input">Base64 formatted string with optional PEM header and footer.</param>
    /// <returns>
    ///     An array of 8-bit unsigned integers that is equivalent to input, or <c>null</c> if input string doesn't represent
    ///     valid Base64 or PEM formatted string.
    /// </returns>
    public static Byte[]? FromBase64Any(String input) {
        if (input.Contains("-----BEGIN ")) {
            // if input string contains PEM begin sequence, then try only Base64 with header and footer
            // without strict validation.
            return FromBase64Header(input, String.Empty, true);
        }
        // if there is no PEM found, then try raw base64.
        return FromBase64(input);
    }
    public static Byte[] FromStringAny(String input) {
        if (input.Contains("-----BEGIN ")) {
            return FromBase64Header(input, String.Empty, true);
        }
        return FromBase64(input) ?? FromBinary(input);
    }
    public static Byte[]? FromHexAny(String input) {
        return FromHexAddr(input) ??
            FromHexAddrAscii(input) ??
            FromHex(input) ??
            FromHexAscii(input);
    }

    // unchecked.
    static Byte hexCharToByte(Char c) {
        return c switch {
            >= '0' and <= '9' => (Byte)(c - '0'),
            >= 'a' and <= 'f' => (Byte)(c - 'a' + 10),
            _ => (Byte)(c - 'A' + 10)
        };
    }

    
    static Boolean testWhitespace(Char c) {
        return c is ' ' or '\t' or '\r' or '\n';
    }
    static Boolean testWhitespaceLimited(Char c) {
        return c is ' ' or '\t' or '\r';
    }
    static Boolean testDelimiter(Char c) {
        return c is ' ' or '-' or ':' or '\t' or '\n' or '\r';
    }
    static Boolean testHexChar(Char c) {
        // valid chars: 0-9, A-F, a-f
        return c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
    }
}
