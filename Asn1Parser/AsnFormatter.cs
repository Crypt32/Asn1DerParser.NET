using System;
using System.IO;

namespace SysadminsLV.Asn1Parser;

/// <summary>
/// This class contains methods to convert Base64, Hex and Binary strings to byte array and vice versa.
/// </summary>
public static class AsnFormatter {
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
        if (PemHeader.ContainsEncoding(encoding)) {
            return BinaryToStringFormatter.ToBase64(rawData, encoding, format, start, count);
        }

        return encoding switch {
            EncodingType.Base64          => BinaryToStringFormatter.ToBase64(rawData, encoding, format, start, count),
            EncodingType.Hex             => BinaryToStringFormatter.ToHex(rawData, format, start, count, forceUpperCase),
            EncodingType.HexAddress      => BinaryToStringFormatter.ToHexAddress(rawData, format, start, count, forceUpperCase),
            EncodingType.HexAscii        => BinaryToStringFormatter.ToHexAscii(rawData, format, start, count, forceUpperCase),
            EncodingType.HexAsciiAddress => BinaryToStringFormatter.ToHexAddressAndAscii(rawData, format, start, count, forceUpperCase),
            EncodingType.HexRaw          => BinaryToStringFormatter.ToHexRaw(rawData, start, count, forceUpperCase),
            _                            => throw new ArgumentException("Specified encoding is invalid.")
        };
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
        if (asn == null) {
            throw new ArgumentNullException(nameof(asn));
        }
        if (asn.PayloadLength == 0) {
            return String.Empty;
        }
        if ((Int32)encoding > 20 && (Int32)encoding < 45) {
            return BinaryToStringFormatter.ToBase64(asn.GetRawData(), encoding, format, asn.PayloadStartOffset, asn.PayloadLength);
        }
        if (PemHeader.ContainsEncoding(encoding)) {
            return BinaryToStringFormatter.ToBase64(asn.GetRawData(), encoding, format, asn.PayloadStartOffset, asn.PayloadLength);
        }

        return encoding switch {
            EncodingType.Base64          => BinaryToStringFormatter.ToBase64(asn.GetRawData(), encoding, format, asn.PayloadStartOffset, asn.PayloadLength),
            EncodingType.Hex             => BinaryToStringFormatter.ToHex(asn.GetRawData(), format, asn.PayloadStartOffset, asn.PayloadLength, forceUpperCase),
            EncodingType.HexAddress      => BinaryToStringFormatter.ToHexAddress(asn.GetRawData(), format, asn.PayloadStartOffset, asn.PayloadLength, forceUpperCase),
            EncodingType.HexAscii        => BinaryToStringFormatter.ToHexAscii(asn.GetRawData(), format, asn.PayloadStartOffset, asn.PayloadLength, forceUpperCase),
            EncodingType.HexAsciiAddress => BinaryToStringFormatter.ToHexAddressAndAscii(asn.GetRawData(), format, asn.PayloadStartOffset, asn.PayloadLength, forceUpperCase),
            EncodingType.HexRaw          => BinaryToStringFormatter.ToHexRaw(asn.GetRawData(), asn.PayloadStartOffset, asn.PayloadLength, forceUpperCase),
            _                            => throw new ArgumentException("Specified encoding is invalid.")
        };
    }
    /// <summary>
    /// Converts previously formatted string back to a byte array.
    /// </summary>
    /// <param name="input">Formatted string</param>
    /// <param name="encoding">Specifies the string encoding</param>
    /// <exception cref="ArgumentException">And invalid encoding is specified.</exception>
    /// <exception cref="InvalidDataException">The string cannot be decoded.</exception>
    /// <returns>Original byte array.</returns>
    /// <remarks>
    ///     This method may not be fully compatible with
    ///     <see cref="BinaryToString(Byte[],EncodingType,EncodingFormat,Int32,Int32,Boolean)">BinaryToString</see>
    ///     method.
    /// <para>
    ///     If encoding parameter is set to <strong>Base64Header</strong>, the method will accept any properly formatted PEM header
    ///     and footer.
    /// </para>
    /// </remarks>
    public static Byte[] StringToBinary(String input, EncodingType encoding = EncodingType.Base64) {
        Byte[] rawData;
        if (PemHeader.ContainsEncoding(encoding)) {
            var pemHeader = PemHeader.GetHeader(encoding);
            rawData = StringToBinaryFormatter.FromBase64Header(input, pemHeader.GetHeader(), pemHeader.GetFooter());
        } else {
            rawData = encoding switch {

                EncodingType.Binary    => StringToBinaryFormatter.FromBinary(input),
                EncodingType.Base64    => StringToBinaryFormatter.FromBase64(input),
                EncodingType.Base64Any => StringToBinaryFormatter.FromBase64Any(input),
                EncodingType.StringAny => StringToBinaryFormatter.FromStringAny(input),
                EncodingType.Hex
                    or EncodingType.HexRaw   => StringToBinaryFormatter.FromHex(input),
                EncodingType.HexAddress      => StringToBinaryFormatter.FromHexAddr(input),
                EncodingType.HexAscii        => StringToBinaryFormatter.FromHexAscii(input),
                EncodingType.HexAsciiAddress => StringToBinaryFormatter.FromHexAddrAscii(input),
                EncodingType.HexAny          => StringToBinaryFormatter.FromHexAny(input),
                _                 => throw new ArgumentException("Invalid encoding type is specified.")
            };
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
        Byte[] rawBytes;
        foreach (PemHeader pemHeader in PemHeader.GetPemHeaders()) {
            rawBytes = StringToBinaryFormatter.FromBase64Header(input, pemHeader.GetHeader(), pemHeader.GetFooter());
            if (rawBytes != null) {
                return pemHeader.Encoding;
            }
        }
        rawBytes = StringToBinaryFormatter.FromBase64Header(input);
        if (rawBytes != null) {
            return EncodingType.Base64Header;
        }
        rawBytes = StringToBinaryFormatter.FromBase64(input);
        if (rawBytes != null) {
            return EncodingType.Base64;
        }
        rawBytes = StringToBinaryFormatter.FromHexAddr(input);
        if (rawBytes != null) {
            return EncodingType.HexAddress;
        }
        rawBytes = StringToBinaryFormatter.FromHexAddrAscii(input);
        if (rawBytes != null) {
            return EncodingType.HexAsciiAddress;
        }
        rawBytes = StringToBinaryFormatter.FromHex(input);
        if (rawBytes != null) {
            return EncodingType.Hex;
        }
        rawBytes = StringToBinaryFormatter.FromHexAscii(input);
        return rawBytes != null ? EncodingType.HexAscii : EncodingType.Binary;
    }
}