using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.Asn1Parser {
    /// <summary>
    /// Contains utility methods for ASN.1 data.
    /// </summary>
    public static class Asn1Utils {
        #region ASN.1 helper methods
        /// <summary>
        /// Generates tag length header for specified size.
        /// </summary>
        /// <param name="payloadLength">A projected tag length.</param>
        /// <returns>Encoded tag length header. Return value do not contain tag and payload.</returns>
        public static Byte[] GetLengthBytes(Int32 payloadLength) {
            if (payloadLength < 128) {
                return new[] { (Byte)payloadLength };
            }
            Byte[] lenBytes = new Byte[4];
            Int32 num = payloadLength;
            Int32 counter = 0;
            while (num >= 256) {
                lenBytes[counter] = (Byte)(num & 255);
                num >>= 8;
                counter++;
            }
            // 3 is: len byte and enclosing tag
            Byte[] retValue = new Byte[2 + counter];
            retValue[0] = (Byte)(129 + counter);
            retValue[1] = (Byte)num;
            Int32 n = 2;
            for (Int32 i = counter - 1; i >= 0; i--) {
                retValue[n] = lenBytes[i];
                n++;
            }
            return retValue;
        }
        /// <summary>
        /// Calculates the ASN.1 payload length from a given ASN.1 length header.
        /// </summary>
        /// <param name="asnHeader">A byte array that represents ASN.1 length header</param>
        /// <exception cref="ArgumentNullException">
        /// <strong>asnHeader</strong> parameter is null.
        /// </exception>
        /// <exception cref="OverflowException">
        /// <strong>asnHeader</strong> parameter length is more than 4 bytes or is invalid value.
        /// </exception>
        /// <returns>ASN.1 payload length in bytes.</returns>
        public static Int64 CalculatePayloadLength(Byte[] asnHeader) {
            if (asnHeader == null) { throw new ArgumentNullException(nameof(asnHeader)); }
            if (asnHeader.Length == 0) { return 0; }
            if (asnHeader[0] < 127) { return asnHeader[0]; }
            Int32 lengthBytes = asnHeader[0] - 128;
            // max length can be encoded by using 4 bytes.
            if (lengthBytes > 4 || asnHeader.Length < 1 + lengthBytes) {
                throw new OverflowException("Data length is too large or too small.");
            }
            Int64 payloadLength = asnHeader[1];
            for (Int32 i = 2; i < asnHeader.Length; i++) {
                payloadLength = (payloadLength << 8) | asnHeader[i];
            }
            return payloadLength;
        }
        /// <summary>
        /// Wraps encoded data to an ASN.1 type/structure.
        /// </summary>
        /// <remarks>This method do not check whether the data in <strong>rawData</strong> is valid data for specified enclosing type.</remarks>
        /// <param name="rawData">A byte array to wrap.</param>
        /// <param name="enclosingTag">An enumeration of <see cref="Asn1Type"/>.</param>
        /// <returns>Wrapped encoded byte array.</returns>
        /// <remarks>If <strong>rawData</strong> is null, an empty tag is encoded.</remarks>
        public static Byte[] Encode(Byte[] rawData, Byte enclosingTag) {
            if (rawData == null) {
                return new Byte[] { enclosingTag, 0 };
            }
            Byte[] retValue;
            if (rawData.Length < 128) {
                retValue = new Byte[rawData.Length + 2];
                retValue[0] = enclosingTag;
                retValue[1] = (Byte)rawData.Length;
                rawData.CopyTo(retValue, 2);
            } else {
                Byte[] lenBytes = new Byte[4];
                Int32 num = rawData.Length;
                Int32 counter = 0;
                while (num >= 256) {
                    lenBytes[counter] = (Byte)(num & 255);
                    num >>= 8;
                    counter++;
                }
                // 3 is: len byte and enclosing tag
                retValue = new Byte[rawData.Length + 3 + counter];
                rawData.CopyTo(retValue, 3 + counter);
                retValue[0] = enclosingTag;
                retValue[1] = (Byte)(129 + counter);
                retValue[2] = (Byte)num;
                Int32 n = 3;
                for (Int32 i = counter - 1; i >= 0; i--) {
                    retValue[n] = lenBytes[i];
                    n++;
                }
            }
            return retValue;
        }
        #endregion
        #region Static methods
        /// <summary>
        /// Decodes a ASN.1-encoded INTEGER to a unsigned 64-bit integer.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="InvalidDataException">The data is not valid ASN.1-encoded integer.</exception>
        /// <exception cref="OverflowException">
        /// The input data exceeds 8 bytes (max bytes that can be allocated for 64-bit integer).
        /// In order to decode large integers, use <see cref="DecodeInteger(Byte[], Boolean)"/> overloaded method.
        /// </exception>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <returns>Unsigned 64-bit integer.</returns>
        public static Int64 DecodeInteger(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            var asn = new Asn1Reader(rawData);
            if (asn.Tag != (Byte)Asn1Type.INTEGER) {
                throw new InvalidDataException("Input data is not valid ASN.1-encoded INTEGER.");
            }
            if (asn.GetPayload().Length > 8) { throw new OverflowException(); }
            var dummyPayload = new List<Byte>(asn.GetPayload());
            if (asn.GetPayload()[0] >= 128) {
                while (dummyPayload.Count < 8) {
                    dummyPayload.Insert(0, 255);
                }
            }
            var SB = new StringBuilder();
            foreach (Byte item in dummyPayload) {
                SB.Append($"{item:x2}");
            }
            return Int64.Parse(SB.ToString(), NumberStyles.AllowHexSpecifier);
        }
        /// <summary>
        /// Decodes a ASN.1-encoded INTEGER to a hex string that represents ASN.1-encoded integer. This method accepts large integers.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <param name="allowLarge">
        ///		Specifies whether to allow large integers. If this parameter is set to <strong>True</strong>, method
        ///		returns integer in a hexadecimal form. If this parameter is set to <strong>False</strong>, method
        ///		attempts to convert encoded integer to an <see cref="UInt32"/> numerical value. Numerical value is
        ///		returned as a string.
        /// </param>
        /// <exception cref="InvalidDataException">The data is not valid ASN.1-encoded integer.</exception>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <returns>A hex string that represents large integer.</returns>
        public static String DecodeInteger(Byte[] rawData, Boolean allowLarge) {
            if (rawData == null) { throw new ArgumentNullException(); }
            var asn = new Asn1Reader(rawData);
            if (asn.Tag != (Byte)Asn1Type.INTEGER) {
                throw new InvalidDataException("Input data is not valid ASN.1-encoded INTEGER.");
            }
            var SB = new StringBuilder();
            foreach (Byte item in asn.GetPayload()) { SB.AppendFormat("{0:x2}", item); }
            return allowLarge
                ? SB.ToString()
                : DecodeInteger(rawData).ToString(CultureInfo.InvariantCulture);
        }
        /// <summary>
        /// Decodes <strong>OCTET_STRING</strong> as a sequence of hexadecimal octets.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded <strong>OCTET_STRING</strong>.</param>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <exception cref="InvalidDataException">The data is not valid ASN.1-encoded octet string.</exception>
        /// <returns>A sequence of hexadecimal octets.</returns>
        public static String DecodeOctetString(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            var asn = new Asn1Reader(rawData);
            if (asn.Tag != (Byte)Asn1Type.OCTET_STRING) {
                throw new InvalidDataException("Input data is not valid OCTET_STRING.");
            }
            var SB = new StringBuilder();
            foreach (Byte item in asn.GetPayload()) {
                SB.Append($"{item:x2}" + " ");
            }
            return SB.ToString();
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="time"></param>
        /// <param name="usePrecise"></param>
        /// <returns></returns>
        internal static Byte[] EncodeUTCTime(DateTime time, Boolean usePrecise) {
            return EncodeUTCTime(time, null, usePrecise);
        }
        /// <summary>
        /// Encodes a .NET DateTime object to a AN1.1-encoded byte array.
        /// </summary>
        /// <param name="time">An instance of <see cref="DateTime"/> object.</param>
        /// <param name="zone">
        ///		Specifies the time zone for the value in <strong>time</strong> parameter.
        /// </param>
        /// <returns>ASN.1-encoded byte array.</returns>
        /// <remarks>
        ///		If <strong>zone</strong> parameter is set to <strong>NULL</strong>, date and time in <strong>time</strong>
        ///		parameter will be converted to a Zulu time (Universal time). If zone information is not <strong>NULL</strong>,
        ///		date and time in <strong>time</strong> parameter will be converted to a GMT time and time zone will be added
        ///		to encoded value.
        /// </remarks>
        internal static Byte[] EncodeUTCTime(DateTime time, TimeZoneInfo zone) {
            return EncodeUTCTime(time, zone, false);
        }
        internal static Byte[] EncodeUTCTime(DateTime time, TimeZoneInfo zone = null, Boolean usePrecise = false) {
            return new Asn1UtcTime(time, zone, usePrecise).RawData;
        }
        /// <summary>
        /// Encodes a .NET DateTime object to a AN1.1-encoded byte array.
        /// </summary>
        /// <param name="time">An instance of <see cref="DateTime"/> object.</param>
        /// <param name="zone">
        ///		Specifies the time zone for the value in <strong>time</strong> parameter.
        /// </param>
        /// <returns>ASN.1-encoded byte array.</returns>
        /// <remarks>
        ///		If <strong>zone</strong> parameter is set to <strong>NULL</strong>, date and time in <strong>time</strong>
        ///		parameter will be converted to a Zulu time (Universal time). If zone information is not <strong>NULL</strong>,
        ///		date and time in <strong>time</strong> parameter will be converted to a GMT time and time zone will be added
        ///		to encoded value.
        /// </remarks>
        public static Byte[] EncodeGeneralizedTime(DateTime time, TimeZoneInfo zone = null) {
            return (new Asn1GeneralizedTime(time, zone)).RawData;
        }
        /// <summary>
        /// Decodes ASN.1-encoded GeneralizedTime structure to a .NET <see cref="DateTime"/> object. Returned time is automatically converted to a local time
        /// (by identifying current zone's information).
        /// </summary>
        /// <param name="rawData">Byte array to decode.</param>
        /// <exception cref="InvalidDataException">Input data is not correct ASN-encoded Generalized Time.</exception>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <returns>Decoded DateTime object.</returns>
        public static DateTime DecodeGeneralizedTime(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            Asn1Reader asn = new Asn1Reader(rawData);
            if (asn.Tag != (Byte)Asn1Type.GeneralizedTime) {
                throw new InvalidDataException("Input data is not valid ASN-encoded GENERALIZED TIME.");
            }
            return (new Asn1GeneralizedTime(asn)).Value;
        }
        /// <summary>
        /// Encodes an instance of <see cref="Oid"/> class to a ASN.1-encoded byte array that represents <strong>OBJECT IDENTIFIER</strong> type.
        /// </summary>
        /// <param name="oid">An instance of <see cref="Oid"/> class.</param>
        /// <exception cref="ArgumentNullException"><strong>oid</strong> parameter is null reference.</exception>
        /// <exception cref="ArgumentException">The object identifier is not initialized.</exception>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] EncodeObjectIdentifier(Oid oid) {
            if (oid == null) { throw new ArgumentNullException(); }
            if (String.IsNullOrEmpty(oid.Value)) { throw new ArgumentException("oid"); }
            return CryptoConfig.EncodeOID(oid.Value);
        }
        /// <summary>
        /// Decodes ASN.1-encoded object identifier to an instance of generic <see cref="Oid"/> class.
        /// </summary>
        /// <param name="rawData">Byte array to decode.</param>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <exception cref="InvalidDataException">The data is not properly encoded Object Identifier.</exception>
        /// <returns>An instance of <see cref="Oid"/> class contained decoded object identifier.</returns>
        public static Oid DecodeObjectIdentifier(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            try {
                Byte[] raw = Encode(rawData, 48);
                AsnEncodedData asnencoded = new AsnEncodedData(raw);
                X509EnhancedKeyUsageExtension eku = new X509EnhancedKeyUsageExtension(asnencoded, false);
                return eku.EnhancedKeyUsages[0];
            } catch { throw new InvalidDataException("Input data is not valid ASN-encoded Oid."); }
        }
        /// <summary>
        /// Encodes an instance of <see cref="Boolean"/> class to a ASN.1-encoded byte array that represents <strong>BOOLEAN</strong> type.
        /// </summary>
        /// <param name="str">The value to encode. Can be either <strong>True</strong> or <strong>False</strong>.</param>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] EncodeBoolean(Boolean str) {
            Byte[] rawData = { 1, 1, 0 };
            if (str) { rawData[2] = 255; }
            return rawData;
        }
        /// <summary>
        /// Decodes ASN.1-encoded <strong>BOOLEAN</strong> type to a generic .NET Boolean value.
        /// </summary>
        /// <param name="rawData">Byte array to decode.</param>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <exception cref="ArgumentException">Boolean type cannot be determined.</exception>
        /// <exception cref="InvalidDataException">The input data is not properly encoded Boolean.</exception>
        /// <returns>An instance of <see cref="Boolean"/> class.</returns>
        public static Boolean DecodeBoolean(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            if (rawData.Length == 3 && rawData[0] == 1 && rawData[1] == 1) {
                switch (rawData[2]) {
                    case 0:
                        return false;
                    case 0xff:
                        return true;
                    default:
                        throw new ArgumentException("Boolean value cannot be recognized.");
                }
            }
            throw new InvalidDataException("Input data is not valid ASN-encoded Boolean.");
        }
        /// <summary>
        /// Decodes ASN.1-encoded <strong>UTF-8</strong> string to it's textual representation.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded UTF-8 string.</param>
        /// <exception cref="InvalidDataException">The input data is not properly encoded UTF8String.</exception>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <returns>Decoded string.</returns>
        public static String DecodeUTF8String(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            var asn = new Asn1Reader(rawData);
            if (asn.Tag != (Byte)Asn1Type.UTF8String) { throw new InvalidDataException(); }
            return Encoding.UTF8.GetString(asn.GetPayload());
        }
        /// <summary>
        /// Encodes a <strong>UTF-8</strong> string to a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="inputString">UTF-8 string to encode.</param>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] EncodeUTF8String(String inputString) {
            return Encode(Encoding.UTF8.GetBytes(inputString), (Byte)Asn1Type.UTF8String);
        }
        /// <summary>
        /// Decodes <strong>IA5String</strong> (also known as ANSI) to it's textual representation.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded IA5 string.</param>
        /// <exception cref="InvalidDataException">The input data is not properly encoded IA5String.</exception>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <returns>Decoded string.</returns>
        public static String DecodeIA5String(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            var asn = new Asn1Reader(rawData);
            if (asn.GetPayload().Any(@by => @by > 127)) {
                throw new ArgumentException("The data is invalid.");
            }
            if (asn.Tag == (Byte)Asn1Type.IA5String) {
                return Encoding.ASCII.GetString(asn.GetPayload());
            }
            throw new InvalidDataException();
        }
        /// <summary>
        /// Encodes IA5 string to a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="inputString">IA5 (ANSI) string to encode.</param>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] EncodeIA5String(String inputString) {
            var chars = inputString.ToCharArray();
            if (chars.Any(ch => ch > 127)) {
                throw new InvalidDataException();
            }
            return Encode(Encoding.ASCII.GetBytes(inputString), (Byte)Asn1Type.IA5String);
        }
        /// <summary>
        /// Decodes <strong>PrintableString</strong> to it's textual representation.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded PrintableString.</param>
        /// <exception cref="InvalidDataException">The input data is not properly encoded PrintableString.</exception>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <returns>Decoded string.</returns>
        public static String DecodePrintableString(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            return (new Asn1PrintableString(rawData)).Value;
        }
        /// <summary>
        /// Encodes Printable String to a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="inputString">Printable String string to encode.</param>
        /// <exception cref="InvalidDataException">The string contains invalid character or characters
        /// and cannot be encoded to a Printable String.
        /// </exception>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] EncodePrintableString(String inputString) {
            return (new Asn1PrintableString(inputString)).RawData;
        }
        /// <summary>
        /// Decodes <strong>TeletexString</strong> to it's textual representation.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded TeletexString.</param>
        /// <exception cref="InvalidDataException">The input data is not properly encoded TeletexString.</exception>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <returns>Decoded string.</returns>
        public static String DecodeTeletexString(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            var asn = new Asn1Reader(rawData);
            if (asn.GetPayload().Any(@by => @by > 127)) {
                throw new ArgumentException("The data is invalid.");
            }
            if (asn.Tag == (Byte)Asn1Type.TeletexString) {
                return Encoding.ASCII.GetString(asn.GetPayload());
            }
            throw new InvalidDataException();
        }
        /// <summary>
        /// Encodes string to a ASN.1-encoded byte array that represents TeletexString.
        /// </summary>
        /// <param name="inputString">String to encode.</param>
        /// <exception cref="InvalidDataException">The string contains invalid character or characters
        /// and cannot be encoded to a TeletexString.
        /// </exception>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] EncodeTeletexString(String inputString) {
            if (inputString.ToCharArray().Any(ch => ch > 127)) {
                throw new InvalidDataException();
            }
            return Encode(Encoding.ASCII.GetBytes(inputString), (Byte)Asn1Type.TeletexString);
        }
        /// <summary>
        /// Decodes <strong>VisibleString</strong> to it's textual representation.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded VisibleString string.</param>
        /// <exception cref="InvalidDataException">The input data is not properly encoded VisibleString.</exception>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <returns>Decoded string.</returns>
        public static String DecodeVisibleString(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            var asn = new Asn1Reader(rawData);
            if (asn.GetPayload().Any(b => b < 32 || b > 126)) {
                throw new InvalidDataException();
            }
            if (asn.Tag == (Byte)Asn1Type.VisibleString) {
                return Encoding.ASCII.GetString(asn.GetPayload());
            }
            throw new InvalidDataException();
        }
        /// <summary>
        /// Encodes visible string to a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="inputString">VisibleString string to encode.</param>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] EncodeVisibleString(String inputString) {
            Char[] chars = inputString.ToCharArray();
            if (chars.Any(ch => ch < 32 || ch > 126)) {
                throw new InvalidDataException();
            }
            return Encode(Encoding.ASCII.GetBytes(inputString), (Byte)Asn1Type.VisibleString);
        }
        /// <summary>
        /// Decodes <strong>BMPString</strong> (UTF-16) to it's textual representation.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded BMP string.</param>
        /// <exception cref="InvalidDataException">The input data is not properly encoded BMPString.</exception>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <returns>Decoded string.</returns>
        public static String DecodeBMPString(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            var asn = new Asn1Reader(rawData);
            if (asn.Tag == (Byte)Asn1Type.BMPString) {
                return Encoding.BigEndianUnicode.GetString(asn.GetPayload());
            }
            throw new InvalidDataException();
        }
        /// <summary>
        /// Encodes UTF-16 string to a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="inputString">UTF-16 string to encode.</param>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] EncodeBMPString(String inputString) {
            return Encode(Encoding.BigEndianUnicode.GetBytes(inputString), (Byte)Asn1Type.BMPString);
        }
        /// <summary>
        /// Decodes <strong>UniversalString</strong> (UTF-16) to it's textual representation.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded UniversalString.</param>
        /// <exception cref="InvalidDataException">The input data is not properly encoded UniversalString.</exception>
        /// <exception cref="ArgumentNullException"><strong>rawData</strong> parameter is null reference.</exception>
        /// <returns>Decoded string.</returns>
        public static String DecodeUniversalString(Byte[] rawData) {
            if (rawData == null) { throw new ArgumentNullException(); }
            Asn1Reader asn = new Asn1Reader(rawData);
            List<Byte> orderedBytes = new List<Byte>();
            if (asn.Tag == (Byte)Asn1Type.UniversalString) {
                for (Int32 index = 0; index < rawData.Length; index += 4) {
                    orderedBytes.AddRange(new[] { rawData[index + 3], rawData[index + 2], rawData[index + 1], rawData[index] });
                }
                return Encoding.UTF32.GetString(orderedBytes.ToArray());
            }
            throw new InvalidDataException();
        }
        /// <summary>
        /// Encodes UTF-32 string to a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="inputString">UTF-32 string to encode.</param>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] EncodeUniversalString(String inputString) {
            List<Byte> orderedBytes = new List<Byte>();
            Byte[] unordered = Encoding.UTF32.GetBytes(inputString);
            for (Int32 index = 0; index < unordered.Length; index += 4) {
                orderedBytes.AddRange(new[] { unordered[index + 3], unordered[index + 2], unordered[index + 1], unordered[index] });
            }
            return Encode(orderedBytes.ToArray(), (Byte)Asn1Type.UniversalString);
        }
        /// <summary>
        /// Encodes primitive ASN.1 type of <strong>NULL</strong>.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        public static Byte[] EncodeNull() {
            return new Byte[] { 5, 0 };
        }
        /// <summary>
        /// Encodes a .NET DateTime object to a ASN.1-encoded byte array. This method is designed to conform
        /// <see href="http://tools.ietf.org/html/rfc5280">RFC 5280</see> requirement, so dates before 1950 and
        /// after 2050 year are required to be encoded by using Generalized Time encoding. UTC Time encoding is not allowed
        /// for periods beyond 1950 - 2049 years.
        /// </summary>
        /// <param name="time">
        /// An instance of <see cref="DateTime"/> object.</param> Value in this parameter is treated as local time. 
        /// <param name="zone">
        ///		Specifies the time zone for the value in <strong>time</strong> parameter.
        /// </param>
        /// <returns>ASN.1-encoded byte array.</returns>
        /// <remarks>
        ///		If the <strong>Year</strong> value of the <strong>time</strong> object is less or equals to 2049
        ///     and greater or equals to 1950, the DateTime object is encoded as a UTC time.
        ///     if year value is outside of 1950-2049 range, it is encoded as a generalized time.
        ///		<para>
        ///		If <strong>zone</strong> parameter is set to <strong>NULL</strong>, date and time in <strong>time</strong>
        ///		parameter will be converted to a Zulu time (Universal time). If zone information is not <strong>NULL</strong>,
        ///		date and time in <strong>time</strong> parameter will be converted to a GMT time and time zone will be added
        ///		to encoded value.
        ///		</para>
        /// </remarks>
        /// <seealso cref="EncodeUTCTime"/>
        /// <seealso cref="EncodeGeneralizedTime"/>
        public static Byte[] EncodeDateTime(DateTime time, TimeZoneInfo zone = null) {
            return time.Year < 2050 && time.Year >= 1950
                ? EncodeUTCTime(time, zone)
                : EncodeGeneralizedTime(time, zone);
        }
        public static DateTime DecodeDateTime(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            switch (asn.Tag) {
                case (Byte)Asn1Type.UTCTime: return new Asn1UtcTime(rawData).Value;
                case (Byte)Asn1Type.GeneralizedTime: return new Asn1GeneralizedTime(rawData).Value;
                default: throw new Asn1InvalidTagException();
            }
        }
        public static String DecodeAnyString(Byte[] rawData, IEnumerable<Asn1Type> types) {
            foreach (Asn1Type type in types) {
                switch (type) {
                    case Asn1Type.IA5String:
                        try { return new Asn1IA5String(rawData).Value; } catch { }
                        break;
                    case Asn1Type.PrintableString:
                        try { return new Asn1PrintableString(rawData).Value; } catch { }
                        break;
                    case Asn1Type.VisibleString:
                        try { return new Asn1VisibleString(rawData).Value; } catch { }
                        break;
                    case Asn1Type.UTF8String:
                        try { return new Asn1UTF8String(rawData).Value; } catch { }
                        break;
                    case Asn1Type.UniversalString:
                        try { return new Asn1UniversalString(rawData).Value; } catch { }
                        break;
                    case Asn1Type.BMPString:
                        try { return new Asn1BMPString(rawData).Value; } catch { }
                        break;
                    case Asn1Type.TeletexString:
                        try { return new Asn1TeletexString(rawData).Value; } catch { }
                        break;
                }
            }
            throw new InvalidDataException("The data is not valid string.");
        }
        public static Byte[] EncodeAnyString(String str, IEnumerable<Asn1Type> types) {
            foreach (Asn1Type type in types) {
                switch (type) {
                    case Asn1Type.IA5String:
                        try { return new Asn1IA5String(str).RawData; } catch { }
                        break;
                    case Asn1Type.PrintableString:
                        try { return new Asn1PrintableString(str).RawData; } catch { }
                        break;
                    case Asn1Type.VisibleString:
                        try { return new Asn1VisibleString(str).RawData; } catch { }
                        break;
                    case Asn1Type.UTF8String:
                        try { return new Asn1UTF8String(str).RawData; } catch { }
                        break;
                    case Asn1Type.BMPString:
                        try { return new Asn1BMPString(str).RawData; } catch { }
                        break;
                    case Asn1Type.TeletexString:
                        try { return new Asn1TeletexString(str).RawData; } catch { }
                        break;
                }
            }
            throw new InvalidDataException("The data is not valid string.");
        }
        #endregion
        #region String types:
        internal const Int32 CERT_RDN_ANY_TYPE         = 0;
        internal const Int32 CERT_RDN_ENCODED_BLOB     = 1;
        internal const Int32 CERT_RDN_OCTET_STRING     = 2;
        internal const Int32 CERT_RDN_NUMERIC_STRING   = 3;
        internal const Int32 CERT_RDN_PRINTABLE_STRING = 4;
        internal const Int32 CERT_RDN_TELETEX_STRING   = 5;
        internal const Int32 CERT_RDN_T61_STRING       = 5;
        internal const Int32 CERT_RDN_VIDEOTEX_STRING  = 6;
        internal const Int32 CERT_RDN_IA5_STRING       = 7;
        internal const Int32 CERT_RDN_GRAPHIC_STRING   = 8; // not used
        internal const Int32 CERT_RDN_VISIBLE_STRING   = 9;
        internal const Int32 CERT_RDN_ISO646_STRING    = 9;
        internal const Int32 CERT_RDN_GENERAL_STRING   = 10; // not used
        internal const Int32 CERT_RDN_UNIVERSAL_STRING = 11;
        internal const Int32 CERT_RDN_INT4_STRING      = 11;
        internal const Int32 CERT_RDN_BMP_STRING       = 12;
        internal const Int32 CERT_RDN_UNICODE_STRING   = 12;
        internal const Int32 CERT_RDN_UTF8_STRING      = 13;
        #endregion
        #region internal
        public static String GetViewValue(Asn1Reader asn) {
            if (asn.PayloadLength == 0 && asn.Tag != (Byte)Asn1Type.NULL) { return "NULL"; }
            switch (asn.Tag) {
                case (Byte)Asn1Type.BOOLEAN: return DecodeBoolean(asn);
                case (Byte)Asn1Type.INTEGER: return new Asn1Integer(asn).Value.ToString();
                case (Byte)Asn1Type.BIT_STRING: return DecodeBitString(asn);
                case (Byte)Asn1Type.OCTET_STRING: return DecodeOctetString(asn);
                case (Byte)Asn1Type.NULL: return null;
                case (Byte)Asn1Type.OBJECT_IDENTIFIER: return DecodeObjectIdentifier(asn);
                case (Byte)Asn1Type.UTF8String: return DecodeUTF8String(asn.GetTagRawData());
                case (Byte)Asn1Type.NumericString:
                case (Byte)Asn1Type.PrintableString:
                case (Byte)Asn1Type.TeletexString:
                case (Byte)Asn1Type.VideotexString:
                case (Byte)Asn1Type.IA5String:
                    return DecodeAsciiString(asn);
                case (Byte)Asn1Type.UTCTime:
                    return DecodeUtcTime(asn);
                case (Byte)Asn1Type.BMPString: return DecodeBMPString(asn);
                case (Byte)Asn1Type.GeneralizedTime:
                    return DecodeGeneralizedTime(asn);
                default:
                    return (asn.Tag & (Byte)Asn1Type.TAG_MASK) == 6
                        ? DecodeUTF8String(asn)
                        : DecodeOctetString(asn);
            }
        }
        #region Data type robust decoders
        static String DecodeBoolean(Asn1Reader asn) {
            if (asn.PayloadLength != 1) {
                throw new InvalidDataException("Invalid Boolean.");
            }
            // non-zero value is True
            return asn.RawData[asn.PayloadStartOffset] == 0 ? false.ToString() : true.ToString();
        }
        static String DecodeBitString(Asn1Reader asn) {
            return String.Format(
                "Unused bits: {0} : {1}",
                asn.RawData[asn.PayloadStartOffset],
                AsnFormatter.BinaryToString(
                    asn.RawData,
                    EncodingType.HexRaw,
                    EncodingFormat.NOCRLF,
                    asn.PayloadStartOffset + 1,
                    asn.PayloadLength - 1)
            );
        }
        static String DecodeOctetString(Asn1Reader asn) {
            return AsnFormatter.BinaryToString(
                asn.RawData,
                EncodingType.HexRaw,
                EncodingFormat.NOCRLF, asn.PayloadStartOffset, asn.PayloadLength);
        }
        static String DecodeObjectIdentifier(Asn1Reader asn) {
            var oid = new Asn1ObjectIdentifier(asn);
            return String.IsNullOrEmpty(oid.Value.FriendlyName)
                ? oid.Value.Value
                : $"{oid.Value.FriendlyName} ({oid.Value})";
        }
        static String DecodeUTF8String(Asn1Reader asn) {
            return Encoding.UTF8.GetString(asn.RawData, asn.PayloadStartOffset, asn.PayloadLength);
        }
        static String DecodeAsciiString(Asn1Reader asn) {
            return Encoding.ASCII.GetString(asn.RawData, asn.PayloadStartOffset, asn.PayloadLength);
        }
        static String DecodeUtcTime(Asn1Reader asn) {
            var dt = new Asn1UtcTime(asn).Value;
            return dt.ToShortDateString() + " " + dt.ToShortTimeString();
        }
        static String DecodeGeneralizedTime(Asn1Reader asn) {
            var dt = new Asn1GeneralizedTime(asn).Value;
            return dt.ToShortDateString() + " " + dt.ToShortTimeString();
        }
        static String DecodeBMPString(Asn1Reader asn) {
            return Encoding.BigEndianUnicode.GetString(asn.RawData, asn.PayloadStartOffset, asn.PayloadLength);
        }
        #endregion
        #endregion
    }
}
