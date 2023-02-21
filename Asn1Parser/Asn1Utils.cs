using System;
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
        /// <param name="enclosingTag">An enumeration of <see cref="Asn1Type"/> type represented as byte.</param>
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
        /// <summary>
        /// Wraps encoded data to an ASN.1 type/structure.
        /// </summary>
        /// <remarks>This method do not check whether the data in <strong>rawData</strong> is valid data for specified enclosing type.</remarks>
        /// <param name="rawData">A byte array to wrap.</param>
        /// <param name="type">An enumeration of <see cref="Asn1Type"/>.</param>
        /// <returns>Wrapped encoded byte array.</returns>
        /// <remarks>If <strong>rawData</strong> is null, an empty tag is encoded.</remarks>
        public static Byte[] Encode(Byte[] rawData, Asn1Type type) {
            return Encode(rawData, (Byte)type);
        }
        #endregion
        
        #region internal
        public static String GetViewValue(Asn1Reader asn) {
            if (asn.PayloadLength == 0 && asn.Tag != (Byte)Asn1Type.NULL) { return "NULL"; }
            switch (asn.Tag) {
                case (Byte)Asn1Type.BOOLEAN:
                    return new Asn1Boolean(asn).Value.ToString();
                case (Byte)Asn1Type.INTEGER:
                    return new Asn1Integer(asn).Value.ToString();
                case (Byte)Asn1Type.BIT_STRING: return decodeBitString(asn);
                case (Byte)Asn1Type.OCTET_STRING: return decodeOctetString(asn);
                case (Byte)Asn1Type.NULL: return null;
                case (Byte)Asn1Type.OBJECT_IDENTIFIER:
                    return new Asn1ObjectIdentifier(asn).GetDisplayValue();
                case (Byte)Asn1Type.UTF8String:
                    return new Asn1UTF8String(asn).Value;
                case (Byte)Asn1Type.NumericString:
                case (Byte)Asn1Type.PrintableString:
                case (Byte)Asn1Type.TeletexString:
                case (Byte)Asn1Type.VideotexString:
                case (Byte)Asn1Type.IA5String:
                    return decodeAsciiString(asn);
                case (Byte)Asn1Type.UTCTime:
                    return decodeUtcTime(asn);
                case (Byte)Asn1Type.BMPString:
                    return new Asn1BMPString(asn).Value;
                case (Byte)Asn1Type.GeneralizedTime:
                    return decodeGeneralizedTime(asn);
                default:
                    return (asn.Tag & (Byte)Asn1Type.TAG_MASK) == 6
                        ? new Asn1UTF8String(asn).Value
                        : decodeOctetString(asn);
            }
        }
        static String decodeBitString(Asn1Reader asn) {
            return String.Format(
                "Unused bits: {0} : {1}",
                asn[asn.PayloadStartOffset],
                AsnFormatter.BinaryToString(
                    asn.GetRawData(),
                    EncodingType.HexRaw,
                    EncodingFormat.NOCRLF,
                    asn.PayloadStartOffset + 1,
                    asn.PayloadLength - 1)
            );
        }
        static String decodeOctetString(Asn1Reader asn) {
            return AsnFormatter.BinaryToString(
                asn.GetRawData(),
                EncodingType.HexRaw,
                EncodingFormat.NOCRLF, asn.PayloadStartOffset, asn.PayloadLength);
        }
        static String decodeAsciiString(Asn1Reader asn) {
            return Encoding.ASCII.GetString(asn.GetRawData(), asn.PayloadStartOffset, asn.PayloadLength);
        }
        static String decodeUtcTime(Asn1Reader asn) {
            DateTime dt = new Asn1UtcTime(asn).Value;
            return dt.ToShortDateString() + " " + dt.ToShortTimeString();
        }
        static String decodeGeneralizedTime(Asn1Reader asn) {
            DateTime dt = new Asn1GeneralizedTime(asn).Value;
            return dt.ToShortDateString() + " " + dt.ToShortTimeString();
        }
        #endregion
    }
}
