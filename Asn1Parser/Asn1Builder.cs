using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.Asn1Parser.Universal;

namespace SysadminsLV.Asn1Parser {
    /// <summary>
    /// Represents ASN.1 Distinguished Encoding Rules (DER) binary builder.
    /// </summary>
    public class Asn1Builder {
        readonly List<Byte> _rawData;

        /// <summary>
        ///     Initializes a new instance of <strong>Asn1Builder</strong> class.
        /// </summary>
        public Asn1Builder() {
            _rawData = new List<Byte>();
        }

        Asn1Builder(Asn1Builder builder) {
            _rawData = new List<Byte>(builder._rawData);
        }

        /// <summary>
        ///     Adds ASN.1 Boolean value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddBoolean(Boolean value) {
            _rawData.AddRange(new Asn1Boolean(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 Integer value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddInteger(BigInteger value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1Integer(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 BIT_STRING value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <param name="unusedBits">
        ///     Unused bits in bit string. This value must fall in range between 0 and 7.
        /// </param>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddBitString(Byte[] value, Byte unusedBits) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1BitString(value, unusedBits).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 BIT_STRING value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <param name="calculateUnusedBits">
        ///     Indicates whether unused bits should be calculated. If set to <strong>false</strong>, unused bits value is set to zero.
        /// </param>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddBitString(Byte[] value, Boolean calculateUnusedBits = false) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1BitString(value, calculateUnusedBits).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 OCTET_STRING value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddOctetString(Byte[] value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1OctetString(value, false).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 NULL value.
        /// </summary>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddNull() {
            _rawData.AddRange(new Asn1Null().RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 OBJECT_IDENTIFIER value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddObjectIdentifier(Oid value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1ObjectIdentifier(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 ENUMERATED value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddEnumerated(UInt64 value) {
            _rawData.AddRange(new Asn1Enumerated(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 UTF8String value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddUTF8String(String value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1UTF8String(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 SEQUENCE value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        /// <remarks>
        ///     In the current implementation, SEQUENCE is encoded using constructed form.
        /// </remarks>
        public Asn1Builder AddSequence(Byte[] value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            IEnumerable<Byte> encoded = Asn1Utils.Encode(value, 0x30);
            var asn = new Asn1Reader(value);
            asn.BuildOffsetMap();
            // if we reach this far, most likely, the data is ok.
            _rawData.AddRange(encoded);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 SET value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        /// <remarks>
        ///     In the current implementation, SET is encoded using constructed form.
        /// </remarks>
        public Asn1Builder AddSet(Byte[] value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            IEnumerable<Byte> encoded = Asn1Utils.Encode(value, 0x31);
            var asn = new Asn1Reader(value);
            asn.BuildOffsetMap();
            // if we reach this far, most likely, the data is ok.
            _rawData.AddRange(encoded);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 NumericString value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddNumericString(String value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1NumericString(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 PrintableString value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddPrintableString(String value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1PrintableString(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 TeletexString (T61String) value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddTeletexString(String value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1TeletexString(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 VideotexString value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddVideotexString(String value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(Asn1Utils.Encode(Encoding.ASCII.GetBytes(value), (Byte)Asn1Type.VideotexString));
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 IA5String value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddIA5String(String value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1IA5String(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 UTC_TIME value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddUtcTime(DateTime value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1UtcTime(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 GeneralizedTime value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddGeneralizedTime(DateTime value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1GeneralizedTime(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 VisibleString value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddVisibleString(String value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1VisibleString(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 UniversalString value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddUniversalString(String value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1UniversalString(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds ASN.1 BMP_STRING value.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddBMPString(String value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(new Asn1BMPString(value).RawData);
            return this;
        }
        /// <summary>
        ///     Adds arbitrary ASN.1-encoded data.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddDerData(Byte[] value) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            var asn = new Asn1Reader(value);
            asn.BuildOffsetMap();
            _rawData.AddRange(value);
            return this;
        }
        /// <summary>
        ///     Adds pure raw data (untagged) that is then encoded using specified tag.
        /// </summary>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <param name="outerTag">
        ///     Tag number to encode the data with.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddDerData(Byte[] value, Byte outerTag) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            _rawData.AddRange(Asn1Utils.Encode(value, outerTag));
            return this;
        }
        /// <summary>
        /// Adds implicitly tagged type. Implicit (IMPLICIT OPTIONAL, CHOICE) must derive from primitive types and cannot be constructed.
        /// </summary>
        /// <param name="implicitTag">
        ///     Implicit tag number. This number equals to tag number in square brackets in ASN module definition of IMPLICIT or CHOICE members.
        /// </param>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <param name="mustEncode">
        ///     Specifies if data in <strong>value</strong> parameter must be encoded or not. See Remarks for more details.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <exception cref="InvalidDataException">
        ///     <strong>value</strong> is not encoded.
        /// </exception>
        /// <returns>Current instance.</returns>
        /// <remarks>
        ///     If <strong>mustEncode</strong> parameter is set to <strong>true</strong>, then data in <strong>value</strong> parameter
        ///     is untagged. If <strong>mustEncode</strong> parameter is set to <strong>false</strong>, then data in <strong>value</strong>
        ///     parameter is explicitly tagged and only tag name change is necessary. Caller must have knowledge in advance if value is tagged or not.
        ///     If <strong>mustEncode</strong> parameter is set to <strong>false</strong> and value passed in <strong>value</strong> parameter
        ///     is untagged, an exception will be thrown.
        /// </remarks>
        public Asn1Builder AddImplicit(Byte implicitTag, Byte[] value, Boolean mustEncode) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            if (mustEncode) {
                _rawData.AddRange(Asn1Utils.Encode(value, (Byte)(0x80 + implicitTag)));
            } else {
                if (value.Length < 2) {
                    throw new InvalidDataException();
                }
                var asn = new Asn1Reader(value);
                asn.BuildOffsetMap();
                var valueCopy = value.ToArray();
                valueCopy[0] = (Byte)(0x80 + implicitTag);
                _rawData.AddRange(valueCopy);
            }
            return this;
        }
        /// <summary>
        /// Adds explicitly tagged type. Implicit (EXPLICIT OPTIONAL) must have at least one primitive or constructed nested type.
        /// </summary>
        /// <param name="explicitTag">
        ///     Explicit tag number. This number equals to tag number in square brackets in ASN module definition of EXPLICIT.
        /// </param>
        /// <param name="value">
        ///     Value to encode.
        /// </param>
        /// <param name="mustEncode">
        ///     Specifies if data in <strong>value</strong> parameter must be encoded or not. See Remarks for more details.
        /// </param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>value</strong> parameter is null.
        /// </exception>
        /// <exception cref="InvalidDataException">
        ///     <strong>value</strong> is not encoded.
        /// </exception>
        /// <returns>Current instance.</returns>
        /// <remarks>
        ///     If <strong>mustEncode</strong> parameter is set to <strong>true</strong>, then data in <strong>value</strong> parameter
        ///     is untagged. If <strong>mustEncode</strong> parameter is set to <strong>false</strong>, then data in <strong>value</strong>
        ///     parameter is explicitly tagged and only tag name change is necessary. Caller must have knowledge in advance if value is tagged or not.
        ///     If <strong>mustEncode</strong> parameter is set to <strong>false</strong> and value passed in <strong>value</strong> parameter
        ///     is untagged, invalid type will be produced.
        /// </remarks>
        public Asn1Builder AddExplicit(Byte explicitTag, Byte[] value, Boolean mustEncode) {
            if (value == null) {
                throw new ArgumentNullException(nameof(value));
            }
            if (mustEncode) {
                _rawData.AddRange(Asn1Utils.Encode(value, (Byte)(0xa0 + explicitTag)));
            } else {
                var asn = new Asn1Reader(value);
                asn.BuildOffsetMap();
                var valueCopy = value.ToArray();
                valueCopy[0] = (Byte)(0xa0 + explicitTag);
                _rawData.AddRange(valueCopy);
            }
            return this;
        }
        /// <summary>
        /// Adds constructed bit string.
        /// </summary>
        /// <param name="selector">Lambda expression to fill nested content.</param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>selector</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddBitString(Func<Asn1Builder, Asn1Builder> selector) {
            if (selector == null) {
                throw new ArgumentNullException(nameof(selector));
            }
            Asn1Builder b = selector(new Asn1Builder());
            _rawData.AddRange(new Asn1BitString(b._rawData.ToArray(), 0).RawData);
            return this;
        }
        /// <summary>
        /// Adds constructed octet string.
        /// </summary>
        /// <param name="selector">Lambda expression to fill nested content.</param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>selector</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddOctetString(Func<Asn1Builder, Asn1Builder> selector) {
            if (selector == null) {
                throw new ArgumentNullException(nameof(selector));
            }
            Asn1Builder b = selector(new Asn1Builder());
            _rawData.AddRange(Asn1Utils.Encode(b._rawData.ToArray(), (Byte)Asn1Type.OCTET_STRING));
            return this;
        }
        /// <summary>
        /// Adds constructed SEQUENCE.
        /// </summary>
        /// <param name="selector">Lambda expression to fill nested content.</param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>selector</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddSequence(Func<Asn1Builder, Asn1Builder> selector) {
            if (selector == null) {
                throw new ArgumentNullException(nameof(selector));
            }
            Asn1Builder b = selector(new Asn1Builder());
            _rawData.AddRange(Asn1Utils.Encode(b._rawData.ToArray(), 0x30));
            return this;
        }
        /// <summary>
        /// Adds constructed SET.
        /// </summary>
        /// <param name="selector">Lambda expression to fill nested content.</param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>selector</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddSet(Func<Asn1Builder, Asn1Builder> selector) {
            if (selector == null) {
                throw new ArgumentNullException(nameof(selector));
            }
            Asn1Builder b = selector(new Asn1Builder());
            _rawData.AddRange(Asn1Utils.Encode(b._rawData.ToArray(), 0x31));
            return this;
        }
        /// <summary>
        /// Adds constructed octet string.
        /// </summary>
        /// <param name="explicitTag">
        ///     Explicit tag number. This number equals to tag number in square brackets in ASN module definition of EXPLICIT.
        /// </param>
        /// <param name="selector">Lambda expression to fill nested content.</param>
        /// <exception cref="ArgumentNullException">
        ///     <strong>selector</strong> parameter is null.
        /// </exception>
        /// <returns>Current instance.</returns>
        public Asn1Builder AddExplicit(Byte explicitTag, Func<Asn1Builder, Asn1Builder> selector) {
            if (selector == null) {
                throw new ArgumentNullException(nameof(selector));
            }
            Asn1Builder b = selector(new Asn1Builder());
            _rawData.AddRange(Asn1Utils.Encode(b._rawData.ToArray(), (Byte)(0xa0 + explicitTag)));
            return this;
        }

        /// <summary>
        ///     Gets ASN.1-encoded byte array that represents current state of builder wrapped using outer ASN.1 type and returns new
        ///     builder instance that contains current builder state.
        /// </summary>
        /// <param name="outerType">
        ///     Outer type to wrap current state of builder. Outer type must not by the type that is used in primitive form only.
        ///     Default outer type is constructed SEQUENCE (0x30 or decimal 48).
        /// </param>
        /// <returns>
        ///     A new instance of ASN.1 DER builder that contains the state of the current instance.
        /// </returns>
        public Asn1Builder Encode(Byte outerType = 0x30) {
            IEnumerable<Byte> encoded = GetEncoded(outerType);
            _rawData.Clear();
            _rawData.AddRange(encoded);
            return new Asn1Builder(this);
        }

        /// <summary>
        ///     Gets ASN.1-encoded byte array that represents current state of builder wrapped using outer ASN.1 type.
        /// </summary>
        /// <param name="outerTag">
        ///     Outer type to wrap current state of builder. Outer type must not by the type that is used in primitive form only.
        ///     Default outer tag is constructed SEQUENCE (0x30 or decimal 48).
        /// </param>
        /// <returns>
        ///     ASN.1-encoded byte array.
        /// </returns>
        public Byte[] GetEncoded(Byte outerTag = 0x30) {
            return Asn1Utils.Encode(_rawData.ToArray(), outerTag);
        }
    }
}
