using System;
using System.IO;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents an ASN.1 <strong>OCTET_STRING</strong> data type.
/// </summary>
public sealed class Asn1OctetString : Asn1Universal {
    const Asn1Type TYPE = Asn1Type.OCTET_STRING;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1NumericString</strong> class from an <see cref="Asn1Reader"/>
    /// object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not <strong>NumericString</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid NumericString character.
    /// </exception>
    public Asn1OctetString(Asn1Reader asn) : base(asn, TYPE) {
        Value = asn.GetPayload();
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1NumericString</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <param name="tagged">Boolean value that indicates whether the byte array in <strong>rawData</strong> parameter is encoded or not.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>NumericString</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid NumericString character.
    /// </exception>
    [Obsolete("Consider using constructor that accepts 'ReadOnlyMemory' instead.")]
    public Asn1OctetString(Byte[] rawData, Boolean tagged) : base(TYPE) {
        if (tagged) {
            var asn = new Asn1Reader(rawData);
            if (asn.Tag != Tag) {
                throw new Asn1InvalidTagException(String.Format(InvalidType, TYPE.ToString()));
            }
            Value = asn.GetPayload();
            Initialize(asn);
        } else {
            Value = rawData;
            Initialize(new Asn1Reader(Asn1Utils.Encode(rawData.AsSpan(), TYPE)));
        }
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1NumericString</strong> from a ASN.1-encoded memory buffer.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded memory buffer.</param>
    /// <param name="tagged">Boolean value that indicates whether the byte array in <strong>rawData</strong> parameter is encoded or not.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>NumericString</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid NumericString character.
    /// </exception>
    public Asn1OctetString(ReadOnlyMemory<Byte> rawData, Boolean tagged) : base(TYPE) {
        if (tagged) {
            var asn = new Asn1Reader(rawData);
            if (asn.Tag != Tag) {
                throw new Asn1InvalidTagException(String.Format(InvalidType, TYPE.ToString()));
            }
            Value = asn.GetPayload();
            Initialize(asn);
        } else {
            Value = rawData.ToArray();
            Initialize(new Asn1Reader(Asn1Utils.Encode(rawData.Span, TYPE)));
        }
    }

    /// <summary>
    /// Gets value associated with the current object.
    /// </summary>
    [Obsolete("Use 'GetValue()' method instead.")]
    public Byte[] Value { get; private set; }

    public ReadOnlyMemory<Byte> GetValue() {
        return GetInternalReader().GetPayloadAsMemory();
    }
}