using System;
using System.IO;
using System.Linq;
using System.Numerics;
using SysadminsLV.Asn1Parser.Utils.CLRExtensions;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents an ASN.1 <strong>ENUMERATED</strong> data type.
/// </summary>
public sealed class Asn1Enumerated : Asn1Universal {
    const Asn1Type TYPE = Asn1Type.ENUMERATED;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1Enumerated</strong> class from an <see cref="Asn1Reader"/>
    /// object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not valid <strong>INTEGER</strong> data type.
    /// </exception>
    public Asn1Enumerated(Asn1Reader asn) : base(asn, TYPE) {
        m_decode(asn);
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1Enumerated</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not valid <strong>INTEGER</strong> data type.
    /// </exception>
    public Asn1Enumerated(Byte[] rawData) : this(rawData.AsMemory()) { }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1Enumerated</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not valid <strong>INTEGER</strong> data type.
    /// </exception>
    public Asn1Enumerated(ReadOnlyMemory<Byte> rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1Enumerated</strong> class from an integer value.
    /// </summary>
    /// <param name="inputInteger">Integer value to encode.</param>
    public Asn1Enumerated(UInt64 inputInteger) : base(TYPE) {
        m_encode(inputInteger);
    }

    /// <summary>
    /// Gets value associated with the current object.
    /// </summary>
    public UInt64 Value { get; private set; }

    void m_encode(BigInteger inputInteger) {
        Value = (UInt64)inputInteger;
        Initialize(new Asn1Reader(Asn1Utils.Encode(inputInteger.GetAsnBytes(), TYPE)));
    }
    void m_decode(Asn1Reader asn) {
        var value = new BigInteger(asn.GetPayload().Reverse().ToArray());
        if (value > UInt64.MaxValue) {
            throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
        }
        Value = Convert.ToUInt64(value);
    }
}