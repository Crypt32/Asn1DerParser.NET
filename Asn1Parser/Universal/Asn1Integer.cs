using System;
using System.Linq;
using System.Numerics;
using SysadminsLV.Asn1Parser.Utils.CLRExtensions;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents an ASN.1 <strong>INTEGER</strong> data type.
/// </summary>
public sealed class Asn1Integer : Asn1Universal {
    const Asn1Type TYPE = Asn1Type.INTEGER;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1Integer</strong> class from an <see cref="Asn1Reader"/>
    /// object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not valid <strong>INTEGER</strong> data type.
    /// </exception>
    public Asn1Integer(Asn1Reader asn) : base(asn, TYPE) {
        m_decode(asn);
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1Integer</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not valid <strong>INTEGER</strong> data type.
    /// </exception>
    public Asn1Integer(Byte[] rawData) : this(rawData.AsMemory()) { }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1Integer</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not valid <strong>INTEGER</strong> data type.
    /// </exception>
    public Asn1Integer(ReadOnlyMemory<Byte> rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1Integer</strong> class from an integer value.
    /// </summary>
    /// <param name="inputInteger">Integer value to encode.</param>
    public Asn1Integer(BigInteger inputInteger) : base(TYPE) {
        m_encode(inputInteger);
    }

    /// <summary>
    /// Gets value associated with the current object.
    /// </summary>
    public BigInteger Value { get; private set; }

    void m_encode(BigInteger inputInteger) {
        Value = inputInteger;
        Initialize(Asn1Utils.EncodeAsReader(inputInteger.GetAsnBytes(), TYPE));
    }
    void m_decode(Asn1Reader asn) {
        Value = new BigInteger(asn.GetPayload().Reverse().ToArray());
    }
}