using System;
using System.Text;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents a <strong>BMPString</strong> ASN.1 tag object. <Strong>BMPString</Strong> is a 16-bit unicode
/// string where each character is encoded by using two bytes in Big-Endian encoding.
/// </summary>
public sealed class Asn1BMPString : Asn1String {
    const Asn1Type TYPE = Asn1Type.BMPString;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1BitString</strong> class from an <see cref="Asn1Reader"/>
    /// object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not <strong>BMPString</strong>.
    /// </exception>
    public Asn1BMPString(Asn1Reader asn) : base(asn, TYPE) {
        m_decode(asn);
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1BitString</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>BMPString</strong> data type.
    /// </exception>
    public Asn1BMPString(Byte[] rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1BMPString</strong> class from a unicode string.
    /// </summary>
    /// <param name="inputString">A unicode string to encode.</param>
    public Asn1BMPString(String inputString) : base(TYPE) {
        m_encode(inputString);
    }

    void m_encode(String inputString) {
        Value = inputString;
        Initialize(new Asn1Reader(Asn1Utils.Encode(Encoding.BigEndianUnicode.GetBytes(inputString), TYPE)));
    }
    void m_decode(Asn1Reader asn) {
        Value = Encoding.BigEndianUnicode.GetString(asn.GetPayload());
    }

    /// <inheritdoc/>
    public override String GetDisplayValue() {
        return Value;
    }
}