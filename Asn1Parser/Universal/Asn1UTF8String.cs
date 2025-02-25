using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents an ASN.1 <strong>UTF8String</strong> data type. UTF8String consist of 8-bit encoded characters, including control
/// characters.
/// </summary>
public sealed class Asn1UTF8String : Asn1String {
    const Asn1Type TYPE = Asn1Type.UTF8String;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1UTF8String</strong> class from an <see cref="Asn1Reader"/>
    /// object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not <strong>UTF8String</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid UTF8String character.
    /// </exception>
    public Asn1UTF8String(Asn1Reader asn) : base(asn, TYPE) {
        m_decode(asn);
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1UTF8String</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>UTF8String</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid UTF8String character.
    /// </exception>
    public Asn1UTF8String(Byte[] rawData) : this(rawData.AsMemory()) { }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1UTF8String</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>UTF8String</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid UTF8String character.
    /// </exception>
    public Asn1UTF8String(ReadOnlyMemory<Byte> rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1UTF8String</strong> class from a unicode string.
    /// </summary>
    /// <param name="inputString">A unicode string to encode.</param>
    /// <exception cref="InvalidDataException">
    /// <strong>inputString</strong> contains invalid UTF8String characters
    /// </exception>
    public Asn1UTF8String(String inputString) : base(TYPE) {
        m_encode(inputString);
    }

    void m_encode(String inputString) {
        if (!testValue(inputString)) {
            throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
        }
        Value = inputString;
        Initialize(new Asn1Reader(Asn1Utils.Encode(Encoding.UTF8.GetBytes(inputString).AsMemory().Span, TYPE)));
    }
    void m_decode(Asn1Reader asn) {
        Value = Encoding.UTF8.GetString(asn.GetPayload());
    }
    static Boolean testValue(String str) {
        return str.All(x => Convert.ToUInt32(x) <= 255);
    }
}