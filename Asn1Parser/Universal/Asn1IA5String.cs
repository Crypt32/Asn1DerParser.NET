using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents an ASN.1 <strong>IA5String</strong> data type. IA5String contains characters
/// from International ASCII character (International Alphabet 5) set.
/// </summary>
public sealed class Asn1IA5String : Asn1String {
    const Asn1Type TYPE = Asn1Type.IA5String;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1IA5String</strong> class from an <see cref="Asn1Reader"/>
    /// object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not <strong>IA5String</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid IA5String character.
    /// </exception>
    public Asn1IA5String(Asn1Reader asn) : base(asn, TYPE) {
        m_decode(asn);
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1IA5String</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>IA5String</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid IA5String character.
    /// </exception>
    public Asn1IA5String(Byte[] rawData) : this(rawData.AsMemory()) { }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1IA5String</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>IA5String</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid IA5String character.
    /// </exception>
    public Asn1IA5String(ReadOnlyMemory<Byte> rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1IA5String</strong> class from a unicode string.
    /// </summary>
    /// <param name="inputString">A unicode string to encode.</param>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid IA5String character.
    /// </exception>
    public Asn1IA5String(String inputString) : base(TYPE) {
        m_encode(inputString);
    }

    void m_encode(String inputString) {
        if (inputString.Any(c => c > 127)) {
            throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
        }
        Value = inputString;
        Initialize(Asn1Utils.EncodeAsReader(Encoding.ASCII.GetBytes(inputString).AsSpan(), TYPE));
    }
    void m_decode(Asn1Reader asn) {
        if (asn.GetPayload().Any(b => b > 127)) {
            throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
        }
        Value = Encoding.ASCII.GetString(asn.GetPayload());
    }
}