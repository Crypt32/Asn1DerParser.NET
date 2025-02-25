using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents ASN.1 <strong>VisibleString</strong> data type. VisibleString consist of characters from international
/// printing character set. International printing character set contains characters starting from 32 and up to 126
/// codes in ASCII character table.
/// </summary>
public sealed class Asn1VisibleString : Asn1String {
    const Asn1Type TYPE = Asn1Type.VisibleString;


    /// <summary>
    /// Initializes a new instance of the <strong>Asn1VisibleString</strong> class from an <see cref="Asn1Reader"/>
    /// object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not <strong>VisibleString</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid VisibleString character.
    /// </exception>
    public Asn1VisibleString(Asn1Reader asn) : base(asn, TYPE) {
        m_decode(asn);
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1VisibleString</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>VisibleString</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid VisibleString character.
    /// </exception>
    public Asn1VisibleString(Byte[] rawData) : this(rawData.AsMemory()) { }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1VisibleString</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>VisibleString</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid VisibleString character.
    /// </exception>
    public Asn1VisibleString(ReadOnlyMemory<Byte> rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1VisibleString</strong> class from a unicode string.
    /// </summary>
    /// <param name="inputString">A unicode string to encode.</param>
    /// <exception cref="InvalidDataException">
    /// <strong>inputString</strong> contains invalid VisibleString characters
    /// </exception>
    public Asn1VisibleString(String inputString) : base(TYPE) {
        m_encode(inputString);
    }

    void m_encode(String inputString) {
        if (inputString.Any(c => c < 32 || c > 126)) {
            throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
        }
        Value = inputString;
        Initialize(new Asn1Reader(Asn1Utils.Encode(Encoding.ASCII.GetBytes(inputString).AsSpan(), TYPE)));
    }
    void m_decode(Asn1Reader asn) {
        if (asn.GetPayload().Any(b => b is < 32 or > 126)) {
            throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
        }
        Value = Encoding.ASCII.GetString(asn.GetPayload());
    }
}