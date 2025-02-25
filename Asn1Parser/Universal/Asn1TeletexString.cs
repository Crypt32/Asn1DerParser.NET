using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents an ASN.1 TeletexString data type. TeletexString may contain characters from T.101 and CCITT, which
/// are basically characters encoded with 7-bits (0-127 in ASCII table).
/// </summary>
public sealed class Asn1TeletexString : Asn1String {
    const Asn1Type TYPE = Asn1Type.TeletexString;

    /// <summary>
    /// Initializes a new instance of <strong>Asn1TeletexString</strong> from an ASN reader object.
    /// </summary>
    /// <param name="asn">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not <strong>TeletexString</strong>.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid TeletexString character.
    /// </exception>
    public Asn1TeletexString(Asn1Reader asn) : base(asn, TYPE) { }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1TeletexString</strong> from an ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="InvalidDataException">
    /// <strong>rawData</strong> parameter represents different data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid TeletexString character.
    /// </exception>
    public Asn1TeletexString(Byte[] rawData) : this(rawData.AsMemory()) { }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1TeletexString</strong> from an ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="InvalidDataException">
    /// <strong>rawData</strong> parameter represents different data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid TeletexString character.
    /// </exception>
    public Asn1TeletexString(ReadOnlyMemory<Byte> rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1TeletexString</strong> from a string that contains valid
    /// Teletex String characters.
    /// </summary>
    /// <param name="inputString"></param>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid TeletexString character.
    /// </exception>
    public Asn1TeletexString(String inputString) : base(TYPE) {
        m_encode(inputString);
    }

    void m_encode(String inputString) {
        if (inputString.Any(c => c > 127)) {
            throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
        }
        Value = inputString;
        Initialize(new Asn1Reader(Asn1Utils.Encode(Encoding.ASCII.GetBytes(inputString).AsSpan(), TYPE)));
    }

    protected override Boolean IsValidString(ReadOnlySpan<Byte> value) {
        foreach (Byte b in value) {
            if (b > 127) {
                return false;
            }
        }

        return true;
    }
    protected override String Decode(ReadOnlySpan<Byte> payload) {
        var sb = new StringBuilder(payload.Length);
        foreach (Byte b in payload) {
            sb.Append((Char)b);
        }

        return sb.ToString();
    }
}