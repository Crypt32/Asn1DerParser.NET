using System;
using System.IO;
using System.Text;

namespace SysadminsLV.Asn1Parser.Universal;
/// <summary>
/// Represents an ASN.1 <strong>VideotexString</strong> data type.
/// The ASN.1 VideotexString type supports T.100/T.101 characters. This type is no longer used.
/// </summary>
public sealed class Asn1VideotexString : Asn1String {
    const Asn1Type TYPE = Asn1Type.VideotexString;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1VideotexString</strong> class from an <see cref="Asn1Reader"/>
    /// object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not <strong>VideotexString</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid VideotexString character.
    /// </exception>
    public Asn1VideotexString(Asn1Reader asn) : base(asn, TYPE) { }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1VideotexString</strong> from a ASN.1-encoded memory buffer.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded memory buffer.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>VideotexString</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid VideotexString character.
    /// </exception>
    public Asn1VideotexString(ReadOnlyMemory<Byte> rawData) : base(new Asn1Reader(rawData), TYPE) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1VideotexString</strong> class from a unicode string.
    /// </summary>
    /// <param name="inputString">A unicode string to encode.</param>
    /// <exception cref="InvalidDataException">
    /// <strong>inputString</strong> contains invalid VideotexString characters
    /// </exception>
    public Asn1VideotexString(String inputString) : base(TYPE) {
        encode(inputString);
    }

    void encode(String inputString) {
        Initialize(Asn1Utils.EncodeAsReader(Encoding.ASCII.GetBytes(inputString).AsSpan(), TYPE));
        Value = inputString;
    }
    protected override String Decode(ReadOnlySpan<Byte> payload) {
        var sb = new StringBuilder(payload.Length);
        foreach (Byte b in payload) {
            sb.Append((Char)b);
        }

        return sb.ToString();
    }
}