using System;
using System.IO;
using System.Text;
using SysadminsLV.Asn1Parser.Utils.CLRExtensions;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents an ASN.1 <strong>UniversalString</strong> data type. Universal String represents strings where each character
/// is encoded using 4 bytes.
/// </summary>
public sealed class Asn1UniversalString : Asn1String {
    const Asn1Type TYPE = Asn1Type.UniversalString;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1UniversalString</strong> class from an <see cref="Asn1Reader"/>
    /// object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not <strong>UniversalString</strong> data type.
    /// </exception>
    public Asn1UniversalString(Asn1Reader asn) : base(asn, TYPE) {
        m_decode(asn);
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1UniversalString</strong> from a ASN.1-encoded memory buffer.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded memory buffer.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>UniversalString</strong> data type.
    /// </exception>
    public Asn1UniversalString(ReadOnlyMemory<Byte> rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1UniversalString</strong> class from a Unicode string.
    /// </summary>
    /// <param name="inputString">A unicode string to encode.</param>
    /// <exception cref="InvalidDataException">
    /// <strong>inputString</strong> contains invalid PrintableString characters
    /// </exception>
    public Asn1UniversalString(String inputString) : base(TYPE) {
        m_encode(inputString);
    }

    void m_encode(String inputString) {
        Value = inputString;
        // UTF-32BE encoding (big-endian, no BOM)
        var utf32be = new UTF32Encoding(bigEndian: true, byteOrderMark: false);
        Initialize(Asn1Utils.EncodeAsReader(utf32be.GetBytes(inputString).AsSpan(), TYPE));
    }
    void m_decode(Asn1Reader asn) {
        // UTF-32BE decoding (big-endian, no BOM)
        var utf32be = new UTF32Encoding(bigEndian: true, byteOrderMark: false);
        ReadOnlySpan<Byte> payload = asn.GetPayloadAsMemory().Span;
        Value = utf32be.GetString(payload);
    }
}