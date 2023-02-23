using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using SysadminsLV.Asn1Parser.Utils;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents an ASN.1 <strong>PrintableString</strong> data type. PrintableString consists of the following
/// characters: a-z, A-Z, ' () +,-.?:/= and SPACE.
/// </summary>
public sealed class Asn1PrintableString : Asn1String {
    const Asn1Type TYPE = Asn1Type.PrintableString;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1PrintableString</strong> class from an <see cref="Asn1Reader"/>
    /// object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// Current position in the <strong>ASN.1</strong> object is not <strong>PrintableString</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid PrintableString character.
    /// </exception>
    public Asn1PrintableString(Asn1Reader asn) : base(asn, TYPE) {
        m_decode(asn);
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1PrintableString</strong> from a ASN.1-encoded byte array.
    /// </summary>
    /// <param name="rawData">ASN.1-encoded byte array.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// <strong>rawData</strong> is not <strong>PrintableString</strong> data type.
    /// </exception>
    /// <exception cref="InvalidDataException">
    /// Input data contains invalid PrintableString character.
    /// </exception>
    public Asn1PrintableString(Byte[] rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1PrintableString</strong> class from a unicode string.
    /// </summary>
    /// <param name="inputString">A unicode string to encode.</param>
    /// <exception cref="InvalidDataException">
    /// <strong>inputString</strong> contains invalid PrintableString characters
    /// </exception>
    public Asn1PrintableString(String inputString) : base(TYPE) {
        m_encode(inputString);
    }

    void m_encode(String inputString) {
        if (!testValue(inputString)) {
            throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
        }
        Value = inputString;
        Initialize(new Asn1Reader(Asn1Utils.Encode(Encoding.ASCII.GetBytes(inputString), TYPE)));
    }
    void m_decode(Asn1Reader asn) {
        if (!testValue(asn.GetPayload())) {
            throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
        }
        Value = Encoding.ASCII.GetString(asn.GetPayload());
    }
    static Boolean testValue(String str) {
        List<Byte> alphabet = StringUtils.GetAlphabet(TYPE);
        try {
            return str.All(c => alphabet.Contains(Convert.ToByte(c)));
        } catch { return false; }
    }
    static Boolean testValue(IEnumerable<Byte> rawData) {
        List<Byte> alphabet = StringUtils.GetAlphabet(TYPE);
        return rawData.All(alphabet.Contains);
    }

    /// <inheritdoc />
    public override String GetDisplayValue() {
        return Value;
    }
}