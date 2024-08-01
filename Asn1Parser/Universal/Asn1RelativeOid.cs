using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using SysadminsLV.Asn1Parser.Utils;

namespace SysadminsLV.Asn1Parser.Universal;
/// <summary>
/// Represents ASN.1 RELATIVE-OID type.
/// </summary>
public class Asn1RelativeOid : Asn1Universal {
    const Asn1Type TYPE = Asn1Type.RELATIVE_OID;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1RelativeOid</strong> class from an existing
    /// <see cref="Asn1Reader"/> class instance.
    /// </summary>
    /// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents relative object identifier.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// The current state of <strong>ASN1</strong> object is not relative object identifier.
    /// </exception>
    public Asn1RelativeOid(Asn1Reader asn) : base(asn, TYPE) {
        Value = decode(asn);
    }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1RelativeOid</strong> class from a byte array
    /// that represents encoded relative object identifier.
    /// </summary>
    /// <param name="rawData">Byte array that represents encoded relative object identifier.</param>
    public Asn1RelativeOid(Byte[] rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1RelativeOid</strong> class from a string
    /// that represents relative object identifier value.
    /// </summary>
    /// <param name="relativeOid">
    ///     String that represents relative object identifier value. This parameter accepts relative OIDs with or without
    ///     leading dot, e.g. '5', '.5', '5.10', '.5.10'.
    /// </param>
    /// <exception cref="ArgumentNullException"><strong>relativeOid</strong> parameter is null.</exception>
    /// <exception cref="OverflowException">The string is too large.</exception>
    /// <remarks>Maximum relative object identifier string is 8kb.</remarks>
    public Asn1RelativeOid(String relativeOid) : base(TYPE) {
        if (relativeOid == null) {
            throw new ArgumentNullException(nameof(relativeOid));
        }
        m_encode(relativeOid);
        if (relativeOid.StartsWith(".")) {
            Value = relativeOid;
        } else {
            Value = "." + relativeOid;
        }
    }

    /// <summary>
    /// Gets relative OID value string with leading dot (e.g. '.1', '.1.3').
    /// </summary>
    public String Value { get; private set; }

    void m_encode(String oidString) {
        if (String.IsNullOrWhiteSpace(oidString)) {
            Initialize(new Asn1Reader([Tag, 0]));
            Value = String.Empty;
            return;
        }
        oidString = oidString.Trim();
        if (oidString.Length > 8096) {
            throw new OverflowException("Oid string is longer than 8kb");
        }
        IEnumerable<BigInteger> tokens = oidString
            .Split(['.'], StringSplitOptions.RemoveEmptyEntries)
            .Select(BigInteger.Parse);
        Initialize(new Asn1Reader(Asn1Utils.Encode(encode(tokens), TYPE)));
    }
    static Byte[] encode(IEnumerable<BigInteger> tokens) {
        var rawOid = new List<Byte>();
        foreach (BigInteger token in tokens) {
            rawOid.AddRange(OidUtils.EncodeOidArc(token));
        }
        
        return rawOid.ToArray();
    }
    static String decode(Asn1Reader asn) {
        var SB = new StringBuilder();
        for (Int32 i = 0; i < asn.PayloadLength; i++) {
            Int32 pi = asn.PayloadStartOffset + i;

            BigInteger value = 0;
            Boolean proceed;
            do {
                value <<= 7;
                value += asn[pi] & 0x7f;
                proceed = (asn[pi] & 0x80) > 0;
                if (proceed) {
                    i++;
                    pi++;
                }
            } while (proceed);

            SB.Append("." + value);
        }
        return SB.ToString();
    }

    /// <inheritdoc />
    public override String GetDisplayValue() {
        return Value;
    }
}
