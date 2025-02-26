using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using SysadminsLV.Asn1Parser.Utils;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents ASN.1 Object Identifier type.
/// </summary>
public sealed class Asn1ObjectIdentifier : Asn1Universal {
    const Asn1Type TYPE = Asn1Type.OBJECT_IDENTIFIER;
    const Byte ITU_T_ROOT = 0;
    const Byte ISO_ROOT   = 1;

    /// <summary>
    /// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from an existing
    /// <see cref="Asn1Reader"/> class instance.
    /// </summary>
    /// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents object identifier.</param>
    /// <exception cref="Asn1InvalidTagException">
    /// The current state of <strong>ASN1</strong> object is not object identifier.
    /// </exception>
    public Asn1ObjectIdentifier(Asn1Reader asn) : base(asn, TYPE) {
        Value = new Oid(decode(asn));
    }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from a memory buffer
    /// that represents encoded object identifier.
    /// </summary>
    /// <param name="rawData">Memory buffer that represents encoded object identifier.</param>
    public Asn1ObjectIdentifier(ReadOnlyMemory<Byte> rawData) : this(new Asn1Reader(rawData)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from a string
    /// that represents object identifier value.
    /// </summary>
    /// <param name="oid">String represents object identifier value.</param>
    /// <exception cref="InvalidDataException">The string is not valid object identifier.</exception>
    /// <exception cref="OverflowException">The string is too large.</exception>
    /// <remarks>Maximum object identifier string is 8kb.</remarks>
    public Asn1ObjectIdentifier(String oid) : this(new Oid(oid)) { }
    /// <summary>
    /// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from an OID object.
    /// </summary>
    /// <param name="oid">Object identifier (OID).</param>
    /// <exception cref="ArgumentNullException"><strong>oid</strong> parameter is null.</exception>
    /// <exception cref="InvalidDataException">The string is not valid object identifier.</exception>
    /// <exception cref="OverflowException">The string is too large.</exception>
    public Asn1ObjectIdentifier(Oid oid) : base(TYPE) {
        if (oid is null) {
            throw new ArgumentNullException(nameof(oid));
        }
        m_encode(oid);
    }

    /// <summary>
    /// Gets value associated with the current object.
    /// </summary>
    public Oid Value { get; private set; } = new();

    void m_encode(Oid oid) {
        if (String.IsNullOrWhiteSpace(oid.Value)) {
            Initialize(new Asn1Reader(new Byte[] { Tag, 0 }.AsMemory()));
            Value = new Oid();
            return;
        }
        if (oid.Value.Length > 8096) {
            throw new OverflowException("Oid string is longer than 8kb");
        }
        if (!validateOidString(oid.Value, out List<BigInteger> tokens)) {
            throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
        }
        Value = oid;
        Initialize(Asn1Utils.EncodeAsReader(encode(tokens), TYPE));
    }

    static ReadOnlySpan<Byte> encode(IList<BigInteger> tokens) {
        var rawOid = new List<Byte>();
        for (Int32 tokenIndex = 0; tokenIndex < tokens.Count; tokenIndex++) {
            BigInteger token = tokens[tokenIndex];
            // first two arcs are encoded as a single arc
            switch (tokenIndex) {
                case 0:
                    // 
                    token = 40 * token + tokens[tokenIndex + 1];
                    // if first two arcs can be encoded using 7 bits (single byte where most significant bit is 0),
                    // then nothing fancy, simply add it as single byte.
                    if (token < 0x80) {
                        rawOid.Add((Byte)token);
                        continue;
                    }
                    // otherwise first two arcs are encoded using multiple bytes, and we have to go through
                    // standard OID arc encoding routine.
                break;
                // we already handled 2nd arc, so skip its processing.
                case 1:
                    continue;
            }
            rawOid.AddRange(OidUtils.EncodeOidArc(token));
        }
        return rawOid.ToArray();
    }
    static String decode(Asn1Reader asn) {
        var SB = new StringBuilder();
        Boolean topArcsProcessed = false;
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
            if (!topArcsProcessed) {
                topArcsProcessed = true;
                // max value for first two arcs in ITU-T and ISO is 79 (OID=1.39). If this value is larger, then
                // it belongs to 'joint-iso-itu-t' (OID=2.x)
                if (value >= 80) {
                    SB.Append("2.").Append(value - 80);
                } else {
                    SB.Append(value / 40);
                    SB.Append("." + value % 40);
                }
                continue;
            }

            SB.Append("." + value);
        }
        return SB.ToString();
    }
    static Boolean validateOidString(String oid, out List<BigInteger> tokens) {
        String[] strTokens = oid.Split('.');
        if (strTokens.Length < 2) {
            tokens = [];
            return false;
        }
        tokens = [];
        for (Int32 index = 0; index < strTokens.Length; index++) {
            try {
                var value = BigInteger.Parse(strTokens[index]);
                if (index == 0) {
                    // check if root arc is 0, 1, or 2
                    if (value > 2) {
                        return false;
                    }
                    var secondArc = BigInteger.Parse(strTokens[1]);
                    // check if 2nd arc under ITU-T and ISO is <=39
                    if ((Byte)value is ITU_T_ROOT or ISO_ROOT && secondArc > 39) {
                        return false;
                    }
                }
                tokens.Add(value);
            } catch {
                tokens = [];
                return false;
            }
        }
        return true;
    }

    /// <inheritdoc/>
    public override String GetDisplayValue() {
        return String.IsNullOrEmpty(Value.FriendlyName)
            ? Value.Value
            : $"{Value.FriendlyName} ({Value.Value})";
    }
}