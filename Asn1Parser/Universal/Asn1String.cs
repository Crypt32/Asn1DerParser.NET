using System;
using System.Collections.Generic;
using System.Linq;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents base class for ASN.1 string types.
/// </summary>
public abstract class Asn1String : Asn1Universal {
    #region allowedStringTypes:
    const Int32 CERT_RDN_ANY_TYPE         = 0;
    const Int32 CERT_RDN_ENCODED_BLOB     = 1;
    const Int32 CERT_RDN_OCTET_STRING     = 2;
    const Int32 CERT_RDN_NUMERIC_STRING   = 3;
    const Int32 CERT_RDN_PRINTABLE_STRING = 4;
    const Int32 CERT_RDN_TELETEX_STRING   = 5;
    const Int32 CERT_RDN_T61_STRING       = 5;
    const Int32 CERT_RDN_VIDEOTEX_STRING  = 6;
    const Int32 CERT_RDN_IA5_STRING       = 7;
    const Int32 CERT_RDN_GRAPHIC_STRING   = 8; // not used
    const Int32 CERT_RDN_VISIBLE_STRING   = 9;
    const Int32 CERT_RDN_ISO646_STRING    = 9;
    const Int32 CERT_RDN_GENERAL_STRING   = 10; // not used
    const Int32 CERT_RDN_UNIVERSAL_STRING = 11;
    const Int32 CERT_RDN_INT4_STRING      = 11;
    const Int32 CERT_RDN_BMP_STRING       = 12;
    const Int32 CERT_RDN_UNICODE_STRING   = 12;
    const Int32 CERT_RDN_UTF8_STRING      = 13;
    #endregion

    /// <summary>
    /// Initializes a new instance of <strong>Asn1String</strong> class.
    /// </summary>
    protected Asn1String(Asn1Type type) : base(type) { }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1String</strong> class from an existing
    /// <see cref="Asn1Reader"/> object.
    /// </summary>
    /// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents ASN.1 date/time object.</param>
    /// <param name="type">Optional expected ASN.1 type.</param>
    protected Asn1String(Asn1Reader asn, Asn1Type? type) : base(asn, type) { }

    /// <summary>
    /// Gets value associated with the current object.
    /// </summary>
    public String Value { get; protected set; }

    /// <summary>
    /// Decodes any ASN.1-encoded binary string into ASN.1 string type instance.
    /// </summary>
    /// <param name="rawData">Encoded ASN.1 string.</param>
    /// <param name="allowedStringTypes">An optional collection of allowed string allowedStringTypes.</param>
    /// <exception cref="ArgumentNullException">
    ///     <strong>rawData</strong> parameter is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///     <strong>rawData</strong> parameter is either too small or is not allowed by restriction.
    /// </exception>
    /// <returns>ASN.1 string type instance.</returns>
    /// <exception cref="Asn1InvalidTagException">
    ///     Input data is not valid string type.
    /// </exception>
    public static Asn1String DecodeAnyString(Byte[] rawData, IEnumerable<Asn1Type> allowedStringTypes = null) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }
        if (rawData.Length < 2) {
            throw new ArgumentException("Raw data must have at least tag (1 byte) and length components (1 byte) in TLV structure.");
        }

        IEnumerable<Asn1Type> asn1Types = allowedStringTypes?.ToList();
        if (asn1Types != null && !asn1Types.Contains((Asn1Type)rawData[0])) {
            throw new ArgumentException("Input string is not permitted by restriction.");
        }
        var tag = (Asn1Type)(rawData[0] & (Int32)Asn1Type.TAG_MASK);
        switch (tag) {
            case Asn1Type.IA5String:
                return new Asn1IA5String(rawData);
            case Asn1Type.PrintableString:
                return new Asn1PrintableString(rawData);
            case Asn1Type.VisibleString:
                return new Asn1VisibleString(rawData);
            case Asn1Type.UTF8String:
                return new Asn1UTF8String(rawData);
            case Asn1Type.UniversalString:
                return new Asn1UniversalString(rawData);
            case Asn1Type.BMPString:
                return new Asn1BMPString(rawData);
            case Asn1Type.TeletexString:
                return new Asn1TeletexString(rawData);
            case Asn1Type.NumericString:
                return new Asn1NumericString(rawData);
            case Asn1Type.VideotexString:
                return new Asn1VideotexString(rawData);
            default:
                throw new Asn1InvalidTagException("Input data is not valid string.");
        }
    }
}