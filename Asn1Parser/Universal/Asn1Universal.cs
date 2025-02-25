using System;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents a base class for ASN.1 primitive tag classes. This class provides
/// </summary>
public abstract class Asn1Universal {
    Asn1Reader? asnReader;
    /// <summary>
    /// Initializes a new instance of <strong>Asn1Universal</strong> class.
    /// </summary>
    protected Asn1Universal(Asn1Type type) {
        Tag = (Byte)type;
        TagName = Asn1Reader.GetTagName(Tag);
        IsContainer = (Tag & (Byte)Asn1Class.CONSTRUCTED) > 0;
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1Universal</strong> from an existing <see cref="Asn1Reader"/>
    /// class instance.
    /// </summary>
    /// <param name="asn">Existing <see cref="ArgumentNullException"/> class instance.</param>
    /// <param name="type">ASN.1 type.</param>
    /// <exception cref="Asn1Reader"><strong>asn</strong> parameter is null reference.</exception>
    protected Asn1Universal(Asn1Reader asn, Asn1Type? type) {
        if (asn == null) {
            throw new ArgumentNullException(nameof(asn));
        }
        if (type.HasValue && asn.Tag != (Byte)type.Value) {
            throw new Asn1InvalidTagException(String.Format(InvalidType, type.ToString()));
        }
        Initialize(asn);
    }

    /// <summary>
    /// Gets the numeric tag value of the current ASN type.
    /// </summary>
    public Byte Tag { get; private set; }
    /// <summary>
    /// Gets the textual name of the ASN tag.
    /// </summary>
    public String TagName { get; private set; } = String.Empty;
    /// <summary>
    /// Indicates whether the current structure is container. This includes all constructed types
    /// and may include OCTET_STRING and BIT_STRING with encapsulated types. OCTET_STRING and BIT_STRING
    /// use primitive type form.
    /// </summary>
    /// <remarks>
    ///		The following primitive types cannot have encapsulated types:
    /// <list type="bullet">
    ///		<item>BOOLEAN</item>
    ///		<item>INTEGER</item>
    ///		<item>NULL</item>
    ///		<item>OBJECT_IDENTIFIER</item>
    ///		<item>REAL</item>
    ///		<item>ENUMERATED</item>
    ///		<item>RELATIVE-OID</item>
    ///     <item>UTC_TIME</item>
    ///     <item>GeneralizedTime</item>
    /// </list>
    ///     and any kind of string types:
    /// <list type="bullet">
    ///		<item>UTF8String</item>
    ///		<item>NumericString</item>
    ///		<item>PrintableString</item>
    ///		<item>TeletexString</item>
    ///		<item>VideotexString</item>
    ///		<item>IA5String-OID</item>
    ///     <item>GraphicString</item>
    ///     <item>VisibleString</item>
    ///     <item>GeneralString</item>
    ///     <item>UniversalString</item>
    ///     <item>CHARACTER_STRING</item>
    ///     <item>BMPString</item>
    /// </list>
    /// </remarks>
    public Boolean IsContainer { get; private set; }
    /// <summary>
    /// Gets the full tag raw data, including header and payload information.
    /// </summary>
    [Obsolete("Use 'GetRawDataAsMemory()' method instead.", true)]
    public Byte[] RawData => GetRawData();

    /// <summary>
    /// Initializes <strong>Asn1Universal</strong> object from an existing <see cref="Asn1Reader"/> object.
    /// </summary>
    /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
    protected void Initialize(Asn1Reader asn) {
        asnReader = asn.GetReader(); // do not store external ASN reader reference.
        Tag = asn.Tag;
        TagName = asn.TagName;
        IsContainer = asn.IsConstructed;
    }
    /// <summary>
    /// Constant string to display error message for tag mismatch exceptions.
    /// </summary>
    protected const String InvalidType = "Input data does not represent valid '{0}' type.";

    /// <summary>
    /// Gets decoded type value. If the value cannot be decoded, a hex dump is returned.
    /// </summary>
    /// <returns>Decoded type value.</returns>
    public virtual String GetDisplayValue() {
        return asnReader == null
            ? String.Empty
            : AsnFormatter.BinaryToString(asnReader, EncodingType.HexRaw, EncodingFormat.NOCRLF);
    }
    /// <summary>
    /// Encodes current tag to either, Base64 or hex string.
    /// </summary>
    /// <param name="encoding">Specifies the output encoding.</param>
    /// <returns>Encoded text value.</returns>
    public virtual String Format(EncodingType encoding = EncodingType.Base64) {
        return asnReader == null
            ? String.Empty
            : AsnFormatter.BinaryToString(asnReader, encoding);
    }
    /// <summary>
    /// Gets the full tag raw data, including header and payload information.
    /// </summary>
    /// <returns>ASN.1-encoded type.</returns>
    [Obsolete("Consider using 'GetRawDataAsMemory()' method instead.")]
    public Byte[] GetRawData() {
        return asnReader!.GetTagRawData();
    }
    /// <summary>
    /// Gets the full tag raw data, including header and payload information.
    /// </summary>
    /// <returns>ASN.1-encoded type as span.</returns>
    public ReadOnlyMemory<Byte> GetRawDataAsMemory() {
        return asnReader!.GetTagRawDataAsMemory();
    }
}