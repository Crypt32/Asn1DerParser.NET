using System;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents a base class for ASN.1 primitive tag classes. This class provides
    /// </summary>
    public class UniversalTagBase {
        /// <summary>
        /// Initializes a new instance of <strong>UniversalTagBase</strong> class.
        /// </summary>
        protected UniversalTagBase() { }
        /// <summary>
        /// Initializes a new instance of <strong>UniversalTagBase</strong> from an existing <see cref="Asn1Reader"/>
        /// class instance.
        /// </summary>
        /// <param name="asn">Existing <see cref="ArgumentNullException"/> class instance.</param>
        /// <exception cref="Asn1Reader"><strong>asn</strong> parameter is null reference.</exception>
        public UniversalTagBase(Asn1Reader asn) {
            if (asn == null) { throw new ArgumentNullException(nameof(asn)); }
            Initialize(asn);
        }
        
        /// <summary>
        /// Gets the numeric tag value of the current ASN type.
        /// </summary>
        public Byte Tag { get; private set; }
        /// <summary>
        /// Gets the textual name of the ASN tag.
        /// </summary>
        public String TagName { get; private set; }
        /// <summary>
        /// Indicates whether the current structure is container.
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
        public Byte[] RawData { get; private set; }

        /// <summary>
        /// Initializes <strong>UniversalTagBase</strong> object from an existing <see cref="Asn1Reader"/> object.
        /// </summary>
        /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
        protected void Initialize(Asn1Reader asn) {
            Tag = asn.Tag;
            TagName = asn.TagName;
            IsContainer = asn.IsConstructed;
            RawData = asn.GetTagRawData();
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
            return RawData == null
                ? String.Empty
                : AsnFormatter.BinaryToString(RawData, EncodingType.HexRaw, EncodingFormat.NOCRLF);
        }
        /// <summary>
        /// Encodes current tag to either, Base64 or hex string.
        /// </summary>
        /// <param name="encoding">Specifies the output encoding.</param>
        /// <returns>Encoded text value.</returns>
        public virtual String Format(EncodingType encoding = EncodingType.Base64) {
            return RawData == null
                ? String.Empty
                : AsnFormatter.BinaryToString(RawData, encoding);
        }
    }
}
