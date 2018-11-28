using System;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents an ASN.1 <strong>BOOLEAN</strong> data type.
    /// </summary>
    public sealed class Asn1Boolean : UniversalTagBase {
        const Asn1Type TYPE = Asn1Type.BOOLEAN;
        const Byte     TAG  = (Byte)TYPE;

        /// <summary>
        /// Initializes a new instance of the <strong>Asn1Boolean</strong> class from an <see cref="Asn1Reader"/>
        /// object.
        /// </summary>
        /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// Current position in the <strong>ASN.1</strong> object is not valid <strong>BOOLEAN</strong> data type.
        /// </exception>
        public Asn1Boolean(Asn1Reader asn) : base(asn) {
            if (asn.Tag != TAG) {
                throw new Asn1InvalidTagException(String.Format(InvalidType, TYPE.ToString()));
            }
            m_decode(asn);
        }
        /// <summary>
        /// Initializes a new instance of <strong>Asn1Boolean</strong> from a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// <strong>rawData</strong> is not valid <strong>BOOLEAN</strong> data type.
        /// </exception>
        public Asn1Boolean(Byte[] rawData) : this(new Asn1Reader(rawData)) { }
        /// <summary>
        /// Initializes a new instance of the <strong>Asn1Boolean</strong> class from a boolean value.
        /// </summary>
        /// <param name="fValue">Boolean value to encode.</param>
        public Asn1Boolean(Boolean fValue) {
            m_encode(fValue);
        }
        /// <summary>
        /// Gets value associated with the current object.
        /// </summary>
        public Boolean Value { get; private set; }

        void m_encode(Boolean fValue) {
            Value = fValue;
            var value = fValue ? 255 : 0;
            Initialize(new Asn1Reader(Asn1Utils.Encode(new Byte[value], TAG)));
        }
        void m_decode(Asn1Reader asn) {
            Value = asn.GetPayload()[0] > 0;
        }
    }
}
