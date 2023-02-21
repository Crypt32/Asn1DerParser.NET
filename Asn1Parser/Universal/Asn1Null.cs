using System;
using System.IO;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents an ASN.1 <strong>NULL</strong> data type.
    /// </summary>
    public sealed class Asn1Null : UniversalTagBase {
        const Asn1Type TYPE = Asn1Type.NULL;

        /// <summary>
        /// Initializes a new instance of <strong>Asn1Null</strong> class.
        /// </summary>
        public Asn1Null() : base(TYPE) {
            Initialize(new Asn1Reader(new Byte[] {5, 0}));
        }
        /// <summary>
        /// Initializes a new instance of the <strong>Asn1Null</strong> class from an <see cref="Asn1Reader"/>
        /// object.
        /// </summary>
        /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// Current position in the <strong>ASN.1</strong> object is not valid <strong>NULL</strong> data type.
        /// </exception>
        public Asn1Null(Asn1Reader asn) : base(asn, TYPE) {
            m_decode(asn);
        }
        /// <summary>
        /// Initializes a new instance of <strong>Asn1Null</strong> from a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// <strong>rawData</strong> is not valid <strong>NULL</strong> data type.
        /// </exception>
        public Asn1Null(Byte[] rawData) : this(new Asn1Reader(rawData)) { }

        void m_decode(Asn1Reader asn) {
            if (asn.PayloadLength > 0) {
                throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
            }
        }
    }
}
