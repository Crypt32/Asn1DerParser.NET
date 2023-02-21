using System;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents base class for ASN.1 string types.
    /// </summary>
    public abstract class Asn1String : UniversalTagBase {
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

    }
}
