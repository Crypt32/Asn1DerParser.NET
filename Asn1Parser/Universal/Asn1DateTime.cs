using System;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents base class for UTCTime and GeneralizedTime ASN.1 types
    /// </summary>
    public abstract class Asn1DateTime : UniversalTagBase {
        /// <summary>
        /// Initializes a new instance of <strong>Asn1DateTime</strong> class.
        /// </summary>
        protected Asn1DateTime(Asn1Type type) : base(type) { }
        /// <summary>
        /// Initializes a new instance of <strong>Asn1DateTime</strong> class from an existing
        /// <see cref="Asn1Reader"/> object.
        /// </summary>
        /// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents ASN.1 date/time object.</param>
        /// <param name="type">Optional expected ASN.1 type.</param>
        protected Asn1DateTime(Asn1Reader asn, Asn1Type? type) : base(asn, type) { }

        /// <summary>
        /// Gets the time zone information for the current object.
        /// </summary>
        public TimeZoneInfo ZoneInfo { get; protected set; }
        /// <summary>
        /// Gets date/time value associated with the current date/time object.
        /// </summary>
        public DateTime Value { get; protected set; }

    }
}
