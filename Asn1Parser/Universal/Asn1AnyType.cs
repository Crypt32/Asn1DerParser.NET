namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents arbitrary ASN.1 type.
    /// </summary>
    public class Asn1AnyType : Asn1Universal {
        /// <summary>
        /// Initializes a new instance of <strong>Asn1AnyType</strong> class.
        /// </summary>
        /// <param name="asn">ASN.1 reader.</param>
        public Asn1AnyType(Asn1Reader asn) : base(asn, null) { }
    }
}