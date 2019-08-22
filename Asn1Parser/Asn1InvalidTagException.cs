using System;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

namespace SysadminsLV.Asn1Parser {
    /// <summary>
    /// The exception that is thrown when a data stream contains invalid ASN.1 type or type is not the one client expects.
    /// </summary>
    [Serializable]
    [ComVisible(true)]
    public sealed class Asn1InvalidTagException : Exception {
        /// <inheritdoc />
        public Asn1InvalidTagException()
            : base("ASN1 bad tag value met.") {
            HResult = unchecked((Int32)0x8009310b);
        }
        /// <inheritdoc />
        public Asn1InvalidTagException(String message) : base(message) {
            HResult = unchecked((Int32)0x8009310b);
        }
        /// <inheritdoc />
        public Asn1InvalidTagException(Int32 offset)
            : base(String.Format("ASN1 bad tag value met at offset:{0}.", offset)) {
            HResult = unchecked((Int32)0x8009310b);
            Offset = offset;
        }
        /// <inheritdoc />
        public Asn1InvalidTagException(Exception innerException)
            : base("ASN1 bad tag value met.", innerException) {
            HResult = unchecked((Int32)0x8009310b);
        }
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">
        /// The exception that is the cause of the current exception. If the <strong>innerException</strong> parameter is not a null
        /// reference, the current exception is raised in a catch block that handles the inner exception.
        /// </param>
        public Asn1InvalidTagException(String message, Exception innerException) : base(message, innerException) { }
        /// <param name="info">The object that holds the serialized object data.</param>
        /// <param name="context">The contextual information about the source or destination.</param>
        /// <remarks>This constructor is called during deserialization to reconstitute the exception object transmitted over a stream.</remarks>
        public Asn1InvalidTagException(SerializationInfo info, StreamingContext context) : base(info, context) { }
        /// <summary>
        /// Gets the offset at which invalid ASN tag appear.
        /// </summary>
        public Int32 Offset { get; private set; }
    }
}
