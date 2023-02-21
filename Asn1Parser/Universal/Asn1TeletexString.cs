using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents an ASN.1 TeletexString data type. TeletexString may contain characters from T.101 and CCITT, which
    /// are basically characters encoded with 7-bits (0-127 in ASCII table).
    /// </summary>
    public sealed class Asn1TeletexString : Asn1String {
        const Asn1Type TYPE = Asn1Type.TeletexString;

        /// <summary>
        /// Initializes a new instance of <strong>Asn1TeletexString</strong> from an ASN reader object.
        /// </summary>
        /// <param name="asn">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// Current position in the <strong>ASN.1</strong> object is not <strong>TeletexString</strong>.
        /// </exception>
        /// <exception cref="InvalidDataException">
        /// Input data contains invalid TeletexString character.
        /// </exception>
        public Asn1TeletexString(Asn1Reader asn) : base(asn, TYPE) {
            m_decode(asn);
        }
        /// <summary>
        /// Initializes a new instance of <strong>Asn1TeletexString</strong> from an ASN.1-encoded byte array.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="InvalidDataException">
        /// <strong>rawData</strong> parameter represents different data type.
        /// </exception>
        /// <exception cref="InvalidDataException">
        /// Input data contains invalid TeletexString character.
        /// </exception>
        public Asn1TeletexString(Byte[] rawData) : this(new Asn1Reader(rawData)) { }
        /// <summary>
        /// Initializes a new instance of <strong>Asn1TeletexString</strong> from a string that contains valid
        /// Teletex String characters.
        /// </summary>
        /// <param name="inputString"></param>
        /// <exception cref="InvalidDataException">
        /// Input data contains invalid TeletexString character.
        /// </exception>
        public Asn1TeletexString(String inputString) : base(TYPE) {
            m_encode(inputString);
        }

        void m_encode(String inputString) {
            if (inputString.Any(c => c > 127)) {
                throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
            }
            Value = inputString;
            Initialize(new Asn1Reader(Asn1Utils.Encode(Encoding.ASCII.GetBytes(inputString), TYPE)));
        }
        void m_decode(Asn1Reader asn) {
            if (asn.GetPayload().Any(b => b > 127)) {
                throw new InvalidDataException(String.Format(InvalidType, TYPE.ToString()));
            }
            Value = Encoding.ASCII.GetString(asn.GetPayload());
        }
        
        /// <inheritdoc/>
        public override String GetDisplayValue() {
            return Value;
        }
    }
}
