using System;
using System.Linq;
using System.Text;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents a <strong>BIT_STRING</strong> ASN.1 tag object.
    /// </summary>
    public sealed class Asn1BitString : UniversalTagBase {
        const Asn1Type TYPE = Asn1Type.BIT_STRING;

        /// <summary>
        /// Initializes a new instance of the <strong>Asn1BitString</strong> class from an <see cref="Asn1Reader"/>
        /// object.
        /// </summary>
        /// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// Current position in the <strong>ASN.1</strong> object is not <strong>BIT_STRING</strong> data type.
        /// </exception>
        public Asn1BitString(Asn1Reader asn) : base(asn, TYPE) {
            UnusedBits = asn[asn.PayloadStartOffset];
            Value = asn.GetPayload().Skip(1).ToArray();
        }
        /// <summary>
        /// Initializes a new instance of <strong>Asn1BitString</strong> from a ASN.1-encoded byte array.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// <strong>rawData</strong> is not <strong>BIT_STRING</strong> data type.
        /// </exception>
        public Asn1BitString(Byte[] rawData) : this(new Asn1Reader(rawData)) { }
        /// <summary>
        /// Initializes a new instance of <strong>Asn1BitString</strong> from a raw byte array to encode and parameter that indicates
        /// whether the bit length is decremented to exclude trailing zero bits.
        /// </summary>
        /// <param name="valueToEncode">Raw value to encode.</param>
        /// <param name="calculateUnusedBits">
        /// <strong>True</strong> if the bit length is decremented to exclude trailing zero bits. Otherwise <strong>False</strong>.
        /// </param>
        /// <exception cref="ArgumentNullException"><strong>valueToEncode</strong> parameter is null reference.</exception>
        public Asn1BitString(Byte[] valueToEncode, Boolean calculateUnusedBits) : base(TYPE) {
            if (valueToEncode == null) { throw new ArgumentNullException(nameof(valueToEncode)); }
            m_encode(valueToEncode, calculateUnusedBits, 0);
        }
        ///  <summary>
        /// Initializes a new instance of <strong>Asn1BitString</strong> from a raw byte array to encode and a number of unused bits
        /// in a current bit string.
        /// </summary>
        /// <param name="valueToEncode">Raw value to encode.</param>
        /// <param name="unusedBits">A number of unused bits in bit string.</param>
        /// <exception cref="ArgumentNullException"><strong>valueToEncode</strong> parameter is null reference.</exception>
        public Asn1BitString(Byte[] valueToEncode, Byte unusedBits) : base(TYPE) {
            if (valueToEncode == null) { throw new ArgumentNullException(nameof(valueToEncode)); }
            m_encode(valueToEncode, false, unusedBits);
        }

        /// <summary>
        /// Gets the count of unused bits in the current <strong>BIT_STRING</strong>.
        /// </summary>
        public Byte UnusedBits { get; private set; }
        /// <summary>
        /// Gets raw value of BIT_STRING without unused bits identifier.
        /// </summary>
        public Byte[] Value { get; private set; }

        void m_encode(Byte[] value, Boolean calc, Byte unusedBits) {
            Value = value;
            UnusedBits = calc
                ? CalculateUnusedBits(value)
                : unusedBits;
            Byte[] v = new Byte[value.Length + 1];
            v[0] = UnusedBits;
            value.CopyTo(v, 1);
            Initialize(new Asn1Reader(Asn1Utils.Encode(v, Tag)));
        }

        /// <summary>
        /// Gets formatted tag value.
        /// </summary>
        /// <returns>Formatted tag value.</returns>
        public override String GetDisplayValue() {
            var SB = new StringBuilder();
            SB.AppendFormat("Unused bits={0}\r\n", UnusedBits);
            String tempString = AsnFormatter.BinaryToString(Value, EncodingType.HexAddress);
            SB.AppendFormat("{0}\r\n", tempString.Replace("\r\n", "\r\n    ").TrimEnd());

            return SB.ToString();
        }

        /// <summary>
        /// Calculates the number of bits left unused in the final byte of content.
        /// </summary>
        /// <param name="bytes">A byte array to process.</param>
        /// <returns>The number of unused bits.</returns>
        /// <exception cref="ArgumentNullException"><strong>bytes</strong> parameter is null reference.</exception>
        public static Byte CalculateUnusedBits(Byte[] bytes) {
            if (bytes == null) {
                throw new ArgumentNullException(nameof(bytes));
            }

            return CalculateUnusedBits(bytes[bytes.Length - 1]);
        }
        /// <summary>
        /// Calculates the number of bits left unused in the specified byte.
        /// </summary>
        /// <param name="b">The final byte of content</param>
        /// <returns>The number of unused bits.</returns>
        public static Byte CalculateUnusedBits(Byte b) {
            Byte unused = 0;
            Byte mask = 1;
            while ((mask & b) == 0 && mask < 128) {
                unused++;
                mask <<= 1;
            }

            return unused;
        }
    }
}
