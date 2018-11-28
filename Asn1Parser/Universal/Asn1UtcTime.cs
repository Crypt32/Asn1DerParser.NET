using System;
using System.Globalization;
using SysadminsLV.Asn1Parser.Utils;

namespace SysadminsLV.Asn1Parser.Universal {
    /// <summary>
    /// Represents ASN.1 <strong>UTCTime</strong> universal tag.
    /// </summary>
    public sealed class Asn1UtcTime : Asn1DateTime {
        const Asn1Type TYPE = Asn1Type.UTCTime;
        const Byte     TAG  = (Byte)TYPE;

        /// <summary>
        /// Initializes a new instance of the <strong>Asn1UtcTime</strong> class from a date time object
        /// to encode and value that indicates whether to include millisecond information.
        /// </summary>
        /// <param name="time">A <see cref="DateTime"/> object.</param>
        /// <param name="preciseTime">
        /// <strong>True</strong> if encoded value should contain millisecond information, otherwise <strong>False</strong>.
        /// </param>
        public Asn1UtcTime(DateTime time, Boolean preciseTime) : this(time, null, preciseTime) { }
        /// <summary>
        /// Initializes a new instance of the <strong>Asn1UtcTime</strong> class from a date time object
        /// to encode, time zone information and value that indicates whether to include millisecond information.
        /// </summary>
        /// <param name="time">A <see cref="DateTime"/> object.</param>
        /// <param name="zone">A <see cref="TimeZoneInfo"/> object that represents time zone information.</param>
        /// <param name="preciseTime">
        /// <strong>True</strong> if encoded value should contain millisecond information, otherwise <strong>False</strong>.
        /// </param>
        public Asn1UtcTime(DateTime time, TimeZoneInfo zone = null, Boolean preciseTime = false) {
            m_encode(time, zone, preciseTime);
        }
        /// <summary>
        /// Initializes a new instance of the <strong>Asn1UtcTime</strong> class from an existing
        /// <see cref="Asn1Reader"/> object.
        /// </summary>
        /// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents UTC time.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// The current state of <strong>ASN1</strong> object is not UTC time.
        /// </exception>
        public Asn1UtcTime(Asn1Reader asn) : base(asn) {
            if (asn.Tag != TAG) {
                throw new Asn1InvalidTagException(String.Format(InvalidType, TYPE.ToString()));
            }
            m_decode(asn.GetTagRawData());
        }
        /// <summary>
        /// Initializes a new instance of the <strong>Asn1UtcTime</strong> class from a byte array that
        /// represents encoded UTC time.
        /// </summary>
        /// <param name="rawData">ASN.1-encoded byte array.</param>
        /// <exception cref="Asn1InvalidTagException">
        /// The current state of <strong>ASN1</strong> object is not UTC time.
        /// </exception>
        public Asn1UtcTime(Byte[] rawData) : base(new Asn1Reader(rawData)) {
            if (rawData[0] != TAG) {
                throw new Asn1InvalidTagException(String.Format(InvalidType, TYPE.ToString()));
            }
            m_decode(rawData);
        }

        void m_encode(DateTime time, TimeZoneInfo zone, Boolean preciseTime) {
            Value = time;
            ZoneInfo = zone;
            Initialize(new Asn1Reader(Asn1Utils.Encode(DateTimeUtils.Encode(time, zone, true, preciseTime), TAG)));
        }
        void m_decode(Byte[] rawData) {
            Asn1Reader asn = new Asn1Reader(rawData);
            Initialize(asn);
            Value = DateTimeUtils.Decode(asn, out TimeZoneInfo zoneInfo);
            ZoneInfo = zoneInfo;
        }

        /// <summary>
        /// Gets decoded date/time string value.
        /// </summary>
        /// <returns>Decoded date/time string value.</returns>
        public override String GetDisplayValue() {
            return Value.ToString(CultureInfo.InvariantCulture);
        }
    }
}
