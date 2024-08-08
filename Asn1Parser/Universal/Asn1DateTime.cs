using System;
using System.Globalization;
using SysadminsLV.Asn1Parser.Utils;

namespace SysadminsLV.Asn1Parser.Universal;

/// <summary>
/// Represents base class for UTCTime and GeneralizedTime ASN.1 types
/// </summary>
public abstract class Asn1DateTime : Asn1Universal {
    /// <summary>
    /// Initializes a new instance of <strong>Asn1DateTime</strong> class.
    /// </summary>
    protected Asn1DateTime(Asn1Type type) : base(type) {
        if (type is not (Asn1Type.UTCTime or Asn1Type.GeneralizedTime)) {
            throw new ArgumentException("Invalid ASN type. Must be either, UTCTime or GeneralizedTime.");
        }
    }
    /// <summary>
    /// Initializes a new instance of <strong>Asn1DateTime</strong> class from an existing
    /// <see cref="Asn1Reader"/> object.
    /// </summary>
    /// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents ASN.1 date/time object.</param>
    /// <param name="type">Optional expected ASN.1 type.</param>
    protected Asn1DateTime(Asn1Reader asn, Asn1Type type) : base(asn, type) {
        if (type is not (Asn1Type.UTCTime or Asn1Type.GeneralizedTime)) {
            throw new ArgumentException("Invalid ASN type. Must be either, UTCTime or GeneralizedTime.");
        }
        m_decode(asn.GetTagRawData());
    }
    protected Asn1DateTime(Asn1Type type, DateTime time, TimeZoneInfo? zone = null, Boolean preciseTime = false) : this(type) {
        m_encode(type, time, zone, preciseTime);
    }

    /// <summary>
    /// Gets the optional time zone information for the current object. Local time zone is assumed if value is null.
    /// </summary>
    public TimeZoneInfo? ZoneInfo { get; protected set; }
    /// <summary>
    /// Gets date/time value associated with the current date/time object and adjusted to local time zone.
    /// </summary>
    public DateTime Value { get; protected set; }

    void m_encode(Asn1Type type, DateTime time, TimeZoneInfo? zone, Boolean preciseTime) {
        zone = DateTimeUtils.CoerceTimeZone(zone);
        time = zone == null
            ? DateTime.SpecifyKind(time, DateTimeKind.Local)
            : TimeZoneInfo.ConvertTimeToUtc(time, zone).ToLocalTime();
        Value = time;
        Boolean utcTime = type == Asn1Type.UTCTime;
        Initialize(new Asn1Reader(Asn1Utils.Encode(DateTimeUtils.Encode(time, ref zone, utcTime, preciseTime), type)));
        ZoneInfo = zone;
    }
    void m_decode(Byte[] rawData) {
        var asn = new Asn1Reader(rawData);
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

    /// <summary>
    /// Encodes a .NET DateTime object to a ASN.1-encoded byte array. This method is designed to conform
    /// <see href="http://tools.ietf.org/html/rfc5280">RFC 5280</see> requirement, so dates before 1950 and
    /// after 2050 year are required to be encoded by using Generalized Time encoding. UTC Time encoding is not allowed
    /// for periods beyond 1950 - 2049 years.
    /// </summary>
    /// <param name="time">
    /// An instance of <see cref="DateTime"/> object.</param> Value in this parameter is treated as local time. 
    /// <param name="zone">
    ///     Specifies the time zone for the value in <strong>time</strong> parameter.
    /// </param>
    /// <returns>ASN.1 type object.</returns>
    /// <remarks>
    ///     If the <strong>Year</strong> value of the <strong>time</strong> object is less or equals to 2049
    ///     and greater or equals to 1950, an <see cref="Asn1UtcTime"/> object is returned.
    ///     If year value is outside of 1950-2049 range, an <see cref="Asn1GeneralizedTime"/> object is returned.
    ///     <para>
    ///     If <strong>zone</strong> parameter is set to <strong>NULL</strong>, date and time in <strong>time</strong>
    ///     parameter will be converted to a Zulu time (Universal time). If zone information is not <strong>NULL</strong>,
    ///     date and time in <strong>time</strong> parameter will be converted to a GMT time and time zone will be added
    ///     to encoded value.
    ///     </para>
    /// </remarks>
    /// <seealso cref="Asn1UtcTime"/>
    /// <seealso cref="Asn1GeneralizedTime"/>
    public static Asn1DateTime CreateRfcDateTime(DateTime time, TimeZoneInfo zone = null) {
        if (time.Year is < 2050 and >= 1950) {
            return new Asn1UtcTime(time, zone);
        }

        return new Asn1GeneralizedTime(time, zone);
    }
    /// <summary>
    /// Gets an ASN.1 date/time instance from current position in ASN.1 reader.
    /// </summary>
    /// <param name="reader">ASN.1 reader that points to either, UTC time or generalized time.</param>
    /// <returns>An instance of <see cref="Asn1UtcTime"/> or <see cref="Asn1GeneralizedTime"/>.</returns>
    /// <exception cref="Asn1InvalidTagException">
    ///     ASN.1 reader points to non-date/time field.
    /// </exception>
    public static Asn1DateTime DecodeAnyDateTime(Asn1Reader reader) {
        return reader.Tag switch {
            (Byte)Asn1Type.UTCTime         => new Asn1UtcTime(reader),
            (Byte)Asn1Type.GeneralizedTime => new Asn1GeneralizedTime(reader),
            _                              => throw new Asn1InvalidTagException("Specified data is not valid ASN.1 date/time type.")
        };
    }
}