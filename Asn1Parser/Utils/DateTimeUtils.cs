using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

namespace SysadminsLV.Asn1Parser.Utils;

static class DateTimeUtils {
    public static Byte[] Encode(DateTime time, TimeZoneInfo? zone, Boolean UTC, Boolean usePrecise) {
        String suffix = String.Empty;
        String preValue;
        String format = UTC
            ? UTCFormat
            : GtFormat;
        if (usePrecise) {
            // encode milliseconds using minimum bytes, i.e. do not encode trailing zeros
            // in worst case, when milliseconds is zero, then omit entire fraction despite
            // it was requested. See ITU-T X.690, section 11.7
            suffix += (time.Millisecond / 1000d).ToString(CultureInfo.InvariantCulture).Substring(1);
        }
        zone = coerceTimeZone(zone);
        if (zone == null) {
            preValue = time.ToUniversalTime().ToString(format) + suffix + "Z";
        } else {
            suffix += zone.BaseUtcOffset is { Hours: >= 0, Minutes: >= 0 }
                ? "+"
                : "-";
            suffix +=
                Math.Abs(zone.BaseUtcOffset.Hours).ToString("d2") +
                Math.Abs(zone.BaseUtcOffset.Minutes).ToString("d2");
            preValue = time.ToString(format) + suffix;
        }
        Byte[] rawData = new Byte[preValue.Length];
        for (Int32 index = 0; index < preValue.Length; index++) {
            Char element = preValue[index];
            rawData[index] = Convert.ToByte(element);
        }
        return rawData;
    }
    // rawData is pure value without header
    public static DateTime Decode(Asn1Reader asn, out TimeZoneInfo? zone) {
        var SB = new StringBuilder();
        for (Int32 i = asn.PayloadStartOffset; i < asn.PayloadStartOffset + asn.PayloadLength; i++) {
            SB.Append(Convert.ToChar(asn[i]));
        }

        return extractDateTime(SB.ToString(), out zone);
    }
    
    static TimeZoneInfo? coerceTimeZone(TimeZoneInfo? zone) {
        // if zone is explicitly specified, but its offset against UTC is zero, we do not encode zone.
        if ((zone?.BaseUtcOffset.TotalMinutes ?? 0) == 0) {
            return null;
        }
        
        return zone;
    }
    static DateTime extractDateTime(String strValue, out TimeZoneInfo? zone) {
        zone = null;
        Boolean hasZone = extractZoneShift(strValue, out Int32 hours, out Int32 minutes, out Int32 zoneDelimiter);
        Int32 milliseconds = extractMilliseconds(strValue, zoneDelimiter, out Int32 msDelimiter);
        DateTime retValue = extractDateTime(strValue, msDelimiter, zoneDelimiter);
        if (hasZone) {
            zone = bindZone(hours, minutes);
            //retValue = retValue.AddHours(hours);
            //retValue = retValue.AddMinutes(minutes);
        } else {
            retValue = DateTime.SpecifyKind(retValue, DateTimeKind.Utc).ToLocalTime();
        }
        retValue = retValue.AddMilliseconds(milliseconds);

        return retValue;
    }
    static DateTime extractDateTime(String strValue, Int32 msDelimiter, Int32 zoneDelimiter) {
        String rawString;
        if (msDelimiter < 0 && zoneDelimiter < 0) {
            // Zulu time zone, no milliseconds
            rawString = strValue;
        } else if (msDelimiter < 0) {
            // Custom time zone, no milliseconds
            rawString = strValue.Substring(0, zoneDelimiter);
        } else {
            // Milliseconds
            rawString = strValue.Substring(0, msDelimiter);
        }

        return rawString.Length switch {
            12 => parseExactUtc(rawString, UTCFormat),
            14 => DateTime.ParseExact(rawString, GtFormat, null),
            _ => throw new ArgumentException("Time zone suffix is not valid.")
        };
    }
    static Boolean extractZoneShift(String strValue, out Int32 hours, out Int32 minutes, out Int32 delimiterIndex) {
        if (strValue.EndsWith("Z")) {
            delimiterIndex = strValue.IndexOf('Z');
            hours = minutes = 0;
            return false;
        }

        if (strValue.Contains('+')) {
            delimiterIndex = strValue.IndexOf('+');
            hours = Int32.Parse(strValue.Substring(delimiterIndex, 3));
        } else if (strValue.Contains('-')) {
            delimiterIndex = strValue.IndexOf('-');
            hours = -Int32.Parse(strValue.Substring(delimiterIndex, 3));
        } else {
            throw new InvalidDataException("ASN.1 DateTime has missing time zone identifier.");
        }
        minutes = strValue.Length > delimiterIndex + 3
            ? -Int32.Parse(strValue.Substring(delimiterIndex + 3, 2))
            : 0;

        return true;
    }
    static Int32 extractMilliseconds(String strValue, Int32 zoneDelimiter, out Int32 msDelimiter) {
        msDelimiter = -1;
        if (!strValue.Contains(".")) { return 0; }
        msDelimiter = strValue.IndexOf('.');
        Int32 precisionLength = zoneDelimiter > 0
            ? zoneDelimiter - msDelimiter - 1
            : strValue.Length - msDelimiter - 1;
        // milliseconds decimal part
        Int32 msNumber = Int32.Parse(strValue.Substring(msDelimiter + 1, precisionLength));
        // if precision length is 1, then msNumber represents milliseconds * 100
        // if precision length is 2, then msNumber represents milliseconds * 10
        // if precision length is 3, then msNumber represents milliseconds * 1
        // we can get this by: 100 * msNumber / 10 ^ precisionLength
        return (Int32)(msNumber / Math.Pow(10, precisionLength) * 1000);
    }
    static DateTime parseExactUtc(String strValue, params String[] format) {
        // fix: .NET 'yy' format works in range between 1930-2030. As per RFC5280,
        // dates must be between 1950-2049. In .NET, years between 30 and 50 are treated
        // as 1930-1950, while it should be 2030-2050. So, fix the range between 30 and 50
        // by adding a century.
        var dateTime = DateTime.ParseExact(strValue, format, null, DateTimeStyles.None);
        // not inclusive. Starting with 2050, GeneralizedTime is used, so 50+ values will go
        // to 21st century as in .NET
        if (dateTime.Year < 1950) {
            dateTime = dateTime.AddYears(100);
        }
        return dateTime;
    }
    static TimeZoneInfo bindZone(Int32 hours, Int32 minutes) {
        foreach (TimeZoneInfo zone in TimeZoneInfo.GetSystemTimeZones().Where(zone => zone.BaseUtcOffset.Hours == hours && zone.BaseUtcOffset.Minutes == minutes)) {
            return zone;
        }
        return TimeZoneInfo.FindSystemTimeZoneById("Greenwich Standard Time");
    }

    #region Constants
    const String UTCFormat        = "yyMMddHHmmss";
    const String GtFormat         = "yyyyMMddHHmmss";
    #endregion
}