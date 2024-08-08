using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace Asn1Parser.Tests;

[TestClass]
public class Asn1DateTimeTests {
    [TestMethod, Description("Tests date/time parsing using ")]
    public void TestZuluSimple() {
        var dt = DateTime.ParseExact("2024-08-07 16:12:37", "yyyy-MM-dd HH:mm:ss", null);
        var gt = new Asn1GeneralizedTime(dt);
        assertDateTimeEncode(Asn1Type.GeneralizedTime, gt, dt, "yyyyMMddHHmmssZ");
    }
    [TestMethod, Description("Test date/time with fractions and fraction is zero")]
    public void TestZuluFraction0() {
        var dt = DateTime.ParseExact("2024-08-07 16:12:37.0", "yyyy-MM-dd HH:mm:ss.f", null);
        var gt = new Asn1GeneralizedTime(dt, true);
        assertDateTimeEncode(Asn1Type.GeneralizedTime, gt, dt, "yyyyMMddHHmmssZ");
    }
    [TestMethod]
    public void TestZuluFraction1() {
        var dt = DateTime.ParseExact("2024-08-07 16:12:37.1", "yyyy-MM-dd HH:mm:ss.f", null);
        var gt = new Asn1GeneralizedTime(dt, true);
        assertDateTimeEncode(Asn1Type.GeneralizedTime, gt, dt, "yyyyMMddHHmmss.fZ");
    }
    [TestMethod]
    public void TestZuluFraction2() {
        var dt = DateTime.ParseExact("2024-08-07 16:12:37.15", "yyyy-MM-dd HH:mm:ss.ff", null);
        var gt = new Asn1GeneralizedTime(dt, true);
        assertDateTimeEncode(Asn1Type.GeneralizedTime, gt, dt, "yyyyMMddHHmmss.ffZ");
    }
    [TestMethod]
    public void TestZuluFraction3() {
        var dt = DateTime.ParseExact("2024-08-07 16:12:37.153", "yyyy-MM-dd HH:mm:ss.fff", null);
        var gt = new Asn1GeneralizedTime(dt, true);
        assertDateTimeEncode(Asn1Type.GeneralizedTime, gt, dt, "yyyyMMddHHmmss.fffZ");
    }
    [TestMethod]
    public void TestTimeZone() {
        var zone = TimeZoneInfo.FindSystemTimeZoneById("FLE Standard Time");
        var dt = DateTime.ParseExact("2024-08-07 16:12:37", "yyyy-MM-dd HH:mm:ss", null);
        var gt = new Asn1GeneralizedTime(dt, zone);
        assertDateTimeEncode(Asn1Type.GeneralizedTime, gt, dt, "yyyyMMddHHmmss+0200");
    }
    [TestMethod]
    public void TestTimeZoneFraction() {
        var zone = TimeZoneInfo.FindSystemTimeZoneById("FLE Standard Time");
        var dt = DateTime.ParseExact("2024-08-07 16:12:37.15", "yyyy-MM-dd HH:mm:ss.ff", null);
        var gt = new Asn1GeneralizedTime(dt, zone, true);
        assertDateTimeEncode(Asn1Type.GeneralizedTime, gt, dt, "yyyyMMddHHmmss.ff+0200");
    }

    static void assertDateTimeEncode(Asn1Type expectedType, Asn1DateTime adt, DateTime dt, String expectedFormat, Boolean decode = false) {
        // assert type
        Assert.AreEqual((Byte)expectedType, adt.Tag);
        Assert.AreEqual(DateTimeKind.Local, adt.Value.Kind);

        String gts = Encoding.ASCII.GetString(adt.GetRawData().Skip(2).ToArray());
        Assert.AreEqual(dt, adt.Value);
        if (adt.ZoneInfo == null) {
            dt = dt.ToUniversalTime();
        }
        Assert.AreEqual(dt.ToString(expectedFormat), gts);
        if (!decode) {
            if (adt.ZoneInfo == null) {
                dt = dt.ToLocalTime();
            }
            assertDateTimeDecode(expectedType, adt, dt, expectedFormat);
        }
    }
    static void assertDateTimeDecode(Asn1Type expectedTime, Asn1DateTime adt, DateTime dt, String expectedFormat) {
        adt = expectedTime == Asn1Type.UTCTime
            ? new Asn1UtcTime(adt.GetRawData())
            : new Asn1GeneralizedTime(adt.GetRawData());
        assertDateTimeEncode(expectedTime, adt, dt, expectedFormat, true);
    }
}
