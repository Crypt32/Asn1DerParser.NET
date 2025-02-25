using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser.Universal;

namespace Asn1Parser.Tests;

[TestClass]
public class Asn1OidTests {
    [TestMethod, Description("Test if at least two arcs are required.")]
    public void TestMinStringLength() {
        // must be 06 01 00
        testOidBiDirectional("0.0", "BgEA");
    }
    [TestMethod, Description("Test if single arc encoding fails.")]
    [ExpectedException(typeof(InvalidDataException))]
    public void TestSingleArcEncodeFail() {
        new Asn1ObjectIdentifier("0");
    }
    [TestMethod, Description("Test if 2nd arc under 'itu-t' root node encoded up to 39.")]
    public void TestItuRootArcConstraintsPass() {
        // must be 06 01 27
        testOidBiDirectional("0.39", "BgEn");
    }
    [TestMethod, Description("Test if 2nd arc under 'itu-t' root node >39 fails.")]
    [ExpectedException(typeof(InvalidDataException))]
    public void TestItuRootArcConstraintsFail() {
        new Asn1ObjectIdentifier("0.40");
    }
    [TestMethod, Description("Test if 2nd arc under 'iso' root node encoded up to 39.")]
    public void TestIsoRootArcConstraintsPass() {
        // must be 06 01 4f
        testOidBiDirectional("1.39", "BgFP");
    }
    [TestMethod, Description("Test if 2nd arc under 'iso' root node >39 fails.")]
    [ExpectedException(typeof(InvalidDataException))]
    public void TestIsoRootArcConstraintsFail() {
        new Asn1ObjectIdentifier("1.40");
    }
    [TestMethod, Description("Test if 2nd arc under 'joint-iso-itu-t' root do not impose 2nd arc limits.")]
    public void TestJointIsoItuRootArcPass() {
        // must be 06 01 78
        testOidBiDirectional("2.40", "BgF4");
    }
    [TestMethod, Description("Test random cert template OID, which includes short and long arcs")]
    public void TestCertTemplateOid() {
        testOidBiDirectional("1.3.6.1.4.1.311.21.8.149510.7314491.15746959.9320746.3700693.37.1.25", "Bh8rBgEEAYI3FQiJkAaDvrg7h8GPD4S48iqB4e9VJQEZ");
    }
    [TestMethod, Description("Test if first first two arcs can span multiple bytes if first byte >= 128")]
    public void TestLargeTopArcs() {
        // must be 06 01 50
        // OID 2.0 is identical to invalid 1.40, which is prohibited
        testOidBiDirectional("2.0", "BgFQ");
        // must be 06 02 88 37
        testOidBiDirectional("2.999", "BgKINw==");
        // must be 06 03 88 37 03
        testOidBiDirectional("2.999.3", "BgOINwM=");
        // must be 06 04 82 4B 09 79
        testOidBiDirectional("2.251.9.121", "BgSCSwl5");
        // must be 06 04 88 37 89 52
        testOidBiDirectional("2.999.1234", "BgSIN4lS");
        // must be 06 04 82 00 09 79
        testOidBiDirectional("2.176.9.121", "BgSCAAl5");
        // must be 06 04 79 00 09 79
        testOidBiDirectional("2.81.0.9.121", "BgWBIQAJeQ==");
    }

    static void testOidBiDirectional(String oidString, String expectedB64) {
        // test OID string -> binary encoding process
        var oid = new Asn1ObjectIdentifier(oidString);
        String encodedB64 = Convert.ToBase64String(oid.GetRawDataAsMemory().ToArray());
        Assert.AreEqual(expectedB64, encodedB64);
        // test binary -> OID string decoding process
        oid = new Asn1ObjectIdentifier(Convert.FromBase64String(expectedB64));
        Assert.AreEqual(oidString, oid.Value.Value);
    }
}
