using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser.Universal;

namespace Asn1Parser.Tests;

[TestClass]
public class Asn1OidTests {
    [TestMethod, Description("Test if at least two arcs are encoded.")]
    public void TestMinStringLengthEncode() {
        var oid = new Asn1ObjectIdentifier("0.0");
        Assert.AreEqual("0.0", oid.Value.Value);
        String encodedB64 = Convert.ToBase64String(oid.GetRawData());
        // must be 06 01 00
        Assert.AreEqual("BgEA", encodedB64);
    }
    [TestMethod, Description("Test if at least two arcs are required.")]
    public void TestMinStringLengthDecode() {
        Byte[] rawData = Convert.FromBase64String("BgEA");
        var oid = new Asn1ObjectIdentifier(rawData);
        Assert.AreEqual("0.0", oid.Value.Value);
        String encodedB64 = Convert.ToBase64String(oid.GetRawData());
        // must be 06 01 00
        Assert.AreEqual("BgEA", encodedB64);
    }
    [TestMethod, Description("Test if single arc encoding fails.")]
    [ExpectedException(typeof(InvalidDataException))]
    public void TestSingleArcEncodeFail() {
        new Asn1ObjectIdentifier("0");
    }
    [TestMethod, Description("Test if 2nd arc under 'itu-t' root node encoded up to 39.")]
    public void TestItuRootArcConstraintsPass() {
        new Asn1ObjectIdentifier("0.39");
    }
    [TestMethod, Description("Test if 2nd arc under 'itu-t' root node >39 fails.")]
    [ExpectedException(typeof(InvalidDataException))]
    public void TestItuRootArcConstraintsFail() {
        new Asn1ObjectIdentifier("0.40");
    }
    [TestMethod, Description("Test if 2nd arc under 'iso' root node encoded up to 39.")]
    public void TestIsoRootArcConstraintsPass() {
        new Asn1ObjectIdentifier("1.39");
    }
    [TestMethod, Description("Test if 2nd arc under 'iso' root node >39 fails.")]
    [ExpectedException(typeof(InvalidDataException))]
    public void TestIsoRootArcConstraintsFail() {
        new Asn1ObjectIdentifier("1.40");
    }
    [TestMethod, Description("Test if 2nd arc under 'joint-iso-itu-t' root do not impose 2nd arc limits.")]
    public void TestJointIsoItuRootArcPass() {
        new Asn1ObjectIdentifier("2.40");
    }
    [TestMethod, Description("Test if first first two arcs can span multiple bytes if first byte >= 128")]
    public void TestLargeTopArcs() {
        var oid = new Asn1ObjectIdentifier("2.999");
        String encodedB64 = Convert.ToBase64String(oid.GetRawData());
        // must be 06 02 88 37
        Assert.AreEqual("BgKINw==", encodedB64);

        oid = new Asn1ObjectIdentifier("2.999.3");
        encodedB64 = Convert.ToBase64String(oid.GetRawData());
        // must be 06 03 88 37 03
        Assert.AreEqual("BgOINwM=", encodedB64);

        oid = new Asn1ObjectIdentifier("2.251.9.121");
        encodedB64 = Convert.ToBase64String(oid.GetRawData());
        // must be 06 04 82 4B 09 79
        Assert.AreEqual("BgSCSwl5", encodedB64);

        oid = new Asn1ObjectIdentifier("2.999.1234");
        encodedB64 = Convert.ToBase64String(oid.GetRawData());
        // must be 06 04 88 37 89 52
        Assert.AreEqual("BgSIN4lS", encodedB64);

        oid = new Asn1ObjectIdentifier("2.176.9.121");
        encodedB64 = Convert.ToBase64String(oid.GetRawData());
        // must be 06 04 82 00 09 79
        Assert.AreEqual("BgSCAAl5", encodedB64);

        oid = new Asn1ObjectIdentifier("2.81.0.9.121");
        encodedB64 = Convert.ToBase64String(oid.GetRawData());
        // must be 06 04 79 00 09 79
        Assert.AreEqual("BgWBIQAJeQ==", encodedB64);
    }
}
