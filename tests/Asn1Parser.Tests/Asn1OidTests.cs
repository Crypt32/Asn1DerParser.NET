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
        Assert.AreEqual("BgEA", encodedB64);
    }
    [TestMethod, Description("Test if at least two arcs are required.")]
    public void TestMinStringLengthDecode() {
        Byte[] rawData = Convert.FromBase64String("BgEA");
        var oid = new Asn1ObjectIdentifier(rawData);
        Assert.AreEqual("0.0", oid.Value.Value);
        String encodedB64 = Convert.ToBase64String(oid.GetRawData());
        Assert.AreEqual("BgEA", encodedB64);
    }
    [TestMethod, Description("Test if single arc encoding fails.")]
    [ExpectedException(typeof(InvalidDataException))]
    public void TestSingleArcEncodeFail() {
        new Asn1ObjectIdentifier("0");
    }
    [TestMethod, Description("Test if 2nd arc under 'ITU' root node encoded up to 39.")]
    public void TestItuRootArcConstraintsPass() {
        new Asn1ObjectIdentifier("1.39");
    }
    [TestMethod, Description("Test if 2nd arc under 'ITU' root node >39 fails.")]
    [ExpectedException(typeof(InvalidDataException))]
    public void TestItuRootArcConstraintsFail() {
        new Asn1ObjectIdentifier("1.40");
    }
}
