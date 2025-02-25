using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser.Universal;

namespace Asn1Parser.Tests;

[TestClass]
public class Asn1RelativeOidTests {
    [TestMethod, Description("Tests single-arc, single-byte relative oid.")]
    public void TestSingleArcShortOid() {
        testOidBiDirectional("127", "DQF/");
    }
    [TestMethod, Description("Tests single-arc, multi-byte relative oid.")]
    public void TestSingleArcLongOid() {
        testOidBiDirectional("1234567890", "DQWEzNiFUg==");
    }
    [TestMethod, Description("Tests multi-arc, single-byte (each arc) relative oid.")]
    public void TestMultiArcShortOid() {
        testOidBiDirectional("127.127", "DQJ/fw==");
    }
    [TestMethod, Description("Tests multi-arc, single-byte (each arc) relative oid with leading dot.")]
    public void TestMultiArcShortLeadingDotOid() {
        testOidBiDirectional(".127.127", "DQJ/fw==");
    }
    [TestMethod, Description("Tests multi-arc, multi-byte (each arc) relative oid.")]
    public void TestMultiArcLongOid() {
        testOidBiDirectional("1234567890.1234567890", "DQqEzNiFUoTM2IVS");
    }
    [TestMethod, Description("Tests null oid, should throw null reference.")]
    [ExpectedException(typeof(ArgumentNullException))]
    public void TestRelativeOidNull() {
        testOidBiDirectional(null, String.Empty);
    }
    [TestMethod, Description("Tests junk oid, should throw")]
    [ExpectedException(typeof(FormatException))]
    public void TestRelativeOidJunk() {
        testOidBiDirectional("junk", String.Empty);
    }

    static void testOidBiDirectional(String oidString, String expectedB64) {
        // test OID string -> binary encoding process
        var oid = new Asn1RelativeOid(oidString);
        String encodedB64 = Convert.ToBase64String(oid.GetRawDataAsMemory().ToArray());
        Assert.AreEqual(expectedB64, encodedB64);
        if (oidString.StartsWith('.')) {
            Assert.AreEqual(oidString, oid.Value);
        } else {
            Assert.AreEqual("." + oidString, oid.Value);
        }
        
        // test binary -> OID string decoding process
        oid = new Asn1RelativeOid(Convert.FromBase64String(expectedB64));
        if (oidString.StartsWith('.')) {
            Assert.AreEqual(oidString, oid.Value);
        } else {
            Assert.AreEqual("." + oidString, oid.Value);
        }
    }
}
