using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;

namespace Asn1Parser.Tests;

[TestClass]
public class Asn1ReaderTests {
    [TestMethod]
    public void TestTruncatedSource() {
        var bb = new Byte[] { 48, 2, 5, 0 };
        var asn = new Asn1Reader(bb.AsMemory());
        bb[3] = 1;
    }
}
