using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser.Universal;

namespace Asn1Parser.Tests; 
[TestClass]
public class Asn1BitStringTests {
    [TestMethod]
    public void TestUnusedBitsCalculator() {
        Byte unusedBits = Asn1BitString.CalculateUnusedBits([0x1]);
        Assert.AreEqual(0, unusedBits);
        unusedBits = Asn1BitString.CalculateUnusedBits([0x2]);
        Assert.AreEqual(1, unusedBits);
        unusedBits = Asn1BitString.CalculateUnusedBits([0x4]);
        Assert.AreEqual(2, unusedBits);
        unusedBits = Asn1BitString.CalculateUnusedBits([0x8]);
        Assert.AreEqual(3, unusedBits);
        unusedBits = Asn1BitString.CalculateUnusedBits([0x10]);
        Assert.AreEqual(4, unusedBits);
        unusedBits = Asn1BitString.CalculateUnusedBits([0x20]);
        Assert.AreEqual(5, unusedBits);
        unusedBits = Asn1BitString.CalculateUnusedBits([0x40]);
        Assert.AreEqual(6, unusedBits);
        unusedBits = Asn1BitString.CalculateUnusedBits([0x80]);
        Assert.AreEqual(7, unusedBits);
    }
    [TestMethod]
    public void TestBitStringDecodeFromByteArray() {
        Byte[] array = [3, 2, 5, 0xa0];
        var bitString = new Asn1BitString(array);
        Assert.AreEqual(5, bitString.UnusedBits);
        Assert.IsTrue(array.AsSpan().Slice(3,1).SequenceEqual(bitString.GetValue().Span));
        Assert.IsTrue(array.AsSpan().Slice(2, 2).SequenceEqual(bitString.GetPayloadAsMemory().Span));
        Assert.IsTrue(array.AsSpan().SequenceEqual(bitString.GetRawDataAsMemory().Span));
    }
}
