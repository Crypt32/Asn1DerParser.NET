using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;

namespace Asn1Parser.Tests;

[TestClass]
public class Asn1UtilsTests {
    [TestMethod]
    public void TestGetLengthBytes() {
        ReadOnlyMemory<Byte> lenBytes = Asn1Utils.GetLengthBytesAsMemory(0);
        Assert.AreEqual(1, lenBytes.Length);
        Assert.IsTrue(lenBytes.Span.SequenceEqual(new Byte[] { 0 }));

        lenBytes = Asn1Utils.GetLengthBytesAsMemory(127);
        Assert.AreEqual(1, lenBytes.Length);
        Assert.IsTrue(lenBytes.Span.SequenceEqual(new Byte[] { 127 }));

        lenBytes = Asn1Utils.GetLengthBytesAsMemory(128);
        Assert.AreEqual(2, lenBytes.Length);
        Assert.IsTrue(lenBytes.Span.SequenceEqual(new Byte[] { 129, 128 }));

        lenBytes = Asn1Utils.GetLengthBytesAsMemory(255);
        Assert.AreEqual(2, lenBytes.Length);
        Assert.IsTrue(lenBytes.Span.SequenceEqual(new Byte[] { 129, 255 }));

        lenBytes = Asn1Utils.GetLengthBytesAsMemory(256);
        Assert.AreEqual(3, lenBytes.Length);
        Assert.IsTrue(lenBytes.Span.SequenceEqual(new Byte[] { 130, 1, 0 }));

        lenBytes = Asn1Utils.GetLengthBytesAsMemory(100000);
        Assert.AreEqual(4, lenBytes.Length);
        Assert.IsTrue(lenBytes.Span.SequenceEqual(new Byte[] { 131, 1, 134, 160 }));
    }

    [TestMethod]
    public void TestCalculatePayloadLength() {
        Int64 length = Asn1Utils.CalculatePayloadLength([0]);
        Assert.AreEqual(0, length);

        length = Asn1Utils.CalculatePayloadLength([127]);
        Assert.AreEqual(127, length);

        length = Asn1Utils.CalculatePayloadLength([129, 128]);
        Assert.AreEqual(128, length);

        length = Asn1Utils.CalculatePayloadLength([129, 255]);
        Assert.AreEqual(255, length);

        length = Asn1Utils.CalculatePayloadLength([130, 1, 0]);
        Assert.AreEqual(256, length);

        length = Asn1Utils.CalculatePayloadLength([131, 1, 134, 160]);
        Assert.AreEqual(100000, length);
    }

    [TestMethod]
    public void TestEncode() {
        Byte[] array = new Byte[130];
        for (Int32 i = 0; i < array.Length; i++) {
            array[i] = (Byte)i;
        }

        ReadOnlyMemory<Byte> encoded = Asn1Utils.Encode(array.AsSpan(), Asn1Type.OCTET_STRING);
        var list = new List<Byte>([4, 129, 130]);
        list.AddRange(array);
        
        Assert.AreEqual(list.Count, encoded.Length);
        Assert.IsTrue(encoded.Span.SequenceEqual(list.ToArray()));
    }
}
