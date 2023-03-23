using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;

namespace Asn1Parser.Tests;

[TestClass]
public class BinaryToHexStringTests {
    readonly System.Byte[] _rawData          = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    readonly System.Byte[] _rawDataTruncated = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const System.String HEX                  = "01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f 10";
    const System.String TRUNCATED_HEX        = "01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f";
    const System.String HEX_RAW              = "0102030405060708090a0b0c0d0e0f10";
    const System.String HEX_ADDR             = "0000    ";
    const System.String HEX_ASCII            = "   ................";
    const System.String TRUNCATED_HEX_ASCII  = "      ...............";

    [TestMethod]
    public void TestHex() {
        System.String str = AsnFormatter.BinaryToString(_rawData, EncodingType.Hex);
        Assert.AreEqual(HEX, str.TrimEnd());
        str = AsnFormatter.BinaryToString(_rawData, EncodingType.Hex, forceUpperCase: true);
        Assert.AreEqual(HEX.ToUpper(), str.TrimEnd());
    }
    [TestMethod]
    public void TestHexRaw() {
        System.String str = AsnFormatter.BinaryToString(_rawData);
        Assert.AreEqual(HEX_RAW, str.TrimEnd());
        str = AsnFormatter.BinaryToString(_rawData, forceUpperCase: true);
        Assert.AreEqual(HEX_RAW.ToUpper(), str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAddr() {
        System.String str = AsnFormatter.BinaryToString(_rawData, EncodingType.HexAddress);
        Assert.AreEqual(HEX_ADDR + HEX, str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAscii() {
        System.String str = AsnFormatter.BinaryToString(_rawData, EncodingType.HexAscii);
        Assert.AreEqual(HEX + HEX_ASCII, str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAddrAscii() {
        System.String str = AsnFormatter.BinaryToString(_rawData, EncodingType.HexAsciiAddress);
        Assert.AreEqual(HEX_ADDR + HEX + HEX_ASCII, str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAddrTruncated() {
        System.String str = AsnFormatter.BinaryToString(_rawDataTruncated, EncodingType.HexAddress);
        Assert.AreEqual(HEX_ADDR + TRUNCATED_HEX, str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAsciiTruncated() {
        System.String str = AsnFormatter.BinaryToString(_rawDataTruncated, EncodingType.HexAscii);
        Assert.AreEqual(TRUNCATED_HEX + TRUNCATED_HEX_ASCII, str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAddrAsciiTruncated() {
        System.String str = AsnFormatter.BinaryToString(_rawDataTruncated, EncodingType.HexAsciiAddress);
        Assert.AreEqual(HEX_ADDR + TRUNCATED_HEX + TRUNCATED_HEX_ASCII, str.TrimEnd());
    }
}