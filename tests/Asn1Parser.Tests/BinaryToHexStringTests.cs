using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;

namespace Asn1Parser.Tests;

[TestClass]
public class BinaryToHexStringTests {
    readonly Byte[] _rawData          = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    readonly Byte[] _rawDataTruncated = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    readonly Byte[] _complexRawData = Convert.FromBase64String("BiQrBgEEAYI3FQiWnU2FkrJ4vZ88hejsdILO2ER6gqr3QofnxDY=");
    const String HEX                  = "01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f 10";
    const String TRUNCATED_HEX        = "01 02 03 04 05 06 07 08  09 0a 0b 0c 0d 0e 0f";
    const String HEX_RAW              = "0102030405060708090a0b0c0d0e0f10";
    const String HEX_ADDR             = "0000    ";
    const String HEX_ASCII            = "   ................";
    const String TRUNCATED_HEX_ASCII  = "      ...............";
    const String COMPLEX_HEX_RAW = "06242b0601040182371508969d4d8592b278bd9f3c85e8ec7482ced8447a82aaf74287e7c436";
    const String COMPLEX_HEX = """
                               06 24 2b 06 01 04 01 82  37 15 08 96 9d 4d 85 92
                               b2 78 bd 9f 3c 85 e8 ec  74 82 ce d8 44 7a 82 aa
                               f7 42 87 e7 c4 36
                               """;
    const String COMPLEX_HEX_ADDR = """
                                    0000    06 24 2b 06 01 04 01 82  37 15 08 96 9d 4d 85 92
                                    0010    b2 78 bd 9f 3c 85 e8 ec  74 82 ce d8 44 7a 82 aa
                                    0020    f7 42 87 e7 c4 36
                                    """;
    const String COMPLEX_HEX_ASCII = """
                                     06 24 2b 06 01 04 01 82  37 15 08 96 9d 4d 85 92   .$+.....7....M..
                                     b2 78 bd 9f 3c 85 e8 ec  74 82 ce d8 44 7a 82 aa   .x..<...t...Dz..
                                     f7 42 87 e7 c4 36                                  .B...6
                                     """;
    const String COMPLEX_HEX_ADDR_ASCII = """
                                          0000    06 24 2b 06 01 04 01 82  37 15 08 96 9d 4d 85 92   .$+.....7....M..
                                          0010    b2 78 bd 9f 3c 85 e8 ec  74 82 ce d8 44 7a 82 aa   .x..<...t...Dz..
                                          0020    f7 42 87 e7 c4 36                                  .B...6
                                          """;

    [TestMethod]
    public void TestHex() {
        String str = AsnFormatter.BinaryToString(_rawData, EncodingType.Hex);
        Assert.AreEqual(HEX, str.TrimEnd());
        str = AsnFormatter.BinaryToString(_rawData, EncodingType.Hex, forceUpperCase: true);
        Assert.AreEqual(HEX.ToUpper(), str.TrimEnd());
    }
    [TestMethod]
    public void TestHexRaw() {
        String str = AsnFormatter.BinaryToString(_rawData);
        Assert.AreEqual(HEX_RAW, str.TrimEnd());
        str = AsnFormatter.BinaryToString(_rawData, forceUpperCase: true);
        Assert.AreEqual(HEX_RAW.ToUpper(), str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAddr() {
        String str = AsnFormatter.BinaryToString(_rawData, EncodingType.HexAddress);
        Assert.AreEqual(HEX_ADDR + HEX, str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAscii() {
        String str = AsnFormatter.BinaryToString(_rawData, EncodingType.HexAscii);
        Assert.AreEqual(HEX + HEX_ASCII, str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAddrAscii() {
        String str = AsnFormatter.BinaryToString(_rawData, EncodingType.HexAsciiAddress);
        Assert.AreEqual(HEX_ADDR + HEX + HEX_ASCII, str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAddrTruncated() {
        String str = AsnFormatter.BinaryToString(_rawDataTruncated, EncodingType.HexAddress);
        Assert.AreEqual(HEX_ADDR + TRUNCATED_HEX, str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAsciiTruncated() {
        String str = AsnFormatter.BinaryToString(_rawDataTruncated, EncodingType.HexAscii);
        Assert.AreEqual(TRUNCATED_HEX + TRUNCATED_HEX_ASCII, str.TrimEnd());
    }
    [TestMethod]
    public void TestHexAddrAsciiTruncated() {
        String str = AsnFormatter.BinaryToString(_rawDataTruncated, EncodingType.HexAsciiAddress);
        Assert.AreEqual(HEX_ADDR + TRUNCATED_HEX + TRUNCATED_HEX_ASCII, str.TrimEnd());
    }

    [TestMethod]
    public void TestComplexHexRaw() {
        String str = AsnFormatter.BinaryToString(_complexRawData);
        Assert.AreEqual(COMPLEX_HEX_RAW, str.TrimEnd());
        str = AsnFormatter.BinaryToString(_complexRawData, forceUpperCase: true);
        Assert.AreEqual(COMPLEX_HEX_RAW.ToUpper(), str.TrimEnd());
    }
    [TestMethod]
    public void TestComplexHex() {
        String str = AsnFormatter.BinaryToString(_complexRawData, EncodingType.Hex);
        Assert.AreEqual(COMPLEX_HEX, str.TrimEnd());
        str = AsnFormatter.BinaryToString(_complexRawData, EncodingType.Hex, forceUpperCase: true);
        Assert.AreEqual(COMPLEX_HEX.ToUpper(), str.TrimEnd());
    }
    [TestMethod]
    public void TestComplexHexAddr() {
        String str = AsnFormatter.BinaryToString(_complexRawData, EncodingType.HexAddress);
        Assert.AreEqual(COMPLEX_HEX_ADDR, str.TrimEnd());
        str = AsnFormatter.BinaryToString(_complexRawData, EncodingType.HexAddress, forceUpperCase: true);
        Assert.AreEqual(COMPLEX_HEX_ADDR.ToUpper(), str.TrimEnd());
    }
    [TestMethod]
    public void TestComplexHexAscii() {
        String str = AsnFormatter.BinaryToString(_complexRawData, EncodingType.HexAscii);
        Assert.AreEqual(COMPLEX_HEX_ASCII, str.TrimEnd());
    }
    [TestMethod]
    public void TestComplexHexAddrAscii() {
        String str = AsnFormatter.BinaryToString(_complexRawData, EncodingType.HexAsciiAddress);
        Assert.AreEqual(COMPLEX_HEX_ADDR_ASCII, str.TrimEnd());
    }
}