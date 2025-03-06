using System;
using System.Runtime.InteropServices;
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
        runTest(_rawData, EncodingType.Hex, HEX, true);
    }
    [TestMethod]
    public void TestHexRaw() {
        runTest(_rawData, EncodingType.HexRaw, HEX_RAW, true);
    }
    [TestMethod]
    public void TestHexAddr() {
        runTest(_rawData, EncodingType.HexAddress, HEX_ADDR + HEX, true);
    }
    [TestMethod]
    public void TestHexAscii() {
        runTest(_rawData, EncodingType.HexAscii, HEX + HEX_ASCII, true);
    }
    [TestMethod]
    public void TestHexAddrAscii() {
        runTest(_rawData, EncodingType.HexAsciiAddress, HEX_ADDR + HEX + HEX_ASCII, true);
    }
    [TestMethod]
    public void TestHexAddrTruncated() {
        runTest(_rawDataTruncated, EncodingType.HexAddress, HEX_ADDR + TRUNCATED_HEX, true);
    }
    [TestMethod]
    public void TestHexAsciiTruncated() {
        runTest(_rawDataTruncated, EncodingType.HexAscii, TRUNCATED_HEX + TRUNCATED_HEX_ASCII, true);
    }
    [TestMethod]
    public void TestHexAddrAsciiTruncated() {
        runTest(_rawDataTruncated, EncodingType.HexAsciiAddress, HEX_ADDR + TRUNCATED_HEX + TRUNCATED_HEX_ASCII, true);
    }

    [TestMethod]
    public void TestComplexHexRaw() {
        runTest(_complexRawData, EncodingType.HexRaw, COMPLEX_HEX_RAW, true);
    }
    [TestMethod]
    public void TestComplexHex() {
        runTest(_complexRawData, EncodingType.Hex, COMPLEX_HEX, true);
    }
    [TestMethod]
    public void TestComplexHexAddr() {
        runTest(_complexRawData, EncodingType.HexAddress, COMPLEX_HEX_ADDR, true);
    }
    [TestMethod]
    public void TestComplexHexAscii() {
        runTest(_complexRawData, EncodingType.HexAscii, COMPLEX_HEX_ASCII, false);
    }
    [TestMethod]
    public void TestComplexHexAddrAscii() {
        runTest(_complexRawData, EncodingType.HexAsciiAddress, COMPLEX_HEX_ADDR_ASCII, false);
    }

    void runTest(Byte[] rawData, EncodingType encoding, String expected, Boolean testUppercase) {
        String str = AsnFormatter.BinaryToString(rawData, encoding);
        Assert.AreEqual(expected, str.TrimEnd());
        EncodingType testedEncoding = AsnFormatter.TestInputString(str);
        EncodingType capiEncoding = tryCapiDecode(str);
        // commented for now. Need research for these tests 
        //Assert.AreEqual(encoding, testedEncoding);
        //Assert.AreEqual(capiEncoding, testedEncoding);
        if (testUppercase) {
            str = AsnFormatter.BinaryToString(rawData, encoding, forceUpperCase: true);
            Assert.AreEqual(expected.ToUpper(), str.TrimEnd());
        }
    }

    EncodingType tryCapiDecode(String s) {
        UInt32 pcbBinary = 0;
        if (!CryptStringToBinary(s, s.Length, 0x7, null, ref pcbBinary, out UInt32 pdwSkip, out EncodingType pdwFlags)) {
            Console.WriteLine(Marshal.GetLastWin32Error());
            return EncodingType.Binary;
        }

        return pdwFlags;
    }
    [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern Boolean CryptStringToBinary(
        [In] String pszString,
        [In] Int32 cchString,
        [In] UInt32 dwFlags,
        [In] Byte[]? pbBinary,
        [In, Out] ref UInt32 pcbBinary,
        [Out] out UInt32 pdwSkip,
        [Out] out EncodingType pdwFlags
    );
}