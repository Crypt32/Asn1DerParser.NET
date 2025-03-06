using System;
using System.IO;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;

namespace Asn1Parser.Tests;

[TestClass]
public class Base64StringToBinaryTests {
    readonly Byte[] _rawData = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    readonly String _base64;
    readonly EncodingType[] _b64Encodings = [
        EncodingType.Base64Header,
        EncodingType.PemCert,
        EncodingType.PemTrustedCert,
        EncodingType.PemNewReq,
        EncodingType.Base64RequestHeader,
        EncodingType.PemReq,
        EncodingType.Base64CrlHeader,
        EncodingType.PemEvpPrivateKey,
        EncodingType.PemPublicKey,
        EncodingType.PemRsaPrivateKey,
        EncodingType.PemRsaPublicKey,
        EncodingType.PemDsaPrivateKey,
        EncodingType.PemDsaPublicKey,
        EncodingType.PemPkcs7,
        EncodingType.PemPkcs7Signed,
        EncodingType.PemPkcs8Encrypted,
        EncodingType.PemPkcs8Inf,
        EncodingType.PemDHParams,
        EncodingType.PemDHXParams,
        EncodingType.PemSSLSessionParams,
        EncodingType.PemDsaParams,
        EncodingType.PemECDsaPublicKey,
        EncodingType.PemECParams,
        EncodingType.PemECPrivateKey,
        EncodingType.PemParams,
        EncodingType.PemCms
    ];
    public Base64StringToBinaryTests() {
        _base64 = Convert.ToBase64String(_rawData);
    }

    [TestMethod]
    public void TestBase64ToBinary() {
        Byte[] actual = AsnFormatter.StringToBinary(_base64);
        validateBinary(actual);
    }
    [TestMethod]
    public void TestBase64HeaderToBinaryStrictValid() {
        foreach (EncodingType encoding in _b64Encodings) {
            String input = AsnFormatter.BinaryToString(_rawData, encoding);
            Byte[] actual = AsnFormatter.StringToBinary(input, encoding);

            EncodingType expected;
            switch (encoding) {
                case EncodingType.Base64Header:
                    expected = EncodingType.PemCert;
                    break;
                case EncodingType.Base64RequestHeader:
                    expected = EncodingType.PemNewReq;
                    break;
                default:
                    expected = encoding;
                    break;
            }
            EncodingType suggestedEncoding = AsnFormatter.TestInputString(input);
            Assert.AreEqual(expected, suggestedEncoding);
            validateBinary(actual);
        }
    }
    [TestMethod, ExpectedException(typeof(InvalidDataException))]
    public void TestBase64HeaderToBinaryStrictInvalid() {
        AsnFormatter.StringToBinary(AsnFormatter.BinaryToString(_rawData, EncodingType.Base64CrlHeader), EncodingType.Base64Header);
    }
    [TestMethod]
    public void TestBase64AnyToBinary() {
        foreach (EncodingType encoding in _b64Encodings) {
            Byte[] actual = AsnFormatter.StringToBinary(AsnFormatter.BinaryToString(_rawData, encoding), EncodingType.Base64Any);
            validateBinary(actual);
        }
    }

    void validateBinary(Byte[] actual) {
        Assert.IsTrue(_rawData.SequenceEqual(actual));
    }

    [TestMethod]
    public void TestMismatchHeaderAndFooter() {
        String pem = $"""
                      -----BEGIN CERTIFICATE-----
                      {_base64}
                      -----END PKCS7-----
                      """;
        EncodingType encoding = AsnFormatter.TestInputString(pem);
        Assert.AreEqual(EncodingType.Base64Header, encoding);
    }
    [TestMethod]
    public void TestInvalidBase64() {
        String base64 = "Xblue";
        EncodingType encoding = AsnFormatter.TestInputString(base64);
        Assert.AreEqual(EncodingType.Binary, encoding);
    }
}