using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;

namespace Asn1Parser.Tests;

[TestClass]
public class BinaryToBase64StringTests {
    readonly Byte[] _rawData = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    readonly String _base64;

    public BinaryToBase64StringTests() {
        _base64 = Convert.ToBase64String(_rawData);
    }
    
    [TestMethod]
    public void TestBinaryToBase64WithCRLF() {
        String str = AsnFormatter.BinaryToString(_rawData, EncodingType.Base64);
        Assert.IsNotNull(str);
        Assert.AreEqual(_base64 + Environment.NewLine, str);
    }
    [TestMethod]
    public void TestBinaryToBase64WithLF() {
        String str = AsnFormatter.BinaryToString(_rawData, EncodingType.Base64, EncodingFormat.NOCR);
        Assert.AreEqual(_base64 + "\n", str);
    }
    [TestMethod]
    public void TestBinaryToBase64With() {
        String str = AsnFormatter.BinaryToString(_rawData, EncodingType.Base64, EncodingFormat.NOCRLF);
        Assert.AreEqual(_base64, str);
    }
    [TestMethod]
    public void TestBinaryToStringWithHeader() {
        String str = AsnFormatter.BinaryToString(_rawData, EncodingType.Base64Header);
        validateHeader(str.TrimEnd(), "CERTIFICATE");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemCert);
        validateHeader(str.TrimEnd(), "CERTIFICATE");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemTrustedCert);
        validateHeader(str.TrimEnd(), "TRUSTED CERTIFICATE");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.Base64RequestHeader);
        validateHeader(str.TrimEnd(), "NEW CERTIFICATE REQUEST");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemNewReq);
        validateHeader(str.TrimEnd(), "NEW CERTIFICATE REQUEST");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemReq);
        validateHeader(str.TrimEnd(), "CERTIFICATE REQUEST");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.Base64CrlHeader);
        validateHeader(str.TrimEnd(), "X509 CRL");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemEvpPrivateKey);
        validateHeader(str.TrimEnd(), "ANY PRIVATE KEY");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemPublicKey);
        validateHeader(str.TrimEnd(), "PUBLIC KEY");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemRsaPrivateKey);
        validateHeader(str.TrimEnd(), "RSA PRIVATE KEY");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemRsaPublicKey);
        validateHeader(str.TrimEnd(), "RSA PUBLIC KEY");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemDsaPrivateKey);
        validateHeader(str.TrimEnd(), "DSA PRIVATE KEY");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemDsaPublicKey);
        validateHeader(str.TrimEnd(), "DSA PUBLIC KEY");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemPkcs7);
        validateHeader(str.TrimEnd(), "PKCS7");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemPkcs7Signed);
        validateHeader(str.TrimEnd(), "PKCS #7 SIGNED DATA");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemPkcs8Encrypted);
        validateHeader(str.TrimEnd(), "ENCRYPTED PRIVATE KEY");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemPkcs8Inf);
        validateHeader(str.TrimEnd(), "PRIVATE KEY");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemDHParams);
        validateHeader(str.TrimEnd(), "DH PARAMETERS");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemDHXParams);
        validateHeader(str.TrimEnd(), "X9.42 DH PARAMETERS");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemSSLSessionParams);
        validateHeader(str.TrimEnd(), "SSL SESSION PARAMETERS");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemDsaParams);
        validateHeader(str.TrimEnd(), "DSA PARAMETERS");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemECDsaPublicKey);
        validateHeader(str.TrimEnd(), "ECDSA PUBLIC KEY");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemECParams);
        validateHeader(str.TrimEnd(), "EC PARAMETERS");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemECPrivateKey);
        validateHeader(str.TrimEnd(), "EC PRIVATE KEY");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemParams);
        validateHeader(str.TrimEnd(), "PARAMETERS");

        str = AsnFormatter.BinaryToString(_rawData, EncodingType.PemCms);
        validateHeader(str.TrimEnd(), "CMS");
    }

    void validateHeader(String pemString, String pemHeaderText) {
        String headerString = "-----BEGIN " + pemHeaderText + "-----";
        String footerString = "-----END " + pemHeaderText + "-----";
        Assert.IsTrue(pemString.StartsWith(headerString));
        Assert.IsTrue(pemString.EndsWith(footerString));
    }
}