using System;

namespace SysadminsLV.Asn1Parser;

/// <summary>
/// This enumeration contains string formats used in CryptoAPI. See remarks for string formats examples.
/// </summary>
/// <remarks>
/// The following section displays example string formats.
/// 
/// <example><strong>Base64Header</strong>
/// <code>
/// -----BEGIN CERTIFICATE-----
/// MIIEITCCA+CgAwIBAgIUKMmxmDbjbHqt+Yzwj5lflBxuQwEwCQYHKoZIzjgEAzAjMSEwHwYDVQQD
/// ExhUb2tlbiBTaWduaW5nIFB1YmxpYyBLZXkwHhcNMTIxMTE2MTgzODMwWhcNMTIxMTIzMTgzODMw
/// WjAtMSswKQYDVQQDHiIAYgBiADEANAAxADkAYQAyAGMAZgBjADEAZQAwADAAOAAAMIGfMA0GCSqG
/// &lt;...&gt;
/// -----END CERTIFICATE-----
/// </code>
/// </example>
/// <example><strong>Base64</strong>
/// <code>
/// MIIEITCCA+CgAwIBAgIUKMmxmDbjbHqt+Yzwj5lflBxuQwEwCQYHKoZIzjgEAzAjMSEwHwYDVQQD
/// ExhUb2tlbiBTaWduaW5nIFB1YmxpYyBLZXkwHhcNMTIxMTE2MTgzODMwWhcNMTIxMTIzMTgzODMw
/// WjAtMSswKQYDVQQDHiIAYgBiADEANAAxADkAYQAyAGMAZgBjADEAZQAwADAAOAAAMIGfMA0GCSqG
/// &lt;...&gt;
/// </code>
/// </example>
/// <example><strong>Base64RequestHeader</strong>
/// <code>
/// -----BEGIN NEW CERTIFICATE REQUEST-----
/// MIIDBjCCAm8CAQAwcTERMA8GA1UEAxMIcXV1eC5jb20xDzANBgNVBAsTBkJyYWlu
/// czEWMBQGA1UEChMNRGV2ZWxvcE1lbnRvcjERMA8GA1UEBxMIVG9ycmFuY2UxEzAR
/// BgNVBAgTCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVTMIGfMA0GCSqGSIb3DQEBAQUA
/// &lt;...&gt;
/// -----END NEW CERTIFICATE REQUEST-----
/// </code>
/// </example>
/// <example><strong>Hex</strong>
/// <code>
/// 3a 20 63 65 72 74 6c 69  62 5c 6c 64 61 70 2e 63
/// 70 70 28 32 31 33 31 29  3a 20 6c 64 61 70 65 72
/// &lt;...&gt;
/// </code>
/// </example>
/// <example><strong>HexAscii</strong>
/// <code>
/// 3a 20 63 65 72 74 6c 69  62 5c 6c 64 61 70 2e 63   : certlib\ldap.c
/// 70 70 28 32 31 33 31 29  3a 20 6c 64 61 70 65 72   pp(2131): ldaper
/// &lt;...&gt;
/// </code>
/// </example>
/// <example><strong>Base64CrlHeader</strong>
/// <code>
/// -----BEGIN X509 CRL-----
/// MIIDBjCCAm8CAQAwcTERMA8GA1UEAxMIcXV1eC5jb20xDzANBgNVBAsTBkJyYWlu
/// czEWMBQGA1UEChMNRGV2ZWxvcE1lbnRvcjERMA8GA1UEBxMIVG9ycmFuY2UxEzAR
/// BgNVBAgTCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVTMIGfMA0GCSqGSIb3DQEBAQUA
/// &lt;...&gt;
/// -----END X509 CRL-----
/// </code>
/// </example>
/// <example><strong>HexAddress</strong>
/// <code>
/// 0000  3a 20 63 65 72 74 6c 69  62 5c 6c 64 61 70 2e 63
/// 0010  70 70 28 32 31 33 31 29  3a 20 6c 64 61 70 65 72
/// &lt;...&gt;
/// </code>
/// </example>
/// <example><strong>HexAsciiAddress</strong>
/// <code>
/// 0000  3a 20 63 65 72 74 6c 69  62 5c 6c 64 61 70 2e 63   : certlib\ldap.c
/// 0010  70 70 28 32 31 33 31 29  3a 20 6c 64 61 70 65 72   pp(2131): ldaper
/// &lt;...&gt;
/// </code>
/// </example>
/// <example><strong>HexRaw</strong>
/// <code>
/// 3a20636572746c69625c6c6461702e6370702832313331293a206c6461706572&lt;...&gt;
/// </code>
/// </example>
/// </remarks>
public enum EncodingType : UInt32 {
    /// <summary>
    /// Base64, with certificate beginning and ending headers.
    /// This enumeration value is identical to <strong>PemCert</strong> value.
    /// </summary>
    Base64Header = 0,
    /// <summary>
    /// Base64, without headers.
    /// </summary>
    Base64              = 1,
    /// <summary>
    /// Pure binary copy.
    /// </summary>
    Binary              = 2,
    /// <summary>
    /// The string is base64 encoded with beginning and ending certificate request headers.
    /// This enumeration value is identical to <strong>PemNewReq</strong> value.
    /// </summary>
    Base64RequestHeader = 3,
    /// <summary>
    /// Hexadecimal only format.
    /// </summary>
    Hex                 = 4,
    /// <summary>
    /// Hexadecimal format with ASCII character display.
    /// </summary>
    HexAscii            = 5,
    /// <summary>
    /// Tries the following, in order:
    /// <list type="bullet">
    /// <item>Base64Header</item>
    /// <item>Base64</item>
    /// </list>
    /// <strong><see cref="AsnFormatter.BinaryToString(ReadOnlySpan{Byte}, EncodingType, EncodingFormat, Boolean)">BinaryToString</see></strong> method do not support this flag.
    /// </summary>
    Base64Any = 6,
    /// <summary>
    /// Tries the following, in order:
    /// <list type="bullet">
    /// <item>Base64Header</item>
    /// <item>Base64</item>
    /// <item>Binary</item>
    /// </list>
    /// <strong><see cref="AsnFormatter.BinaryToString(ReadOnlySpan{Byte}, EncodingType, EncodingFormat, Boolean)">BinaryToString</see></strong> method do not support this flag.
    /// </summary>
    StringAny = 7,
    /// <summary>
    /// <list type="bullet">
    /// Tries the following, in order:
    /// <item>HexAddress</item>
    /// <item>HexAsciiAddress</item>
    /// <item>Hex</item>
    /// <item>HexRaw</item>
    /// <item>HexAscii</item>
    /// </list>
    /// <strong><see cref="AsnFormatter.BinaryToString(ReadOnlySpan{Byte}, EncodingType, EncodingFormat, Boolean)">BinaryToString</see></strong> method do not support this flag.
    /// </summary>
    HexAny = 8,
    /// <summary>
    /// Base64, with X.509 certificate revocation list (CRL) beginning and ending headers.
    /// </summary>
    Base64CrlHeader     = 9,
    /// <summary>
    /// Hex, with address display.
    /// </summary>
    HexAddress          = 10,
    /// <summary>
    /// Hex, with ASCII character and address display.
    /// </summary>
    HexAsciiAddress     = 11,
    /// <summary>
    /// A raw hexadecimal string.
    /// </summary>
    HexRaw              = 12,
    /// <summary>
    /// Base64, with trusted certificate beginning and ending headers.
    /// This enumeration value is identical to <strong>Base64Header</strong> value.
    /// </summary>
    PemCert             = 21,
    /// <summary>
    /// Base64, with trusted certificate beginning and ending headers.
    /// </summary>
    PemTrustedCert      = 22,
    /// <summary>
    /// Base64, with new certificate request beginning and ending headers.
    /// This enumeration value is identical to <strong>Base64RequestHeader</strong> value.
    /// </summary>
    PemNewReq           = 23,
    /// <summary>
    /// Base64, with certificate request beginning and ending headers.
    /// </summary>
    PemReq              = 24,
    /// <summary>
    /// Base64, with envelope (EnVeloPe) beginning and ending headers.
    /// </summary>
    PemEvpPrivateKey    = 26,
    /// <summary>
    /// Base64, with public key beginning and ending headers.
    /// </summary>
    PemPublicKey        = 27,
    /// <summary>
    /// Base64, with RSA private key beginning and ending headers.
    /// </summary>
    PemRsaPrivateKey    = 28,
    /// <summary>
    /// Base64, with RSA public key beginning and ending headers.
    /// </summary>
    PemRsaPublicKey     = 29,
    /// <summary>
    /// Base64, with DSA private key beginning and ending headers.
    /// </summary>
    PemDsaPrivateKey    = 30,
    /// <summary>
    /// Base64, with DSA public key beginning and ending headers.
    /// </summary>
    PemDsaPublicKey     = 31,
    /// <summary>
    /// Base64, with PKCS#7 beginning and ending headers.
    /// </summary>
    PemPkcs7            = 32,
    /// <summary>
    /// Base64, with signed PKCS#7 public key beginning and ending headers.
    /// </summary>
    PemPkcs7Signed      = 33,
    /// <summary>
    /// Base64, with encrypted PKCS#8 private key beginning and ending headers.
    /// </summary>
    PemPkcs8Encrypted   = 34,
    /// <summary>
    /// Base64, with unencrypted PKCS#8 private key beginning and ending headers.
    /// </summary>
    PemPkcs8Inf         = 35,
    /// <summary>
    /// Base64, with Diffie-Hellman (DH) parameters beginning and ending headers.
    /// </summary>
    PemDHParams         = 36,
    /// <summary>
    /// Base64, with X9.42 Diffie-Hellman (DH) beginning and ending headers.
    /// </summary>
    PemDHXParams        = 37,
    /// <summary>
    /// Base64, with SSL session parameters beginning and ending headers.
    /// </summary>
    PemSSLSessionParams = 38,
    /// <summary>
    /// Base64, with DSA parameters beginning and ending headers.
    /// </summary>
    PemDsaParams        = 39,
    /// <summary>
    /// Base64, with ECDSA public key beginning and ending headers.
    /// </summary>
    PemECDsaPublicKey   = 40,
    /// <summary>
    /// Base64, with EC parameters beginning and ending headers.
    /// </summary>
    PemECParams         = 41,
    /// <summary>
    /// Base64, with ECDSA private key beginning and ending headers.
    /// </summary>
    PemECPrivateKey     = 42,
    /// <summary>
    /// Base64, with parameters beginning and ending headers.
    /// </summary>
    PemParams           = 43,
    /// <summary>
    /// Base64, with cryptographic message syntax (CMS) beginning and ending headers.
    /// </summary>
    PemCms              = 44,

    ///// <summary>
    ///// Set this flag for Base64 data to specify that the end of the binary data contain only white space and at most
    ///// three equals "=" signs.
    ///// </summary>
    //CRYPT_STRING_STRICT = 0x20000000,

}