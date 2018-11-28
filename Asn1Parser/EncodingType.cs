namespace SysadminsLV.Asn1Parser {
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
    public enum EncodingType : uint {
        /// <summary>
        /// Base64, with certificate beginning and ending headers.
        /// </summary>
        Base64Header = 0x00000000,
        /// <summary>
        /// Base64, without headers.
        /// </summary>
        Base64 = 0x00000001,
        /// <summary>
        /// Pure binary copy.
        /// </summary>
        Binary = 0x00000002, //
        /// <summary>
        /// The string is base64 encoded with beginning and ending certificate request headers.
        /// </summary>
        Base64RequestHeader = 0x00000003,
        /// <summary>
        /// Hexadecimal only format.
        /// </summary>
        Hex = 0x00000004,
        /// <summary>
        /// Hexadecimal format with ASCII character display.
        /// </summary>
        HexAscii = 0x00000005,
        /// <summary>
        /// Tries the following, in order:
        /// <list type="bullet">
        /// <item>Base64Header</item>
        /// <item>Base64</item>
        /// </list>
        /// <strong><see cref="AsnFormatter.BinaryToString">BinaryToString</see></strong> method do not support this flag.
        /// </summary>
        Base64Any = 0x00000006,
        /// <summary>
        /// Tries the following, in order:
        /// <list type="bullet">
        /// <item>Base64Header</item>
        /// <item>Base64</item>
        /// <item>Binary</item>
        /// </list>
        /// <strong><see cref="AsnFormatter.BinaryToString">BinaryToString</see></strong> method do not support this flag.
        /// </summary>
        StringAny = 0x00000007,
        /// <summary>
        /// <list type="bullet">
        /// Tries the following, in order:
        /// <item>HexAddress</item>
        /// <item>HexAsciiAddress</item>
        /// <item>Hex</item>
        /// <item>HexRaw</item>
        /// <item>HexAscii</item>
        /// </list>
        /// <strong><see cref="AsnFormatter.BinaryToString">BinaryToString</see></strong> method do not support this flag.
        /// </summary>
        HexAny = 0x00000008,
        /// <summary>
        /// Base64, with X.509 certificate revocation list (CRL) beginning and ending headers.
        /// </summary>
        Base64CrlHeader = 0x00000009,
        /// <summary>
        /// Hex, with address display.
        /// </summary>
        HexAddress = 0x0000000a,
        /// <summary>
        /// Hex, with ASCII character and address display.
        /// </summary>
        HexAsciiAddress = 0x0000000b,
        /// <summary>
        /// A raw hexadecimal string.
        /// </summary>
        HexRaw = 0x0000000c,
        ///// <summary>
        ///// Set this flag for Base64 data to specify that the end of the binary data contain only white space and at most
        ///// three equals "=" signs.
        ///// </summary>
        //CRYPT_STRING_STRICT = 0x20000000,

    }
}