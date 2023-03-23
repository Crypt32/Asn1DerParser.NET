using System;
using System.Collections.Generic;

namespace SysadminsLV.Asn1Parser;

class PemHeader {
    public PemHeader(String header, EncodingType encoding) {
        Header = header;
        Encoding = encoding;
    }

    public String Header { get; }
    public EncodingType Encoding { get; }

    public String GetHeader() {
        return GetHeaderString(Header);
    }
    public String GetFooter() {
        return GetFooterString(Header);
    }

    public static readonly PemHeader PEM_HEADER_CERT           = new("CERTIFICATE", EncodingType.PemCert);
    public static readonly PemHeader PEM_HEADER_CERT_CAPI      = new("CERTIFICATE", EncodingType.Base64Header);
    public static readonly PemHeader PEM_HEADER_CERT_TRUSTED   = new("TRUSTED CERTIFICATE", EncodingType.PemTrustedCert);
    public static readonly PemHeader PEM_HEADER_REQ_NEW        = new("NEW CERTIFICATE REQUEST", EncodingType.PemNewReq);
    public static readonly PemHeader PEM_HEADER_REQ_NEW_CAPI   = new("NEW CERTIFICATE REQUEST", EncodingType.Base64RequestHeader);
    public static readonly PemHeader PEM_HEADER_REQ            = new("CERTIFICATE REQUEST", EncodingType.PemReq);
    public static readonly PemHeader PEM_HEADER_CRL            = new("X509 CRL", EncodingType.Base64CrlHeader);
    public static readonly PemHeader PEM_HEADER_EVP_PKEY       = new("ANY PRIVATE KEY", EncodingType.PemEvpPrivateKey);
    public static readonly PemHeader PEM_HEADER_PUBLIC         = new("PUBLIC KEY", EncodingType.PemPublicKey);
    public static readonly PemHeader PEM_HEADER_RSA            = new("RSA PRIVATE KEY", EncodingType.PemRsaPrivateKey);
    public static readonly PemHeader PEM_HEADER_RSA_PUBLIC     = new("RSA PUBLIC KEY", EncodingType.PemRsaPublicKey);
    public static readonly PemHeader PEM_HEADER_DSA            = new("DSA PRIVATE KEY", EncodingType.PemDsaPrivateKey);
    public static readonly PemHeader PEM_HEADER_DSA_PUBLIC     = new("DSA PUBLIC KEY", EncodingType.PemDsaPublicKey);
    public static readonly PemHeader PEM_HEADER_PKCS7          = new("PKCS7", EncodingType.PemPkcs7);
    public static readonly PemHeader PEM_HEADER_PKCS7_SIGNED   = new("PKCS #7 SIGNED DATA", EncodingType.PemPkcs7Signed);
    public static readonly PemHeader PEM_HEADER_PKCS8          = new("ENCRYPTED PRIVATE KEY", EncodingType.PemPkcs8Encrypted);
    public static readonly PemHeader PEM_HEADER_PKCS8_INF      = new("PRIVATE KEY", EncodingType.PemPkcs8Inf);
    public static readonly PemHeader PEM_HEADER_DH_PARAMS      = new("DH PARAMETERS", EncodingType.PemDHParams);
    public static readonly PemHeader PEM_HEADER_DHX_PARAMS     = new("X9.42 DH PARAMETERS", EncodingType.PemDHXParams);
    public static readonly PemHeader PEM_HEADER_SSL_SESSION    = new("SSL SESSION PARAMETERS", EncodingType.PemSSLSessionParams);
    public static readonly PemHeader PEM_HEADER_DSA_PARAMS     = new("DSA PARAMETERS", EncodingType.PemDsaParams);
    public static readonly PemHeader PEM_HEADER_ECDSA_PUBLIC   = new("ECDSA PUBLIC KEY", EncodingType.PemECDsaPublicKey);
    public static readonly PemHeader PEM_HEADER_EC_PARAMS      = new("EC PARAMETERS", EncodingType.PemECParams);
    public static readonly PemHeader PEM_HEADER_EC_PRIVATE_KEY = new("EC PRIVATE KEY", EncodingType.PemECPrivateKey);
    public static readonly PemHeader PEM_HEADER_PARAMS         = new("PARAMETERS", EncodingType.PemParams);
    public static readonly PemHeader PEM_HEADER_CMS            = new("CMS", EncodingType.PemCms);

    public static String GetHeaderString(String headerName) {
        return $"-----BEGIN {headerName}-----";
    }
    public static String GetFooterString(String headerName) {
        return $"-----END {headerName}-----";
    }
    public static Boolean ContainsEncoding(EncodingType encoding) {
        return _lookupTable.ContainsKey(encoding);
    }
    public static PemHeader GetHeader(EncodingType encoding) {
        return _lookupTable[encoding];
    }
    public static IEnumerable<PemHeader> GetPemHeaders() {
        return _lookupTable.Values;
    }

    static readonly Dictionary<EncodingType, PemHeader> _lookupTable = new();

    static PemHeader() {
        addToLookup(PEM_HEADER_CERT);
        addToLookup(PEM_HEADER_CERT_CAPI);
        addToLookup(PEM_HEADER_CERT_TRUSTED);
        addToLookup(PEM_HEADER_REQ_NEW);
        addToLookup(PEM_HEADER_REQ_NEW_CAPI);
        addToLookup(PEM_HEADER_REQ);
        addToLookup(PEM_HEADER_CRL);
        addToLookup(PEM_HEADER_EVP_PKEY);
        addToLookup(PEM_HEADER_PUBLIC);
        addToLookup(PEM_HEADER_RSA);
        addToLookup(PEM_HEADER_RSA_PUBLIC);
        addToLookup(PEM_HEADER_DSA);
        addToLookup(PEM_HEADER_DSA_PUBLIC);
        addToLookup(PEM_HEADER_PKCS7);
        addToLookup(PEM_HEADER_PKCS7_SIGNED);
        addToLookup(PEM_HEADER_PKCS8);
        addToLookup(PEM_HEADER_PKCS8_INF);
        addToLookup(PEM_HEADER_DH_PARAMS);
        addToLookup(PEM_HEADER_DHX_PARAMS);
        addToLookup(PEM_HEADER_SSL_SESSION);
        addToLookup(PEM_HEADER_DSA_PARAMS);
        addToLookup(PEM_HEADER_ECDSA_PUBLIC);
        addToLookup(PEM_HEADER_EC_PARAMS);
        addToLookup(PEM_HEADER_EC_PRIVATE_KEY);
        addToLookup(PEM_HEADER_PARAMS);
        addToLookup(PEM_HEADER_CMS);
    }
    static void addToLookup(PemHeader header) {
        _lookupTable.Add(header.Encoding, header);
    }
}