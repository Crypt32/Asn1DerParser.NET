using System;

namespace SysadminsLV.Asn1Parser;

class PemHeaders {
    public const String PEM_HEADER_CERT           = "CERTIFICATE";
    public const String PEM_HEADER_CERT_TRUSTED   = "TRUSTED CERTIFICATE";
    public const String PEM_HEADER_REQ_NEW        = "NEW CERTIFICATE REQUEST";
    public const String PEM_HEADER_REQ            = "CERTIFICATE REQUEST";
    public const String PEM_HEADER_CRL            = "X509 CRL";
    public const String PEM_HEADER_EVP_PKEY       = "ANY PRIVATE KEY";
    public const String PEM_HEADER_PUBLIC         = "PUBLIC KEY";
    public const String PEM_HEADER_RSA            = "RSA PRIVATE KEY";
    public const String PEM_HEADER_RSA_PUBLIC     = "RSA PUBLIC KEY";
    public const String PEM_HEADER_DSA            = "DSA PRIVATE KEY";
    public const String PEM_HEADER_DSA_PUBLIC     = "DSA PUBLIC KEY";
    public const String PEM_HEADER_PKCS7          = "PKCS7";
    public const String PEM_HEADER_PKCS7_SIGNED   = "PKCS #7 SIGNED DATA";
    public const String PEM_HEADER_PKCS8          = "ENCRYPTED PRIVATE KEY";
    public const String PEM_HEADER_PKCS8_INF      = "PRIVATE KEY";
    public const String PEM_HEADER_DH_PARAMS      = "DH PARAMETERS";
    public const String PEM_HEADER_DHX_PARAMS     = "X9.42 DH PARAMETERS";
    public const String PEM_HEADER_SSL_SESSION    = "SSL SESSION PARAMETERS";
    public const String PEM_HEADER_DSA_PARAMS     = "DSA PARAMETERS";
    public const String PEM_HEADER_ECDSA_PUBLIC   = "ECDSA PUBLIC KEY";
    public const String PEM_HEADER_EC_PARAMS      = "EC PARAMETERS";
    public const String PEM_HEADER_EC_PRIVATE_KEY = "EC PRIVATE KEY";
    public const String PEM_HEADER_PARAMS         = "PARAMETERS";
    public const String PEM_HEADER_CMS            = "CMS";

    public static String GetHeader(String headerName) {
        return $"-----BEGIN {headerName}-----";
    }
    public static String GetFooter(String headerName) {
        return $"-----END {headerName}-----";
    }

    public static String GetCertHeader() {
        return GetHeader(PEM_HEADER_CERT);
    }
    public static String GetCertFooter() {
        return GetFooter(PEM_HEADER_CERT);
    }
    public static String GetTrustedCertHeader() {
        return GetHeader(PEM_HEADER_CERT_TRUSTED);
    }
    public static String GetTrustedCertFooter() {
        return GetFooter(PEM_HEADER_CERT_TRUSTED);
    }
    public static String GetCertReqNewHeader() {
        return GetHeader(PEM_HEADER_REQ_NEW);
    }
    public static String GetCertReqNewFooter() {
        return GetFooter(PEM_HEADER_REQ_NEW);
    }
    public static String GetCertReqHeader() {
        return GetHeader(PEM_HEADER_REQ);
    }
    public static String GetCertReqFooter() {
        return GetFooter(PEM_HEADER_REQ);
    }
    public static String GetCrlHeader() {
        return GetHeader(PEM_HEADER_CRL);
    }
    public static String GetCrlFooter() {
        return GetFooter(PEM_HEADER_CRL);
    }
    public static String GetEvpPrivateHeader() {
        return GetHeader(PEM_HEADER_EVP_PKEY);
    }
    public static String GetEvpPrivateFooter() {
        return GetFooter(PEM_HEADER_EVP_PKEY);
    }
    public static String GetPublicKeyHeader() {
        return GetHeader(PEM_HEADER_PUBLIC);
    }
    public static String GetPublicKeyFooter() {
        return GetFooter(PEM_HEADER_PUBLIC);
    }
    public static String GetRsaPrivateKeyHeader() {
        return GetHeader(PEM_HEADER_RSA);
    }
    public static String GetRsaPrivateKeyFooter() {
        return GetFooter(PEM_HEADER_RSA);
    }
    public static String GetRsaPublicKeyHeader() {
        return GetHeader(PEM_HEADER_RSA_PUBLIC);
    }
    public static String GetRsaPublicKeyFooter() {
        return GetFooter(PEM_HEADER_RSA_PUBLIC);
    }
    public static String GetDsaPrivateKeyHeader() {
        return GetHeader(PEM_HEADER_DSA);
    }
    public static String GetDsaPrivateKeyFooter() {
        return GetFooter(PEM_HEADER_DSA);
    }
    public static String GetDsaPublicKeyHeader() {
        return GetHeader(PEM_HEADER_DSA_PUBLIC);
    }
    public static String GetDsaPublicKeyFooter() {
        return GetFooter(PEM_HEADER_DSA_PUBLIC);
    }
    public static String GetPkcs7Header() {
        return GetHeader(PEM_HEADER_PKCS7);
    }
    public static String GetPkcs7Footer() {
        return GetFooter(PEM_HEADER_PKCS7);
    }
    public static String GetPkcs7SignedHeader() {
        return GetHeader(PEM_HEADER_PKCS7_SIGNED);
    }
    public static String GetPkcs7SignedFooter() {
        return GetFooter(PEM_HEADER_PKCS7_SIGNED);
    }
    public static String GetPkcs8EncryptedHeader() {
        return GetHeader(PEM_HEADER_PKCS8);
    }
    public static String GetPkcs8EncryptedFooter() {
        return GetFooter(PEM_HEADER_PKCS8);
    }
    public static String GetPkcs8Header() {
        return GetHeader(PEM_HEADER_PKCS8_INF);
    }
    public static String GetPkcs8Footer() {
        return GetFooter(PEM_HEADER_PKCS8_INF);
    }
    public static String GetDHParamsHeader() {
        return GetHeader(PEM_HEADER_DH_PARAMS);
    }
    public static String GetDHParamsFooter() {
        return GetFooter(PEM_HEADER_DH_PARAMS);
    }
    public static String GetDHXParamsHeader() {
        return GetHeader(PEM_HEADER_DHX_PARAMS);
    }
    public static String GetDHXParamsFooter() {
        return GetFooter(PEM_HEADER_DHX_PARAMS);
    }
    public static String GetSslSessionHeader() {
        return GetHeader(PEM_HEADER_SSL_SESSION);
    }
    public static String GetSslSessionFooter() {
        return GetFooter(PEM_HEADER_SSL_SESSION);
    }
    public static String GetDsaParamsHeader() {
        return GetHeader(PEM_HEADER_DSA_PARAMS);
    }
    public static String GetDsaParamsFooter() {
        return GetFooter(PEM_HEADER_DSA_PARAMS);
    }
    public static String GetECDsaPublicKeyHeader() {
        return GetHeader(PEM_HEADER_ECDSA_PUBLIC);
    }
    public static String GetECDsaPublicKeyFooter() {
        return GetFooter(PEM_HEADER_ECDSA_PUBLIC);
    }
    public static String GetEcParamsHeader() {
        return GetHeader(PEM_HEADER_EC_PARAMS);
    }
    public static String GetEcParamsFooter() {
        return GetFooter(PEM_HEADER_EC_PARAMS);
    }
    public static String GetEcPrivateKeyHeader() {
        return GetHeader(PEM_HEADER_EC_PRIVATE_KEY);
    }
    public static String GetEcPrivateKeyFooter() {
        return GetFooter(PEM_HEADER_EC_PRIVATE_KEY);
    }
    public static String GetParamsHeader() {
        return GetHeader(PEM_HEADER_PARAMS);
    }
    public static String GetParamsFooter() {
        return GetFooter(PEM_HEADER_PARAMS);
    }
    public static String GetCmsHeader() {
        return GetHeader(PEM_HEADER_CMS);
    }
    public static String GetCmsFooter() {
        return GetFooter(PEM_HEADER_CMS);
    }
}