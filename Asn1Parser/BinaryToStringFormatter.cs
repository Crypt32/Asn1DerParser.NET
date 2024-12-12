using System;
using System.Buffers;
using System.Buffers.Text;
using System.Text;

namespace SysadminsLV.Asn1Parser;

static class BinaryToStringFormatter {
    public static String ToHexRaw(ReadOnlySpan<Byte> rawData, EncodingFormat format, Boolean forceUpperCase) {
        String eol = getEOL(format);
        var SB = new StringBuilder();
        foreach (Byte b in rawData) {
            byteToHexOctet(SB, b, forceUpperCase);
        }
        
        return SB.Append(eol).ToString();
    }
    public static String ToHex(ReadOnlySpan<Byte> rawData, EncodingFormat format, Boolean forceUpperCase) {
        var sb = new StringBuilder();
        for (Int32 index = 0; index < rawData.Length; index++) {
            byteToHexOctet(sb, rawData[index], forceUpperCase);
            if (index == 0) {
                sb.Append(" ");
                continue;
            }
            if ((index + 1) % 16 == 0) {
                // if current octet is the last octet in a row, append EOL format
                switch (format) {
                    case EncodingFormat.NOCRLF:
                        sb.Append(" ");
                        break;
                    case EncodingFormat.CRLF:
                        sb.Append("\r\n"); break;
                    case EncodingFormat.NOCR:
                        sb.Append("\n"); break;
                }
            } else if ((index + 1) % 8 == 0 && format != EncodingFormat.NOCRLF) {
                sb.Append("  ");
            } else {
                sb.Append(" ");
            }
        }

        return finalizeBinaryToString(sb, format);
    }
    public static String ToHexAddress(ReadOnlySpan<Byte> rawData, EncodingFormat format, Boolean forceUpperCase) {
        var sb = new StringBuilder();
        Int32 rowCount = 0;
        Int32 addrLength = getAddrLength(rawData.Length);
        for (Int32 index = 0; index < rawData.Length; index++) {
            if (index % 16 == 0) {
                String hexAddress = Convert.ToString(rowCount, 16).PadLeft(addrLength, '0');
                if (forceUpperCase) {
                    hexAddress = hexAddress.ToUpper();
                }
                sb.Append(hexAddress);
                sb.Append("    ");
                rowCount += 16;
            }
            byteToHexOctet(sb, rawData[index], forceUpperCase);
            if (index == 0) {
                sb.Append(" ");
                continue;
            }
            
            if ((index + 1) % 16 == 0) {
                // if current octet is the last octet in a row, append EOL format
                sb.Append(format == EncodingFormat.NOCR ? "\n" : "\r\n");
            } else if ((index + 1) % 8 == 0) {
                // if current octet is center octet in a row, append extra space
                sb.Append("  ");
            } else {
                sb.Append(" ");
            }
        }

        return finalizeBinaryToString(sb, format);
    }
    public static String ToHexAscii(ReadOnlySpan<Byte> rawData, EncodingFormat format, Boolean forceUpperCase) {
        var sb = new StringBuilder();
        var ascii = new StringBuilder(8);
        for (Int32 index = 0; index < rawData.Length; index++) {
            byteToHexOctet(sb, rawData[index], forceUpperCase);
            Char c = rawData[index] < 32 || rawData[index] > 126
                ? '.'
                : (Char)rawData[index];
            ascii.Append(c);
            if (index == 0) {
                sb.Append(" ");
                continue;
            }
            if ((index + 1) % 16 == 0) {
                sb.Append("   ");
                sb.Append(ascii);
                ascii.Clear();
                // if current octet is the last octet in a row, append EOL format
                sb.Append(format == EncodingFormat.NOCR ? "\n" : "\r\n");
            } else if ((index + 1) % 8 == 0) {
                sb.Append("  ");
            } else {
                sb.Append(" ");
            }
            // handle last byte to complete partial ASCII panel.
            if (index + 1 == rawData.Length) {
                sb.Append(getAsciiPadding(index + 1));
                sb.Append(ascii);
            }
        }

        return finalizeBinaryToString(sb, format);
    }
    public static String ToHexAddressAndAscii(ReadOnlySpan<Byte> rawData, EncodingFormat format, Boolean forceUpperCase) {
        var sb = new StringBuilder();
        var ascii = new StringBuilder(8);
        Int32 addrLength = getAddrLength(rawData.Length);
        Int32 rowCount = 0;
        for (Int32 index = 0; index < rawData.Length; index++) {
            if (index % 16 == 0) {
                String hexAddress = Convert.ToString(rowCount, 16).PadLeft(addrLength, '0');
                if (forceUpperCase) {
                    hexAddress = hexAddress.ToUpper();
                }
                sb.Append(hexAddress);
                sb.Append("    ");
                rowCount += 16;
            }
            byteToHexOctet(sb, rawData[index], forceUpperCase);
            Char c = rawData[index] < 32 || rawData[index] > 126
                ? '.'
                : (Char)rawData[index];
            ascii.Append(c);
            if (index == 0) {
                sb.Append(" ");
                continue;
            }
            if ((index + 1) % 16 == 0) {
                sb.Append("   ");
                sb.Append(ascii);
                ascii.Clear();
                sb.Append(format == EncodingFormat.NOCR ? "\n" : "\r\n");
            } else if ((index + 1) % 8 == 0) {
                sb.Append("  ");
            } else {
                sb.Append(" ");
            }
            // handle last byte to complete partial ASCII panel.
            if (index + 1 == rawData.Length) {
                sb.Append(getAsciiPadding(index + 1));
                sb.Append(ascii);
            }
        }

        return finalizeBinaryToString(sb, format);
    }
    public static String ToBase64(ReadOnlySpan<Byte> rawData, EncodingType encoding, EncodingFormat format) {
        Int32 b64Length = Base64.GetMaxEncodedToUtf8Length(rawData.Length);
        Span<Byte> base64 = new Byte[b64Length];
        OperationStatus result = Base64.EncodeToUtf8(rawData, base64, out _, out _);
        String eol = getEOL(format);
        Int32 rowCount = (Int32)Math.Floor(b64Length / 64d);
        Int32 eolCount = rowCount * eol.Length + eol.Length;
        PemHeader? pem = null;
        switch (encoding) {
            case EncodingType.Base64:
                break;
            default:
                pem = getPemHeader(encoding);
                break;
        }
        Int32 totalLength = b64Length + eolCount;
        if (pem is not null) {
            // total length is a sum of:
            // - PEM header length + EOL
            // - main base64 content with EOLs
            // - PEM footer length + EOL
            // - final EOL
            totalLength = totalLength + pem.GetHeader().Length + pem.GetFooter().Length + eol.Length * 2 + 1;
        }
        var sb = new StringBuilder(totalLength);
        // append PEM header if available
        if (pem is not null) {
            sb.Append(pem.GetHeader()).Append(eol);
        }
        // copy first full lines
        for (Int32 i = 0; i < rowCount; i++) {
            for (Int32 j = 0; j < 64; j++) {
                sb.Append((Char)base64[i * 64 + j]);
            }
            sb.Append(eol);
        }
        for (Int32 i = rowCount * 64; i < b64Length; i++) {
            sb.Append((Char)base64[i]);
        }
        // append PEM footer if available
        if (pem is not null) {
            sb.Append(eol);
            sb.Append(pem.GetFooter());
        }
        sb.Append(eol);

        return sb.ToString();
    }

    #region string finalizers

    static PemHeader getPemHeader(EncodingType encoding) {
        if (PemHeader.ContainsEncoding(encoding)) {
            return PemHeader.GetHeader(encoding);
        }

        throw new ArgumentException("Specified encoding is not valid Base64 encoding.");
    }
    static String finalizeBinaryToString(StringBuilder sb, EncodingFormat format) {
        switch (format) {
            case EncodingFormat.NOCR:
                return sb.Append('\n').ToString();
            case EncodingFormat.NOCRLF:
                return sb.ToString().TrimEnd();
            default:
                return sb.Append("\r\n").ToString();
        }
    }
    static String getEOL(EncodingFormat format) {
        return format switch {
            EncodingFormat.CRLF   => "\r\n",
            EncodingFormat.NOCRLF => String.Empty,
            EncodingFormat.NOCR   => "\n",
            _                     => throw new ArgumentOutOfRangeException(nameof(format), format, null)
        };
    }

    #endregion

    #region helper methods

    static String getAsciiPadding(Int32 index) {
        Int32 remainder = index % 16;
        if (remainder > 7) {
            return new String(' ', (17 - remainder) * 3 - 1);
        }

        return new String(' ', (17 - remainder) * 3);
    }
    static Int32 getAddrLength(Int32 size) {
        Int32 div = size / 16;
        if (size % 16 > 0) { div++; }
        String h = $"{div:x}";
        return h.Length < 4
            ? 4
            : (h.Length % 2 == 0 ? h.Length : h.Length + 1);
    }
    static void byteToHexOctet(StringBuilder sb, Byte b, Boolean forceUpperCase) {
        sb.Append(byteToHexChar((b >> 4) & 15, forceUpperCase));
        sb.Append(byteToHexChar(b & 15, forceUpperCase));
    }
    static Char byteToHexChar(Int32 b, Boolean forceUpperCase) {
        return b < 10
            ? (Char)(b + 48)
            : (forceUpperCase ? (Char)(b + 55) : (Char)(b + 87));
    }

    #endregion
}