using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SysadminsLV.Asn1Parser;

static class BinaryToStringFormatter {
    public static String ToHexRaw(IReadOnlyList<Byte> rawData, Int32 start, Int32 count, Boolean forceUpperCase) {
        count = getCount(rawData.Count, start, count);
        var SB = new StringBuilder();
        for (Int32 i = start; i < start + count; i++) {
            byteToHexOctet(SB, rawData[i], forceUpperCase);
        }
        return SB.ToString();
    }
    public static String ToHex(IReadOnlyList<Byte> rawData, EncodingFormat format, Int32 start, Int32 count, Boolean forceUpperCase) {
        count = getCount(rawData.Count, start, count);
        var sb = new StringBuilder();
        Int32 n = 0;
        for (Int32 index = start; index < start + count; index++) {
            n++;
            byteToHexOctet(sb, rawData[index], forceUpperCase);
            if (index == start) {
                sb.Append(" ");
                continue;
            }
            if (n % 16 == 0) {
                switch (format) {
                    case EncodingFormat.NOCRLF:
                        sb.Append(" ");
                        break;
                    case EncodingFormat.CRLF:
                        sb.Append("\r\n"); break;
                    case EncodingFormat.NOCR:
                        sb.Append("\n"); break;
                }
            } else if (n % 8 == 0 && format != EncodingFormat.NOCRLF) {
                sb.Append("  ");
            } else {
                sb.Append(" ");
            }
        }

        return finalizeBinaryToString(sb, format);
    }
    public static String ToHexAddress(IReadOnlyList<Byte> rawData, EncodingFormat format, Int32 start, Int32 count, Boolean forceUpperCase) {
        count = getCount(rawData.Count, start, count);
        var sb = new StringBuilder();
        Int32 rowCount = 0, n = 0;
        Int32 addrLength = getAddrLength(rawData.Count);
        for (Int32 index = start; index < start + count; index++) {
            if (n % 16 == 0) {
                String hexAddress = Convert.ToString(rowCount, 16).PadLeft(addrLength, '0');
                if (forceUpperCase) {
                    hexAddress = hexAddress.ToUpper();
                }
                sb.Append(hexAddress);
                sb.Append("    ");
                rowCount += 16;
            }
            byteToHexOctet(sb, rawData[index], forceUpperCase);
            if (index == start) {
                sb.Append(" ");
                n++;
                continue;
            }
            if ((n + 1) % 16 == 0) {
                sb.Append(format == EncodingFormat.NOCR ? "\n" : "\r\n");
            } else if ((n + 1) % 8 == 0) {
                sb.Append("  ");
            } else {
                sb.Append(" ");
            }
            n++;
        }

        return finalizeBinaryToString(sb, format);
    }
    public static String ToHexAscii(Byte[] rawData, EncodingFormat format, Int32 start, Int32 count, Boolean forceUpperCase) {
        count = getCount(rawData.Length, start, count);
        var sb = new StringBuilder();
        var ascii = new StringBuilder(8);
        Int32 n = 0;
        for (Int32 index = 0; index < start + count; index++) {
            n++;
            byteToHexOctet(sb, rawData[index], forceUpperCase);
            Char c = rawData[index] < 32 || rawData[index] > 126
                ? '.'
                : (Char)rawData[index];
            ascii.Append(c);
            if (index == start) {
                sb.Append(" ");
                continue;
            }
            if (n % 16 == 0) {
                sb.Append("   ");
                sb.Append(ascii);
                ascii.Clear();
                sb.Append(format == EncodingFormat.NOCR ? "\n" : "\r\n");
            } else if (n % 8 == 0) {
                sb.Append("  ");
            } else {
                sb.Append(" ");
            }
            // handle last byte to complete partial ASCII panel.
            if (n == count) {
                sb.Append(getAsciiPadding(n));
                sb.Append(ascii);
            }
        }

        return finalizeBinaryToString(sb, format);
    }
    public static String ToHexAddressAndAscii(IReadOnlyList<Byte> rawData, EncodingFormat format, Int32 start, Int32 count, Boolean forceUpperCase) {
        count = getCount(rawData.Count, start, count);
        var sb = new StringBuilder();
        var ascii = new StringBuilder(8);
        Int32 addrLength = getAddrLength(rawData.Count);
        Int32 rowCount = 0, n = 0;
        for (Int32 index = 0; index < start + count; index++) {
            if (n % 16 == 0) {
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
                n++;
                continue;
            }
            if ((n + 1) % 16 == 0) {
                sb.Append("   ");
                sb.Append(ascii);
                ascii.Clear();
                sb.Append(format == EncodingFormat.NOCR ? "\n" : "\r\n");
            } else if ((n + 1) % 8 == 0) {
                sb.Append("  ");
            } else {
                sb.Append(" ");
            }
            // handle last byte to complete partial ASCII panel.
            if (n + 1 == count) {
                sb.Append(getAsciiPadding(index + 1));
                sb.Append(ascii);
            }
            n++;
        }

        return finalizeBinaryToString(sb, format);
    }
    public static String ToBase64(IReadOnlyCollection<Byte> rawData, EncodingType encoding, EncodingFormat format, Int32 start, Int32 count) {
        count = getCount(rawData.Count, start, count);
        var sb = new StringBuilder(Convert.ToBase64String(rawData.Skip(start).Take(count).ToArray()));
        String splitter;
        switch (format) {
            case EncodingFormat.NOCR:
                splitter = "\n";
                // Base64FormattingOptions inserts new lines at 76 position, while we need 64.
                for (Int32 i = 64; i < sb.Length; i += 65) { // 64 + "\r\n"
                    sb.Insert(i, splitter);
                }
                break;
            case EncodingFormat.NOCRLF:
                splitter = String.Empty;
                break;
            default:
                splitter = "\r\n";
                // Base64FormattingOptions inserts new lines at 76 position, while we need 64.
                for (Int32 i = 64; i < sb.Length; i += 66) { // 64 + "\r\n"
                    sb.Insert(i, splitter);
                }
                break;
        }
        switch (encoding) {
            case EncodingType.Base64:
                break;
            default:
                finalizeBase64WithHeader(sb, encoding, splitter);
                break;
        }

        return finalizeBinaryToString(sb, format);
    }

    #region string finalizers

    static void finalizeBase64WithHeader(StringBuilder sb, EncodingType encoding, String splitter) {
        Func<String> header, footer;
        if (PemHeader.ContainsEncoding(encoding)) {
            PemHeader pemHeader = PemHeader.GetHeader(encoding);
            header = pemHeader.GetHeader;
            footer = pemHeader.GetFooter;
        } else {
            throw new ArgumentException("Specified encoding is not valid Base64 encoding.");
        }
        sb.Insert(0, header.Invoke() + splitter);
        sb.Append(splitter + footer.Invoke());
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

    #endregion

    #region helper methods

    static String getAsciiPadding(Int32 index) {
        Int32 remainder = index % 16;
        if (remainder > 7) {
            return new String(' ', (17 - remainder) * 3 - 1);
        }

        return new String(' ', (17 - remainder) * 3);
    }
    static Int32 getCount(Int32 size, Int32 start, Int32 count) {
        if (start < 0 || start >= size) {
            throw new OverflowException();
        }
        return count == 0 || start + count > size ? size - start : count;
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