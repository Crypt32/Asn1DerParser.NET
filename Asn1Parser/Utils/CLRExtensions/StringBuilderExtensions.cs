using System;
using System.Text;

namespace SysadminsLV.Asn1Parser.Utils.CLRExtensions;
/// <summary>
/// Contains extension methods for <see cref="StringBuilder"/>.
/// </summary>
internal static class StringBuilderExtensions {
    /// <summary>
    /// Appends byte as a two-character hex octet. If input value is less than 16, then hex string is prepended with leading zero character.
    /// </summary>
    /// <param name="sb">StringBuilder instance.</param>
    /// <param name="b">Byte to add.</param>
    /// <param name="forceUpperCase">Specifies whether hex octet should be added in uppercase. Default is <c>false</c>.</param>
    /// <returns>StringBuilder instance with appended hex.</returns>
    public static StringBuilder AppendHexOctet(this StringBuilder sb, Byte b, Boolean forceUpperCase = false) {
        return sb
            .Append(byteToHexChar((b >> 4) & 15, forceUpperCase))
            .Append(byteToHexChar(b & 15, forceUpperCase));
    }

    static Char byteToHexChar(Int32 b, Boolean forceUpperCase) {
        return b < 10
            ? (Char)(b + 48)
            : (forceUpperCase ? (Char)(b + 55) : (Char)(b + 87));
    }
}
