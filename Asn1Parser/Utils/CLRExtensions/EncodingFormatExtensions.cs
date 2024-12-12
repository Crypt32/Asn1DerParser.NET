using System;

namespace SysadminsLV.Asn1Parser.Utils.CLRExtensions;

/// <summary>
/// Contains extension methods for <see cref="EncodingFormat"/> enumeration.
/// </summary>
static class EncodingFormatExtensions {
    /// <summary>
    /// Gets end of line implementation.
    /// </summary>
    /// <param name="format">Encoding format.</param>
    /// <returns>End of line string. Can be empty string.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><strong>format</strong> argument is not valid value.</exception>
    public static String GetEndOfLine(this EncodingFormat format) {
        return format switch {
            EncodingFormat.CRLF => "\r\n",
            EncodingFormat.NOCRLF => String.Empty,
            EncodingFormat.NOCR => "\n",
            _ => throw new ArgumentOutOfRangeException(nameof(format), format, null)
        };
    }
}
