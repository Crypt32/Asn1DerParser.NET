using System;
using System.Text;

namespace SysadminsLV.Asn1Parser.Utils.CLRExtensions;

/// <summary>
/// Provides extension methods for the <see cref="System.Text.Encoding"/> class to enhance its functionality.
/// </summary>
static class EncodingExtensions {
    /// <summary>
    /// Decodes a sequence of bytes from the specified <see cref="ReadOnlyMemory{T}"/> into a string using the provided <see cref="System.Text.Encoding"/>.
    /// </summary>
    /// <param name="encoding">The <see cref="System.Text.Encoding"/> to use for decoding the byte sequence.</param>
    /// <param name="bytes">The byte sequence to decode, represented as a <see cref="ReadOnlyMemory{T}"/> of <see cref="Byte"/>.</param>
    /// <returns>A <see cref="String"/> that contains the decoded characters from the byte sequence.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="encoding"/> is <c>null</c>.</exception>
    public static String GetString(this Encoding encoding, ReadOnlySpan<Byte> bytes) {
#if NET8_0_OR_GREATER
        return encoding.GetString(bytes);
#else
        return encoding.GetString(bytes.ToArray());
#endif
    }
}
