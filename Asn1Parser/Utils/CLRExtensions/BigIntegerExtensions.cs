using System;
using System.Linq;
using System.Numerics;

namespace SysadminsLV.Asn1Parser.Utils.CLRExtensions;

/// <summary>
/// Extension class for <see cref="BigInteger"/> class.
/// </summary>
internal static class BigIntegerExtensions {
    /// <summary>
    /// Gets a byte array in the big-endian order.
    /// </summary>
    /// <param name="bigInteger">An <see cref="BigInteger"/> class instance.</param>
    /// <returns>Byte array in a big-endian order.</returns>
    public static ReadOnlySpan<Byte> GetAsnBytes(this BigInteger bigInteger) {
        return bigInteger.ToByteArray().Reverse().ToArray();
    }
}