using System;
using System.Collections.Generic;
using System.Numerics;

namespace SysadminsLV.Asn1Parser.Utils;
static class OidUtils {
    public static IEnumerable<Byte> EncodeOidArc(BigInteger arcValue) {
        List<Byte> rawOid = [];
        BigInteger temp = arcValue;
        // calculate how many bits are occupied by the current integer value
        Int16 bitLength = 0;
        do {
            temp = (BigInteger)Math.Floor((Double)temp / 2);
            bitLength++;
        } while (temp > 0);
        // calculate how many additional bytes are required and encode each integer in a 7 bit.
        // 8th bit of the integer is shifted to the left and 8th bit is set to 1 to indicate that
        // additional bytes are related to the current OID arc. Details:
        // http://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
        // loop may not execute if arc value is less than 128.
        for (Int32 index = (bitLength - 1) / 7; index > 0; index--) {
            rawOid.Add((Byte)(0x80 | ((arcValue >> (index * 7)) & 0x7f)));
        }
        rawOid.Add((Byte)(arcValue & 0x7f));

        return rawOid;
    }
    public static String DecodeOidArc(IEnumerable<Byte> rawData) {
        throw new NotImplementedException();
    }
}
