using System;
using System.Collections.Generic;

namespace SysadminsLV.Asn1Parser.Utils;

static class StringUtils {
    public static List<Byte> GetAlphabet(Asn1Type type) {
        switch (type) {
            case Asn1Type.PrintableString:
                return generatePrintableStringAlphabet();
        }
        throw new ArgumentException("Invalid string type is specified.");
    }
    static List<Byte> generatePrintableStringAlphabet() {
        List<Byte> allowed = [32];
        for (Byte index = 0x30; index <= 0x39; index++) { allowed.Add(index); }
        for (Byte index = 0x41; index <= 0x5a; index++) { allowed.Add(index); }
        for (Byte index = 0x61; index <= 0x7a; index++) { allowed.Add(index); }
        for (Byte index = 0x27; index <= 0x29; index++) { allowed.Add(index); }
        for (Byte index = 0x2b; index <= 0x2f; index++) { allowed.Add(index); }
        allowed.AddRange([0x3a, 0x3d, 0x3f]);
        return allowed;
    }
}