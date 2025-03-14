using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace Asn1Parser.Tests.Builder;

[TestClass]
public class Asn1BuilderTests {
    const String EXPECTED_ENCODED = """
                                    MIIBGQEB/wEBAAIBBQMCBLADBAACAQEEAgECBAMCAQQFAAYIKwYBBQUHAwEKAQMM
                                    ClVURjhTdHJpbmcNAQUwBgIBAQIBAjADAgEFMQYCAQECAQIxAwIBBRIHNTU1IDU1
                                    NRMPUHJpbnRhYmxlU3RyaW5nFA1UZWxldGV4U3RyaW5nFQ5WaWRlb3RleFN0cmlu
                                    ZxYJSUE1U3RyaW5nFw0yNTAxMDExODAwMDBaGA8yMDI1MDEwMTE4MDAwMFoaDVZp
                                    c2libGVTdHJpbmccPAAAAFUAAABuAAAAaQAAAHYAAABlAAAAcgAAAHMAAABhAAAA
                                    bAAAAFMAAAB0AAAAcgAAAGkAAABuAAAAZx4SAEIATQBQAFMAdAByAGkAbgBn
                                    """;
    static Asn1Builder BuildTestSimple() {
        return Asn1Builder.Create()
            .AddBoolean(true)
            .AddBoolean(false)
            .AddInteger(5)
            .AddBitString([0xb0], true)
            .AddBitString(builder => builder.AddInteger(1))
            .AddOctetString(new Byte[] { 1, 2 })
            .AddOctetString(builder => builder.AddInteger(4))
            .AddNull()
            .AddObjectIdentifier(new Oid("1.3.6.1.5.5.7.3.1"))
            .AddEnumerated(3)
            .AddUTF8String("UTF8String")
            .AddRelativeOid(".5")
            .AddSequence(builder => builder.AddInteger(1).AddInteger(2))
            .AddSequence(new Asn1Integer(5).GetRawDataAsMemory().Span)
            .AddSet(builder => builder.AddInteger(1).AddInteger(2))
            .AddSet(new Asn1Integer(5).GetRawDataAsMemory().Span)
            .AddNumericString("555 555")
            .AddPrintableString("PrintableString")
            .AddTeletexString("TeletexString")
            .AddVideotexString("VideotexString")
            .AddIA5String("IA5String")
            .AddUtcTime(DateTime.Parse("2025-01-01 20:00:00"))
            .AddGeneralizedTime(DateTime.Parse("2025-01-01 20:00:00"))
            .AddVisibleString("VisibleString")
            .AddUniversalString("UniversalString")
            .AddBMPString("BMPString");
    }

    [TestMethod]
    public void TestBuilderSimple() {
        Asn1Builder builder = BuildTestSimple();
        ReadOnlyMemory<Byte> encoded = builder.GetEncodedAsMemory();

        String base64 = Convert.ToBase64String(encoded.Span);
        Assert.AreEqual(EXPECTED_ENCODED.Replace("\r\n", null), base64.Replace("\r\n", null));

        // read envelope
        var reader = new Asn1Reader(encoded);
        Assert.AreEqual(reader.Tag, 0x30);

        Asn1BuilderTestBase.AssertBoolean(reader, true);
        Asn1BuilderTestBase.AssertBoolean(reader, false);
        Asn1BuilderTestBase.AssertInteger(reader, 5);
        Asn1BuilderTestBase.AssertBitStringSimple(reader, [0xb0], 4);
        Asn1BuilderTestBase.AssertBitString(reader);
        Asn1Reader nestedReader = reader.GetReader();
        Asn1BuilderTestBase.AssertInteger(nestedReader, 1);
        Asn1BuilderTestBase.AssertOctetString(reader, [1, 2], useSibling: true);
        Asn1BuilderTestBase.AssertOctetString(reader);
        nestedReader = reader.GetReader();
        Asn1BuilderTestBase.AssertInteger(nestedReader, 4);
        Asn1BuilderTestBase.AssertNull(reader, useSibling: true);
        Asn1BuilderTestBase.AssertObjectIdentifier(reader, "1.3.6.1.5.5.7.3.1");
        Asn1BuilderTestBase.AssertEnumerated(reader, 3);
        Asn1BuilderTestBase.AssertString(reader, Asn1Type.UTF8String, Asn1Type.UTF8String.ToString());
        Asn1BuilderTestBase.AssertRelativeOid(reader, ".5");
        Asn1BuilderTestBase.AssertSequence(reader);
        nestedReader = reader.GetReader();
        Asn1BuilderTestBase.AssertInteger(nestedReader, 1);
        Asn1BuilderTestBase.AssertInteger(nestedReader, 2);
        Asn1BuilderTestBase.AssertSequence(reader, useSibling: true);
        nestedReader = reader.GetReader();
        Asn1BuilderTestBase.AssertInteger(nestedReader, 5);
        Asn1BuilderTestBase.AssertSet(reader, useSibling: true);
        nestedReader = reader.GetReader();
        Asn1BuilderTestBase.AssertInteger(nestedReader, 1);
        Asn1BuilderTestBase.AssertInteger(nestedReader, 2);
        Asn1BuilderTestBase.AssertSet(reader, useSibling: true);
        nestedReader = reader.GetReader();
        Asn1BuilderTestBase.AssertInteger(nestedReader, 5);
        Asn1BuilderTestBase.AssertString(reader, Asn1Type.NumericString, "555 555", useSibling: true);
        Asn1BuilderTestBase.AssertString(reader, Asn1Type.PrintableString, Asn1Type.PrintableString.ToString());
        Asn1BuilderTestBase.AssertString(reader, Asn1Type.TeletexString, Asn1Type.TeletexString.ToString());
        Asn1BuilderTestBase.AssertString(reader, Asn1Type.VideotexString, Asn1Type.VideotexString.ToString());
        Asn1BuilderTestBase.AssertString(reader, Asn1Type.IA5String, Asn1Type.IA5String.ToString());
        Asn1BuilderTestBase.AssertDateTime(reader, DateTime.Parse("2025-01-01 20:00:00"), true);
        Asn1BuilderTestBase.AssertDateTime(reader, DateTime.Parse("2025-01-01 20:00:00"), false);
        Asn1BuilderTestBase.AssertString(reader, Asn1Type.VisibleString, Asn1Type.VisibleString.ToString());
        Asn1BuilderTestBase.AssertString(reader, Asn1Type.UniversalString, Asn1Type.UniversalString.ToString());
        Asn1BuilderTestBase.AssertString(reader, Asn1Type.BMPString, Asn1Type.BMPString.ToString());
    }
}
