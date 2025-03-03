using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace Asn1Parser.Tests.Builder;

[TestClass]
public class Asn1BuilderContextSpecificTests {
    static Asn1Builder BuildTestContextSpecific() {
        return Asn1Builder.Create()
            .AddImplicit(0, [1, 2], true)
            .AddImplicit(1, new Asn1IA5String("a").GetRawDataAsMemory().Span, false)
            .AddExplicit(0, builder => builder.AddInteger(5))
            .AddExplicit(1, new Asn1Integer(5).GetRawDataAsMemory().Span, true)
            .AddExplicit(2, [48, 3, 2, 1, 5], false);
    }

    [TestMethod]
    public void TestContextSpecific() {
        Asn1Builder builder = BuildTestContextSpecific();

        ReadOnlyMemory<Byte> encoded = builder.GetEncodedAsMemory();
        var reader = new Asn1Reader(encoded);
        Assert.AreEqual(reader.Tag, 0x30);

        Asn1BuilderTestBase.AssertContextSpecific(reader, 0x80, [0x80, 2, 1, 2]);
        Asn1BuilderTestBase.AssertContextSpecific(reader, 0x81, [0x81, 1, 0x61]);
        Asn1BuilderTestBase.AssertContextSpecific(reader, 0xa0, [0xa0, 3, 2, 1, 5]);
        Asn1BuilderTestBase.AssertContextSpecific(reader, 0xa1, [0xa1, 3, 2, 1, 5], useSibling: true);
        Asn1BuilderTestBase.AssertContextSpecific(reader, 0xa2, [0xa2, 3, 2, 1, 5], useSibling: true);
    }
}