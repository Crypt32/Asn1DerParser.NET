using System;
using System.Numerics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SysadminsLV.Asn1Parser;
using SysadminsLV.Asn1Parser.Universal;

namespace Asn1Parser.Tests.Builder;

public static class Asn1BuilderTestBase {
    static void moveNext(Asn1Reader reader, Asn1Type type, Boolean useSibling) {
        if (useSibling) {
            reader.MoveNextSiblingAndExpectTags(type);
        } else {
            reader.MoveNextAndExpectTags(type);
        }
    }

    public static void AssertBoolean(Asn1Reader reader, Boolean expectedValue, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.BOOLEAN, useSibling);
        var tag = (Asn1Boolean)reader.GetTagObject();
        Assert.AreEqual(expectedValue, tag.Value);
    }
    public static void AssertInteger(Asn1Reader reader, BigInteger expectedValue, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.INTEGER, useSibling);
        var tag = (Asn1Integer)reader.GetTagObject();
        Assert.AreEqual(expectedValue, tag.Value);
    }
    public static void AssertBitStringSimple(Asn1Reader reader, ReadOnlySpan<Byte> expectedValue, Byte expectedUnusedBits, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.BIT_STRING, useSibling);
        var tag = (Asn1BitString)reader.GetTagObject();
        Assert.AreEqual(expectedUnusedBits, tag.UnusedBits);
        Assert.IsTrue(expectedValue.SequenceEqual(tag.GetValue().Span));
    }
    public static void AssertBitString(Asn1Reader reader, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.BIT_STRING, useSibling);
        var tag = (Asn1BitString)reader.GetTagObject();
        Assert.AreEqual(0, tag.UnusedBits);
    }
    public static void AssertOctetString(Asn1Reader reader, ReadOnlySpan<Byte> expectedValue, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.OCTET_STRING, useSibling);
        var tag = (Asn1OctetString)reader.GetTagObject();
        Assert.IsTrue(expectedValue.SequenceEqual(tag.GetValue().Span));
    }
    public static void AssertOctetString(Asn1Reader reader, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.OCTET_STRING, useSibling);
    }
    public static void AssertNull(Asn1Reader reader, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.NULL, useSibling);
        var tag = (Asn1Null)reader.GetTagObject();
        Assert.AreEqual(2, tag.GetRawDataAsMemory().Length);
    }
    public static void AssertObjectIdentifier(Asn1Reader reader, String expectedValue, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.OBJECT_IDENTIFIER, useSibling);
        var tag = (Asn1ObjectIdentifier)reader.GetTagObject();
        Assert.AreEqual(expectedValue, tag.Value.Value);
    }
    public static void AssertEnumerated(Asn1Reader reader, UInt64 expectedValue, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.ENUMERATED, useSibling);
        var tag = (Asn1Enumerated)reader.GetTagObject();
        Assert.AreEqual(expectedValue, tag.Value);
    }
    public static void AssertString(Asn1Reader reader, Asn1Type type, String expectedValue, Boolean useSibling = false) {
        moveNext(reader, type, useSibling);
        var tag = (Asn1String)reader.GetTagObject();
        Assert.AreEqual(expectedValue, tag.Value);
    }
    public static void AssertRelativeOid(Asn1Reader reader, String expectedValue, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.RELATIVE_OID, useSibling);
        var tag = (Asn1RelativeOid)reader.GetTagObject();
        Assert.AreEqual(expectedValue, tag.Value);
    }
    public static void AssertSequence(Asn1Reader reader, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.SEQUENCE | (Asn1Type)Asn1Class.CONSTRUCTED, useSibling);
    }
    public static void AssertSet(Asn1Reader reader, Boolean useSibling = false) {
        moveNext(reader, Asn1Type.SET | (Asn1Type)Asn1Class.CONSTRUCTED, useSibling);
    }
    public static void AssertDateTime(Asn1Reader reader, DateTime expected, Boolean useUtc, Boolean useSibling = false) {
        moveNext(reader, useUtc
            ? Asn1Type.UTCTime
            : Asn1Type.GeneralizedTime, useSibling);
        var tag = (Asn1DateTime)reader.GetTagObject();
        Assert.AreEqual(expected, tag.Value);
    }
    public static void AssertContextSpecific(Asn1Reader reader, Byte expectedTag, ReadOnlySpan<Byte> expectedBytes, Boolean useSibling = false) {
        moveNext(reader, (Asn1Type)expectedTag, useSibling);
        Asn1Universal tag = reader.GetTagObject();
        Assert.IsTrue(expectedBytes.SequenceEqual(tag.GetRawDataAsMemory().Span));
    }
}