using Asn1Parser.Benchmark.Properties;
using BenchmarkDotNet.Attributes;
using SysadminsLV.Asn1Parser;

namespace Asn1Parser.Benchmark;

[MemoryDiagnoser]
public abstract class Asn1BinaryToStringBenchmark {
    readonly Asn1Reader _reader;
    readonly EncodingType _encoding;

    protected Asn1BinaryToStringBenchmark(EncodingType encoding) {
        Byte[] bytes = (Byte[])Resources.ResourceManager.GetObject("MiddleSizeCRL");
        _reader = new Asn1Reader(bytes);
        _encoding = encoding;
    }

    [Benchmark(Baseline = true)]
    public void TestArray() {
        _reader.BuildOffsetMap();
        do {
            AsnFormatter.BinaryToString(_reader.GetTagRawData(), _encoding);
        } while (_reader.MoveNext());
    }
    [Benchmark]
    public void TestSpan() {
        _reader.BuildOffsetMap();
        do {
            AsnFormatter.BinaryToString(_reader.GetTagRawDataAsMemory().Span, _encoding);
        } while (_reader.MoveNext());
    }
    [Benchmark]
    public void TestAsnReader() {
        _reader.BuildOffsetMap();
        do {
            AsnFormatter.BinaryToString(_reader, _encoding);
        } while (_reader.MoveNext());
    }
}

public class Asn1FormatterToBase64Benchmark() : Asn1BinaryToStringBenchmark(EncodingType.Base64);
public class Asn1FormatterToHexRawBenchmark() : Asn1BinaryToStringBenchmark(EncodingType.HexRaw);
public class Asn1FormatterToHexBenchmark() : Asn1BinaryToStringBenchmark(EncodingType.Hex);
public class Asn1FormatterToHexAddressBenchmark() : Asn1BinaryToStringBenchmark(EncodingType.HexAddress);
public class Asn1FormatterToHexAsciiBenchmark() : Asn1BinaryToStringBenchmark(EncodingType.HexAscii);
public class Asn1FormatterToHexAddressAsciiBenchmark() : Asn1BinaryToStringBenchmark(EncodingType.HexAsciiAddress);