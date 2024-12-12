using Asn1Parser.Benchmark.Properties;
using BenchmarkDotNet.Attributes;
using SysadminsLV.Asn1Parser;

namespace Asn1Parser.Benchmark;


[MemoryDiagnoser]
public class Asn1ReaderBenchmark {
    readonly Asn1Reader _reader;

    public Asn1ReaderBenchmark() {
        Byte[] bytes = (Byte[])Resources.ResourceManager.GetObject("MiddleSizeCRL"); ;
        _reader = new Asn1Reader(bytes);
    }

    [Benchmark(Baseline = true)]
    public void Test1() {
        _reader.BuildOffsetMap();
        do {
            _reader.GetPayload();
        } while (_reader.MoveNext());
    }
    [Benchmark]
    public void Test2() {
        _reader.BuildOffsetMap();
        do {
            _reader.GetPayloadAsMemory();
        } while (_reader.MoveNext());
    }
}