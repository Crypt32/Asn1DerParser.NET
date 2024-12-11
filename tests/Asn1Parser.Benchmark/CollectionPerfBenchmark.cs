using BenchmarkDotNet.Attributes;

namespace Asn1Parser.Benchmark;

public class CollectionPerfBenchmark {
    static readonly List<Byte> _list = [];
    static readonly HashSet<Byte> _hashSet = [];

    public CollectionPerfBenchmark() {
        foreach (Byte b in Enumerable.Range(0, 31)) {
            _list.Add(b);
            _hashSet.Add(b);
        }
    }

    [Benchmark(Baseline = true)]
    public void Contains11() {
        _list.Contains(0);
    }
    [Benchmark]
    public void Contains21() {
        _hashSet.Contains(0);
    }
    [Benchmark]
    public void Contains12() {
        _list.Contains(20);
    }
    [Benchmark]
    public void Contains22() {
        _hashSet.Contains(20);
    }
    [Benchmark]
    public void Contains13() {
        _list.Contains(30);
    }
    [Benchmark]
    public void Contains23() {
        _hashSet.Contains(30);
    }
    [Benchmark]
    public void Contains14() {
        _list.Contains(255);
    }
    [Benchmark]
    public void Contains24() {
        _hashSet.Contains(255);
    }
}