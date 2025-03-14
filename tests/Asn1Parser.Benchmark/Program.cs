using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;

namespace Asn1Parser.Benchmark;

internal class Program {
    static void Main(String[] args) {
        IConfig config = DefaultConfig.Instance;
        //Summary summary = BenchmarkRunner.Run<Asn1ReaderBenchmark>(config);
        var summary = BenchmarkRunner.Run<Asn1FormatterToHexRawBenchmark>(config);
    }
}
