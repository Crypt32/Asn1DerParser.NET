using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Asn1Parser.Tests;
[TestClass]
public class CollectionPerfTests {
    static readonly List<Byte> _list = [0, 1, 2, 5, 6, 9, 10, 12, 13, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30];
    static readonly HashSet<Byte> _hashSet = [0, 1, 2, 5, 6, 9, 10, 12, 13, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30];
    const Int32 ITERATIONS = 1000000;

    [TestMethod]
    public void TestFirstMatch() {
        assertGlobal(0);
    }
    [TestMethod]
    public void TestMiddleMatch() {
        assertGlobal(20);
    }
    [TestMethod]
    public void TestLastMatch() {
        assertGlobal(30);
    }
    [TestMethod]
    public void TestNoMatch() {
        assertGlobal(255);
    }

    static void assertGlobal(Byte searchByte) {
        TimeSpan list = executeAction(_list.Contains, searchByte, ITERATIONS);
        TimeSpan hashSet = executeAction(_hashSet.Contains, searchByte, ITERATIONS);
        assertListIsFaster(list, hashSet);
    }
    static void assertListIsFaster(TimeSpan list, TimeSpan hashSet) {
        Assert.IsTrue(list < hashSet);
    }
    //static void assertListIsFaster3xTimes(TimeSpan list, TimeSpan hashSet) {
    //    Double ratio = hashSet / list;
    //    Console.WriteLine(ratio);
    //    Assert.IsTrue(ratio >= 3);
    //}
    static TimeSpan executeAction(Func<Byte, Boolean> action, Byte searchValue, Int32 iterations) {
        var sw = new Stopwatch();
        sw.Start();
        for (Int32 i = 0; i < iterations; i++) {
            action.Invoke(searchValue);
        }
        sw.Stop();

        return sw.Elapsed;
    }
}
