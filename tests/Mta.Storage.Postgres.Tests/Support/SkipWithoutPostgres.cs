using System.Reflection;
using Xunit.Abstractions;
using Xunit.Sdk;

[assembly: Xunit.TestFramework("Mta.Storage.Postgres.Tests.SkipWithoutPostgresFramework", "Mta.Storage.Postgres.Tests")]

namespace Mta.Storage.Postgres.Tests;

/// <summary>
/// xUnit 2 cannot skip a test from inside it, and the shared conformance suite's <c>[Fact]</c>s live in another assembly, so
/// this test framework reports every test of this assembly as <b>skipped</b> (with <see cref="PostgresTestServer.UnavailableReason"/>)
/// when no PostgreSQL could be found or started. Classes marked <see cref="NoPostgresAttribute"/> always run.
/// </summary>
public sealed class SkipWithoutPostgresFramework(IMessageSink diagnosticMessageSink) : XunitTestFramework(diagnosticMessageSink)
{
    protected override ITestFrameworkExecutor CreateExecutor(AssemblyName assemblyName) =>
        new Executor(assemblyName, SourceInformationProvider, DiagnosticMessageSink);

    private sealed class Executor(AssemblyName assemblyName, ISourceInformationProvider source, IMessageSink diagnostics)
        : XunitTestFrameworkExecutor(assemblyName, source, diagnostics)
    {
        protected override async void RunTestCases(IEnumerable<IXunitTestCase> testCases, IMessageSink executionMessageSink, ITestFrameworkExecutionOptions executionOptions)
        {
            using var runner = new AssemblyRunner(TestAssembly, testCases, DiagnosticMessageSink, executionMessageSink, executionOptions);
            await runner.RunAsync();
        }
    }

    private sealed class AssemblyRunner(ITestAssembly assembly, IEnumerable<IXunitTestCase> cases, IMessageSink diagnostics, IMessageSink execution, ITestFrameworkExecutionOptions options)
        : XunitTestAssemblyRunner(assembly, cases, diagnostics, execution, options)
    {
        protected override Task<RunSummary> RunTestCollectionAsync(IMessageBus messageBus, ITestCollection testCollection, IEnumerable<IXunitTestCase> testCases, CancellationTokenSource cancellationTokenSource) =>
            new CollectionRunner(testCollection, testCases, DiagnosticMessageSink, messageBus, TestCaseOrderer, new ExceptionAggregator(Aggregator), cancellationTokenSource).RunAsync();
    }

    private sealed class CollectionRunner(ITestCollection collection, IEnumerable<IXunitTestCase> cases, IMessageSink diagnostics, IMessageBus bus, ITestCaseOrderer orderer, ExceptionAggregator aggregator, CancellationTokenSource cts)
        : XunitTestCollectionRunner(collection, cases, diagnostics, bus, orderer, aggregator, cts)
    {
        protected override Task<RunSummary> RunTestClassAsync(ITestClass testClass, IReflectionTypeInfo @class, IEnumerable<IXunitTestCase> testCases) =>
            new ClassRunner(testClass, @class, testCases, DiagnosticMessageSink, MessageBus, TestCaseOrderer, new ExceptionAggregator(Aggregator), CancellationTokenSource, CollectionFixtureMappings).RunAsync();
    }

    private sealed class ClassRunner(ITestClass testClass, IReflectionTypeInfo @class, IEnumerable<IXunitTestCase> cases, IMessageSink diagnostics, IMessageBus bus, ITestCaseOrderer orderer, ExceptionAggregator aggregator, CancellationTokenSource cts, IDictionary<Type, object> collectionFixtures)
        : XunitTestClassRunner(testClass, @class, cases, diagnostics, bus, orderer, aggregator, cts, collectionFixtures)
    {
        protected override async Task<RunSummary> RunTestMethodAsync(ITestMethod testMethod, IReflectionMethodInfo method, IEnumerable<IXunitTestCase> testCases, object[] constructorArguments)
        {
            string? reason = PostgresTestServer.UnavailableReason;
            if (reason is null || Class.Type.IsDefined(typeof(NoPostgresAttribute), inherit: true))
            {
                return await base.RunTestMethodAsync(testMethod, method, testCases, constructorArguments);
            }

            var summary = new RunSummary();
            foreach (IXunitTestCase testCase in testCases)
            {
                summary.Aggregate(await new XunitTestCaseRunner(testCase, testCase.DisplayName, reason, constructorArguments, testCase.TestMethodArguments, MessageBus, new ExceptionAggregator(Aggregator), CancellationTokenSource).RunAsync());
            }

            return summary;
        }
    }
}

/// <summary>The class needs no PostgreSQL server and runs even when none is available.</summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class NoPostgresAttribute : Attribute
{
}
