using BenchmarkDotNet.Running;

// Run all benchmarks:   dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*"
// Run one class:        dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*Dkim*"
BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
