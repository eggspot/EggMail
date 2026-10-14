using System.Text.Json;
using System.Xml.Linq;

namespace Mta.ArchitectureTests;

/// <summary>
/// CI guard for decision 4: the hand-written SMTP/mail-protocol stack uses only the .NET BCL and ASP.NET Core
/// shared framework. These assemblies must have no NuGet package references (direct or transitive) and may only
/// reference other guarded projects.
/// </summary>
public class PackageFreeStackTests
{
    public static readonly string[] GuardedProjects =
    [
        "Mta.Core", "Mta.Dns", "Mta.Mime", "Mta.Dkim", "Mta.Auth", "Mta.Dsn", "Mta.Tls",
        "Mta.Smtp.Protocol", "Mta.Smtp.Server", "Mta.Smtp.Client",
    ];

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EggMail.slnx")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new InvalidOperationException("EggMail.slnx not found above " + AppContext.BaseDirectory);
    }

    public static IEnumerable<object[]> Projects() => GuardedProjects.Select(p => new object[] { p });

    [Theory]
    [MemberData(nameof(Projects))]
    public void Guarded_project_has_no_package_references(string project)
    {
        string csproj = Path.Combine(RepoRoot(), "src", project, project + ".csproj");
        var doc = XDocument.Load(csproj);
        Assert.Empty(doc.Descendants("PackageReference"));
        Assert.Empty(doc.Descendants("PackageVersion"));
    }

    [Theory]
    [MemberData(nameof(Projects))]
    public void Guarded_project_only_references_guarded_projects(string project)
    {
        string csproj = Path.Combine(RepoRoot(), "src", project, project + ".csproj");
        var doc = XDocument.Load(csproj);
        foreach (var pr in doc.Descendants("ProjectReference"))
        {
            string name = Path.GetFileNameWithoutExtension(((string?)pr.Attribute("Include") ?? "").Replace((char)92, (char)47));
            Assert.Contains(name, GuardedProjects);
        }
    }

    [Theory]
    [MemberData(nameof(Projects))]
    public void Guarded_project_resolves_no_packages(string project)
    {
        // project.assets.json is produced by restore and lists transitive packages, which catches packages
        // introduced through props files or framework-dependent surprises.
        string assets = Path.Combine(RepoRoot(), "src", project, "obj", "project.assets.json");
        if (!File.Exists(assets))
        {
            // Not restored in this checkout (the project is not built by this test run). The csproj checks above still apply.
            return;
        }

        using var json = JsonDocument.Parse(File.ReadAllText(assets));
        var libraries = json.RootElement.GetProperty("libraries");
        var packages = libraries.EnumerateObject()
            .Where(l => l.Value.GetProperty("type").GetString() == "package")
            .Select(l => l.Name)
            .ToList();
        Assert.True(packages.Count == 0, $"{project} resolves packages: {string.Join(", ", packages)}");
    }

    [Fact]
    public void Solution_lists_all_guarded_projects()
    {
        string slnx = File.ReadAllText(Path.Combine(RepoRoot(), "EggMail.slnx"));
        foreach (string p in GuardedProjects)
        {
            Assert.Contains($"src/{p}/{p}.csproj", slnx.Replace('\\', '/'));
        }
    }

    [Fact]
    public void No_source_project_depends_on_the_fuzzing_projects_or_fuzzing_packages()
    {
        // The fuzz harness and its targets (fuzz/) reference the protocol assemblies; it must never be the other way round, and the
        // coverage-guided tooling (SharpFuzz) is allowed only in fuzz/Mta.Fuzz.Harness.
        string srcDirectory = Path.Combine(RepoRoot(), "src");
        foreach (string csproj in Directory.EnumerateFiles(srcDirectory, "*.csproj", SearchOption.AllDirectories))
        {
            var doc = XDocument.Load(csproj);
            foreach (var reference in doc.Descendants().Where(e => e.Name.LocalName is "ProjectReference" or "PackageReference"))
            {
                string include = ((string?)reference.Attribute("Include") ?? string.Empty).Replace((char)92, (char)47);
                Assert.DoesNotContain("fuzz", include, StringComparison.OrdinalIgnoreCase);
            }
        }

        var harness = XDocument.Load(Path.Combine(RepoRoot(), "fuzz", "Mta.Fuzz.Harness", "Mta.Fuzz.Harness.csproj"));
        Assert.Contains(harness.Descendants("PackageReference"), r => (string?)r.Attribute("Include") == "SharpFuzz");
        var targets = XDocument.Load(Path.Combine(RepoRoot(), "fuzz", "Mta.Fuzz.Targets", "Mta.Fuzz.Targets.csproj"));
        Assert.Empty(targets.Descendants("PackageReference"));   // the targets themselves stay BCL-only
    }
}
