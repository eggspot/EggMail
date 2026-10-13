using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Mta.Host.Tests.Api;

/// <summary>
/// A small reader for the TypeScript wire types of the dashboard (<c>dashboard/src/api/types.ts</c>): interfaces, aliases, unions, literals, arrays,
/// optional members and generics. It exists to check real API responses against the shapes the SPA is compiled against, without running Node.
/// </summary>
internal sealed class TsContract
{
    public abstract record TsType;

    public sealed record Prim(string Name) : TsType; // string, number, boolean, unknown, null, any

    public sealed record Literal(string Value) : TsType;

    public sealed record ArrayOf(TsType Element) : TsType;

    public sealed record Union(IReadOnlyList<TsType> Options) : TsType;

    public sealed record Ref(string Name, IReadOnlyList<TsType> Args) : TsType;

    public sealed record ObjectOf(IReadOnlyList<Member> Members, bool IndexSignature) : TsType;

    public sealed record Member(string Name, bool Optional, TsType Type);

    public sealed record Decl(IReadOnlyList<string> TypeParams, TsType Body);

    private readonly Dictionary<string, Decl> _decls = new(StringComparer.Ordinal);

    public static TsContract Load(string path)
    {
        var contract = new TsContract();
        contract.Parse(File.ReadAllText(path));
        return contract;
    }

    public static string FindDashboardTypes()
    {
        string? dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "EggMail.slnx")))
        {
            dir = Path.GetDirectoryName(dir);
        }

        Assert.NotNull(dir);
        return Path.Combine(dir!, "dashboard", "src", "api", "types.ts");
    }

    // Declarations

    private void Parse(string source)
    {
        source = Regex.Replace(source, @"/\*.*?\*/", "", RegexOptions.Singleline);
        source = Regex.Replace(source, @"//[^\n]*", "");
        int i = 0;
        while (i < source.Length)
        {
            Match m = Regex.Match(source[i..], @"export\s+(interface|type)\s+(\w+)(<[^>]*>)?");
            if (!m.Success)
            {
                break;
            }

            int start = i + m.Index + m.Length;
            var typeParams = m.Groups[3].Success ? m.Groups[3].Value.Trim('<', '>').Split(',', StringSplitOptions.TrimEntries).ToList() : new List<string>();
            if (m.Groups[1].Value == "interface")
            {
                Match ext = Regex.Match(source[start..], @"^\s*extends\s+(\w+)\s*");
                string? baseName = ext.Success ? ext.Groups[1].Value : null;
                int open = source.IndexOf('{', start);
                int close = Matching(source, open);
                var body = (ObjectOf)new Reader(source[open..(close + 1)]).ReadType();
                if (baseName is not null)
                {
                    var members = ((ObjectOf)_decls[baseName].Body).Members.Concat(body.Members).ToList();
                    body = new ObjectOf(members, body.IndexSignature);
                }

                _decls[m.Groups[2].Value] = new Decl(typeParams, body);
                i = close + 1;
            }
            else
            {
                int eq = source.IndexOf('=', start);
                int end = EndOfAlias(source, eq + 1);
                string text = source[(eq + 1)..end];
                if (!text.TrimStart().StartsWith('['))
                {
                    _decls[m.Groups[2].Value] = new Decl(typeParams, new Reader(text).ReadType());
                }

                i = end + 1;
            }
        }
    }

    private static int Matching(string s, int open)
    {
        int depth = 0;
        for (int i = open; i < s.Length; i++)
        {
            if (s[i] == '{') { depth++; }
            else if (s[i] == '}' && --depth == 0) { return i; }
        }

        throw new InvalidDataException("Unbalanced braces in types.ts");
    }

    private static int EndOfAlias(string s, int from)
    {
        int depth = 0;
        for (int i = from; i < s.Length; i++)
        {
            char c = s[i];
            if (c is '{' or '(' or '[') { depth++; }
            else if (c is '}' or ')' or ']') { depth--; }
            else if (c == ';' && depth == 0) { return i; }
        }

        return s.Length - 1;
    }

    // Type expressions

    private sealed class Reader(string text)
    {
        private int _p;

        public TsType ReadType()
        {
            var options = new List<TsType>();
            SkipWs();
            if (Peek() == '|')
            {
                _p++;
            }

            options.Add(ReadPrimary());
            while (true)
            {
                SkipWs();
                if (Peek() != '|')
                {
                    break;
                }

                _p++;
                options.Add(ReadPrimary());
            }

            return options.Count == 1 ? options[0] : new Union(options);
        }

        private TsType ReadPrimary()
        {
            SkipWs();
            TsType t;
            char c = Peek();
            if (c == '{')
            {
                t = ReadObject();
            }
            else if (c == '\'' || c == '"')
            {
                char quote = c;
                int end = text.IndexOf(quote, _p + 1);
                t = new Literal(text[(_p + 1)..end]);
                _p = end + 1;
            }
            else if (c == '(')
            {
                _p++;
                t = ReadType();
                SkipWs();
                _p++; // ')'
            }
            else
            {
                int start = _p;
                while (_p < text.Length && (char.IsLetterOrDigit(text[_p]) || text[_p] is '_' or '.'))
                {
                    _p++;
                }

                string name = text[start.._p];
                var args = new List<TsType>();
                SkipWs();
                if (Peek() == '<')
                {
                    _p++;
                    while (true)
                    {
                        args.Add(ReadType());
                        SkipWs();
                        if (Peek() == ',') { _p++; continue; }
                        _p++; // '>'
                        break;
                    }
                }

                t = name switch
                {
                    "string" or "number" or "boolean" or "unknown" or "any" or "null" or "undefined" or "void" => new Prim(name),
                    _ => new Ref(name, args),
                };
            }

            while (true)
            {
                SkipWs();
                if (Peek() == '[' && _p + 1 < text.Length && text[_p + 1] == ']')
                {
                    _p += 2;
                    t = new ArrayOf(t);
                }
                else
                {
                    break;
                }
            }

            return t;
        }

        private ObjectOf ReadObject()
        {
            _p++; // '{'
            var members = new List<Member>();
            bool index = false;
            while (true)
            {
                SkipWs();
                if (Peek() == '}')
                {
                    _p++;
                    break;
                }

                if (Peek() == '[')
                {
                    // [extra: string]: unknown
                    int close = text.IndexOf(']', _p);
                    _p = close + 1;
                    SkipWs();
                    _p++; // ':'
                    ReadType();
                    index = true;
                }
                else
                {
                    int start = _p;
                    while (_p < text.Length && (char.IsLetterOrDigit(text[_p]) || text[_p] == '_'))
                    {
                        _p++;
                    }

                    string name = text[start.._p];
                    SkipWs();
                    bool optional = false;
                    if (Peek() == '?')
                    {
                        optional = true;
                        _p++;
                        SkipWs();
                    }

                    _p++; // ':'
                    members.Add(new Member(name, optional, ReadType()));
                }

                SkipWs();
                if (Peek() is ';' or ',')
                {
                    _p++;
                }
            }

            return new ObjectOf(members, index);
        }

        private char Peek() => _p < text.Length ? text[_p] : '\0';

        private void SkipWs()
        {
            while (_p < text.Length && char.IsWhiteSpace(text[_p]))
            {
                _p++;
            }
        }
    }

    // Checking

    /// <summary>Checks <paramref name="value"/> against a type expression such as <c>Domain[]</c> or <c>Page&lt;MessageSummary&gt;</c>; returns every mismatch ("path: reason").</summary>
    public IReadOnlyList<string> Check(string typeExpression, JsonElement value)
    {
        var problems = new List<string>();
        Visit(new Reader(typeExpression).ReadType(), value, "$", new Dictionary<string, TsType>(), problems);
        return problems;
    }

    public bool Has(string typeName) => _decls.ContainsKey(typeName);

    /// <summary>Member names of an interface (including inherited ones).</summary>
    public IReadOnlyList<string> MembersOf(string typeName) => ((ObjectOf)_decls[typeName].Body).Members.Select(m => m.Name).ToList();

    private void Visit(TsType type, JsonElement value, string path, Dictionary<string, TsType> env, List<string> problems)
    {
        switch (type)
        {
            case Prim p:
                CheckPrim(p.Name, value, path, problems);
                break;
            case Literal l:
                if (value.ValueKind != JsonValueKind.String || value.GetString() != l.Value)
                {
                    problems.Add($"{path}: expected the literal '{l.Value}' but got {Describe(value)}");
                }

                break;
            case ArrayOf a:
                if (value.ValueKind != JsonValueKind.Array)
                {
                    problems.Add($"{path}: expected an array but got {Describe(value)}");
                    break;
                }

                int index = 0;
                foreach (JsonElement item in value.EnumerateArray())
                {
                    Visit(a.Element, item, $"{path}[{index++}]", env, problems);
                }

                break;
            case Union u:
                CheckUnion(u, value, path, env, problems);
                break;
            case ObjectOf o:
                CheckObject(o, value, path, env, problems);
                break;
            case Ref r:
                if (env.TryGetValue(r.Name, out TsType? bound))
                {
                    Visit(bound, value, path, env, problems);
                    break;
                }

                if (r.Name == "Record")
                {
                    if (value.ValueKind != JsonValueKind.Object)
                    {
                        problems.Add($"{path}: expected an object but got {Describe(value)}");
                    }

                    break;
                }

                if (!_decls.TryGetValue(r.Name, out Decl? decl))
                {
                    problems.Add($"{path}: unknown type {r.Name} in types.ts");
                    break;
                }

                var inner = new Dictionary<string, TsType>(env);
                for (int i = 0; i < decl.TypeParams.Count && i < r.Args.Count; i++)
                {
                    inner[decl.TypeParams[i]] = r.Args[i];
                }

                Visit(decl.Body, value, path, inner, problems);
                break;
        }
    }

    private static void CheckPrim(string name, JsonElement value, string path, List<string> problems)
    {
        bool ok = name switch
        {
            "string" => value.ValueKind == JsonValueKind.String,
            "number" => value.ValueKind == JsonValueKind.Number,
            "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
            "null" => value.ValueKind == JsonValueKind.Null,
            "unknown" or "any" => true,
            _ => false,
        };
        if (!ok)
        {
            problems.Add($"{path}: expected {name} but got {Describe(value)}");
        }
    }

    private void CheckUnion(Union u, JsonElement value, string path, Dictionary<string, TsType> env, List<string> problems)
    {
        foreach (TsType option in u.Options)
        {
            var attempt = new List<string>();
            Visit(option, value, path, env, attempt);
            if (attempt.Count == 0)
            {
                return;
            }
        }

        problems.Add($"{path}: {Describe(value)} matches none of the union members");
    }

    private void CheckObject(ObjectOf o, JsonElement value, string path, Dictionary<string, TsType> env, List<string> problems)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            problems.Add($"{path}: expected an object but got {Describe(value)}");
            return;
        }

        foreach (Member m in o.Members)
        {
            if (!value.TryGetProperty(m.Name, out JsonElement member))
            {
                if (!m.Optional)
                {
                    problems.Add($"{path}.{m.Name}: required member is missing");
                }

                continue;
            }

            Visit(m.Type, member, $"{path}.{m.Name}", env, problems);
        }
    }

    private static string Describe(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.String => $"string \"{Truncate(e.GetString()!)}\"",
        JsonValueKind.Number => "number " + e.GetRawText(),
        JsonValueKind.Null => "null",
        _ => e.ValueKind.ToString().ToLowerInvariant(),
    };

    private static string Truncate(string s) => s.Length <= 40 ? s : s[..40] + "...";

    public override string ToString() => new StringBuilder().AppendJoin(", ", _decls.Keys).ToString();
}
