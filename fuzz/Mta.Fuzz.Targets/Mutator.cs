namespace Mta.Fuzz;

/// <summary>
/// A small, deterministic mutation engine (same seed, same inputs on every machine and runtime): bit and byte flips, interesting
/// values, insertion and deletion of ranges, duplication and amplification of chunks, splicing between seeds, dictionary tokens,
/// line-ending rewrites and truncation. It is not coverage-guided; the coverage-guided search is done by libFuzzer in the fuzz
/// workflow. This engine is what makes <c>dotnet test</c> replay a reproducible, bounded slice of the same space.
/// </summary>
public sealed class Mutator
{
    private static readonly byte[] Interesting = [0x00, 0x01, 0x07, 0x09, 0x0A, 0x0D, 0x1F, 0x20, 0x22, 0x28, 0x29, 0x2C, 0x2E, 0x2F, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x40, 0x5C, 0x7F, 0x80, 0xBF, 0xC0, 0xC1, 0xE0, 0xF0, 0xFE, 0xFF];

    private readonly Random _random;
    private readonly IReadOnlyList<byte[]> _seeds;
    private readonly IReadOnlyList<byte[]> _tokens;
    private readonly int _maxLength;

    public Mutator(int seed, IReadOnlyList<byte[]> seeds, IReadOnlyList<byte[]> tokens, int maxLength)
    {
        _random = new Random(seed);
        _seeds = seeds;
        _tokens = tokens;
        _maxLength = maxLength;
    }

    /// <summary>Returns the next input: a randomly chosen seed with 1 to 6 mutations applied.</summary>
    public byte[] Next()
    {
        var data = new List<byte>(_seeds.Count == 0 ? [] : _seeds[_random.Next(_seeds.Count)]);
        int steps = 1 + _random.Next(6);
        for (int i = 0; i < steps; i++)
        {
            MutateOnce(data);
            if (data.Count > _maxLength)
            {
                data.RemoveRange(_maxLength, data.Count - _maxLength);
            }
        }

        return data.ToArray();
    }

    private void MutateOnce(List<byte> data)
    {
        switch (_random.Next(14))
        {
            case 0 when data.Count > 0:
                data[_random.Next(data.Count)] ^= (byte)(1 << _random.Next(8));
                break;
            case 1 when data.Count > 0:
                data[_random.Next(data.Count)] = (byte)_random.Next(256);
                break;
            case 2 when data.Count > 0:
                data[_random.Next(data.Count)] = Interesting[_random.Next(Interesting.Length)];
                break;
            case 3:
                data.Insert(_random.Next(data.Count + 1), Interesting[_random.Next(Interesting.Length)]);
                break;
            case 4 when data.Count > 0:
                {
                    int start = _random.Next(data.Count);
                    data.RemoveRange(start, Math.Min(data.Count - start, 1 + _random.Next(16)));
                    break;
                }

            case 5 when data.Count > 0:
                {
                    int start = _random.Next(data.Count);
                    int length = Math.Min(data.Count - start, 1 + _random.Next(64));
                    data.InsertRange(_random.Next(data.Count + 1), data.GetRange(start, length));
                    break;
                }

            case 6 when data.Count > 0:
                {
                    // Amplify a chunk: the way to find quadratic behaviour and limit bypasses.
                    int start = _random.Next(data.Count);
                    int length = Math.Min(data.Count - start, 1 + _random.Next(24));
                    var chunk = data.GetRange(start, length);
                    int copies = 2 + _random.Next(_random.Next(8) == 0 ? 4000 : 60);
                    var repeated = new List<byte>(length * copies);
                    for (int i = 0; i < copies && repeated.Count < _maxLength; i++)
                    {
                        repeated.AddRange(chunk);
                    }

                    data.InsertRange(start, repeated);
                    break;
                }

            case 7 when _seeds.Count > 0:
                {
                    // Splice a piece of another seed.
                    byte[] other = _seeds[_random.Next(_seeds.Count)];
                    if (other.Length > 0)
                    {
                        int start = _random.Next(other.Length);
                        int length = Math.Min(other.Length - start, 1 + _random.Next(128));
                        data.InsertRange(_random.Next(data.Count + 1), other.AsSpan(start, length).ToArray());
                    }

                    break;
                }

            case 8 or 9 when _tokens.Count > 0:
                data.InsertRange(_random.Next(data.Count + 1), _tokens[_random.Next(_tokens.Count)]);
                break;
            case 10 when _tokens.Count > 0 && data.Count > 0:
                {
                    // Replace a stretch with a token.
                    int start = _random.Next(data.Count);
                    data.RemoveRange(start, Math.Min(data.Count - start, 1 + _random.Next(8)));
                    data.InsertRange(start, _tokens[_random.Next(_tokens.Count)]);
                    break;
                }

            case 11:
                RewriteLineEndings(data);
                break;
            case 12 when data.Count > 1:
                {
                    // Truncate at a random point.
                    int keep = _random.Next(data.Count);
                    data.RemoveRange(keep, data.Count - keep);
                    break;
                }

            case 13 when data.Count > 0:
                {
                    // Drop the first bytes (the parser then starts in the middle of a construct).
                    data.RemoveRange(0, _random.Next(data.Count));
                    break;
                }

            default:
                data.Add((byte)_random.Next(256));
                break;
        }
    }

    private void RewriteLineEndings(List<byte> data)
    {
        byte[] replacement = _random.Next(4) switch
        {
            0 => [(byte)'\n'],
            1 => [(byte)'\r'],
            2 => [(byte)'\r', (byte)'\r', (byte)'\n'],
            _ => [(byte)'\r', (byte)'\n', (byte)' '],
        };
        int rewritten = 0;
        for (int i = 0; i + 1 < data.Count && rewritten < 4; i++)
        {
            if (data[i] == '\r' && data[i + 1] == '\n' && _random.Next(3) == 0)
            {
                data.RemoveRange(i, 2);
                data.InsertRange(i, replacement);
                i += replacement.Length - 1;
                rewritten++;
            }
        }
    }
}
