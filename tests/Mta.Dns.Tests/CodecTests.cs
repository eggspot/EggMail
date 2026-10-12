using System.Net;

namespace Mta.Dns.Tests;

public class QueryWriterTests
{
    private static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b).ToLowerInvariant();

    [Fact]
    public void Plain_query_matches_the_rfc1035_layout()
    {
        // ID abcd, RD, 1 question, example.com IN A
        var q = DnsMessageWriter.BuildQuery(0xABCD, "example.com", DnsRecordType.A, new DnsQueryOptions(EdnsUdpPayloadSize: 0));
        Assert.Equal("abcd010000010000000000000765" + "78616d706c6503636f6d0000010001", Hex(q));
    }

    [Fact]
    public void Edns_query_carries_an_opt_record_with_the_payload_size()
    {
        var q = DnsMessageWriter.BuildQuery(0x0001, "example.com", DnsRecordType.MX, DnsQueryOptions.Default);
        // ARCOUNT 1; OPT: root, type 41, class 1232 (0x04d0), TTL 0, RDLEN 0
        Assert.Equal("0001" + "0100" + "0001" + "0000" + "0000" + "0001"
            + "076578616d706c6503636f6d00" + "000f" + "0001"
            + "00" + "0029" + "04d0" + "00000000" + "0000", Hex(q));
    }

    [Fact]
    public void Dnssec_ok_and_flag_bits_are_encoded()
    {
        var q = DnsMessageWriter.BuildQuery(1, "a.b", DnsRecordType.TLSA,
            new DnsQueryOptions(RecursionDesired: true, EdnsUdpPayloadSize: 4096, DnssecOk: true, AuthenticData: true, CheckingDisabled: true));
        Assert.True(DnsWire.TryReadHeader(q, out var h));
        Assert.True(h.RecursionDesired);
        Assert.True(h.AuthenticData);
        Assert.True(h.CheckingDisabled);
        Assert.False(h.IsResponse);
        Assert.Equal(1, h.AdditionalCount);
        // OPT is the last 11 bytes: class (size) 4096, flags 0x8000 (DO)
        Assert.Equal("00" + "0029" + "1000" + "00" + "00" + "8000" + "0000", Hex(q.AsSpan(q.Length - 11)));
    }

    [Fact]
    public void Edns_size_below_512_is_raised_to_512()
    {
        var q = DnsMessageWriter.BuildQuery(1, "a.b", DnsRecordType.A, new DnsQueryOptions(EdnsUdpPayloadSize: 100));
        Assert.Equal("0029" + "0200", Hex(q.AsSpan(q.Length - 10, 4)));
    }

    [Fact]
    public void Trailing_dot_is_accepted_and_the_root_name_is_a_single_zero_byte()
    {
        var a = DnsMessageWriter.BuildQuery(7, "example.com.", DnsRecordType.A, new DnsQueryOptions(EdnsUdpPayloadSize: 0));
        var b = DnsMessageWriter.BuildQuery(7, "example.com", DnsRecordType.A, new DnsQueryOptions(EdnsUdpPayloadSize: 0));
        Assert.Equal(a, b);
        var root = DnsMessageWriter.BuildQuery(7, "", DnsRecordType.NS, new DnsQueryOptions(EdnsUdpPayloadSize: 0));
        Assert.Equal(12 + 1 + 4, root.Length);
    }

    [Fact]
    public void Letter_case_is_preserved_on_the_wire_for_0x20()
    {
        var q = DnsMessageWriter.BuildQuery(1, "ExAmPlE.CoM", DnsRecordType.A, new DnsQueryOptions(EdnsUdpPayloadSize: 0));
        Assert.Contains("ExAmPlE", System.Text.Encoding.ASCII.GetString(q));
    }

    [Theory]
    [InlineData("a..b")]
    [InlineData("..")]
    [InlineData("a b.example")]
    [InlineData("a\\b")]
    [InlineData("é.example")]
    public void Invalid_names_are_rejected_with_DnsException(string name)
    {
        var ex = Assert.Throws<DnsException>(() => DnsMessageWriter.BuildQuery(1, name, DnsRecordType.A, DnsQueryOptions.Default));
        Assert.Equal(DnsFailureReason.InvalidRequest, ex.Reason);
    }

    [Fact]
    public void Label_and_name_length_limits_are_enforced()
    {
        string label63 = new('a', 63);
        DnsMessageWriter.BuildQuery(1, label63 + ".example", DnsRecordType.A, DnsQueryOptions.Default);
        Assert.Throws<DnsException>(() => DnsMessageWriter.BuildQuery(1, new string('a', 64) + ".example", DnsRecordType.A, DnsQueryOptions.Default));

        string name253 = string.Join('.', new[] { new string('a', 63), new string('b', 63), new string('c', 63), new string('d', 61) });
        Assert.Equal(253, name253.Length);
        var ok = DnsMessageWriter.BuildQuery(1, name253, DnsRecordType.A, DnsQueryOptions.Default);
        Assert.True(ok.Length <= DnsMessageWriter.MaxQueryLength);
        Assert.Throws<DnsException>(() => DnsMessageWriter.BuildQuery(1, name253 + "a", DnsRecordType.A, DnsQueryOptions.Default));
    }

    [Fact]
    public void Too_small_a_destination_is_an_argument_error()
    {
        Assert.Throws<ArgumentException>(() => DnsMessageWriter.WriteQuery(new byte[10], 1, "example.com", DnsRecordType.A, DnsQueryOptions.Default));
    }

    [Fact]
    public void Writing_a_query_does_not_allocate()
    {
        Span<byte> buffer = stackalloc byte[DnsMessageWriter.MaxQueryLength];
        var options = DnsQueryOptions.Default;
        for (int i = 0; i < 100; i++)
        {
            DnsMessageWriter.WriteQuery(buffer, 1, "mail.example.com", DnsRecordType.MX, in options);
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 1000; i++)
        {
            DnsMessageWriter.WriteQuery(buffer, (ushort)i, "mail.example.com", DnsRecordType.MX, in options);
        }

        Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
    }
}

public class ResponseReaderTests
{
    private static byte[] FromHex(string hex) => Convert.FromHexString(hex.Replace(" ", string.Empty));

    [Fact]
    public void Parses_a_hand_assembled_A_response_with_a_compressed_owner_name()
    {
        // abcd 8180 qd1 an1; question example.com A IN; answer c00c A IN ttl 3600 len 4 93.184.216.34
        var packet = FromHex("abcd 8180 0001 0001 0000 0000 076578616d706c6503636f6d00 0001 0001 c00c 0001 0001 00000e10 0004 5db8d822");
        var m = DnsMessageReader.Parse(packet);
        Assert.Equal(0xABCD, m.Id);
        Assert.True(m.Header.IsResponse);
        Assert.True(m.Header.RecursionAvailable);
        Assert.Equal(DnsRcode.NoError, m.Rcode);
        Assert.Equal("example.com", m.QuestionName);
        Assert.Equal(DnsRecordType.A, m.QuestionType);
        var a = Assert.IsType<ARecord>(Assert.Single(m.Answers));
        Assert.Equal("example.com", a.Name);
        Assert.Equal(3600u, a.Ttl);
        Assert.Equal(IPAddress.Parse("93.184.216.34"), a.Address);
    }

    [Fact]
    public void Parses_an_MX_response_whose_exchange_uses_a_compression_pointer()
    {
        // MX 10 mail.example.com. -> rdata: 000a 04 'mail' c00c
        var packet = FromHex("0001 8180 0001 0001 0000 0000 076578616d706c6503636f6d00 000f 0001 c00c 000f 0001 0000012c 0009 000a 046d61696c c00c");
        var m = DnsMessageReader.Parse(packet);
        var mx = Assert.IsType<MxRecord>(Assert.Single(m.Answers));
        Assert.Equal((ushort)10, mx.Preference);
        Assert.Equal("mail.example.com", mx.Exchange);
    }

    [Fact]
    public void Round_trips_every_supported_record_type()
    {
        var packet = PacketBuilder.Response(42, "Example.COM", DnsRecordType.ANY)
            .A("example.com", "192.0.2.1", 60)
            .Aaaa("example.com", "2001:db8::1", 61)
            .Cname("www.example.com", "example.com", 62)
            .Ns("example.com", "ns1.example.com", 63)
            .Ptr("1.2.0.192.in-addr.arpa", "example.com", 64)
            .Mx("example.com", 5, "mx.example.com", 65)
            .Txt("example.com", "v=spf1 ", "include:_spf.example.com ", "-all")
            .Tlsa("_25._tcp.example.com", 3, 1, 1, [1, 2, 3, 4], 66)
            .Raw("example.com", 99, [9, 8, 7], 67)
            .Soa("example.com", 3600, 120, authority: false)
            .Build();

        var m = DnsMessageReader.Parse(packet);
        Assert.Equal("example.com", m.QuestionName);
        Assert.Equal(10, m.Answers.Count);
        Assert.Equal(new ARecord("example.com", 60, IPAddress.Parse("192.0.2.1")), m.Answers[0]);
        Assert.Equal(new AaaaRecord("example.com", 61, IPAddress.Parse("2001:db8::1")), m.Answers[1]);
        Assert.Equal(new CnameRecord("www.example.com", 62, "example.com"), m.Answers[2]);
        Assert.Equal(new NsRecord("example.com", 63, "ns1.example.com"), m.Answers[3]);
        Assert.Equal(new PtrRecord("1.2.0.192.in-addr.arpa", 64, "example.com"), m.Answers[4]);
        Assert.Equal(new MxRecord("example.com", 65, 5, "mx.example.com"), m.Answers[5]);
        Assert.Equal("v=spf1 include:_spf.example.com -all", Assert.IsType<TxtRecord>(m.Answers[6]).Text);
        var tlsa = Assert.IsType<TlsaRecord>(m.Answers[7]);
        Assert.Equal("_25._tcp.example.com", tlsa.Name);
        Assert.Equal((3, 1, 1), (tlsa.Usage, tlsa.Selector, tlsa.MatchingType));
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, tlsa.Data);
        var unknown = Assert.IsType<UnknownRecord>(m.Answers[8]);
        Assert.Equal((ushort)99, unknown.RawType);
        Assert.Equal(new byte[] { 9, 8, 7 }, unknown.Data);
        var soa = Assert.IsType<SoaRecord>(m.Answers[9]);
        Assert.Equal("ns.example", soa.MName);
        Assert.Equal("hostmaster.example", soa.RName);
        Assert.Equal(120u, soa.Minimum);
        Assert.Equal(900u, soa.Retry);
    }

    [Fact]
    public void Round_trips_without_compression_too()
    {
        var packet = new PacketBuilder { Id = 1, Compress = false }.SetQuestion("a.example", 15)
            .Mx("a.example", 1, "b.a.example").Build();
        var m = DnsMessageReader.Parse(packet);
        Assert.Equal("b.a.example", Assert.IsType<MxRecord>(Assert.Single(m.Answers)).Exchange);
    }

    [Fact]
    public void Txt_with_one_string_and_with_empty_strings_and_with_long_total()
    {
        var packet = PacketBuilder.Response(1, "t.example", DnsRecordType.TXT)
            .Txt("t.example", "hello")
            .Txt("t.example", "", "a", "", "b")
            .Txt("t.example", new string('x', 255), new string('y', 255), new string('z', 255))
            .Raw("t.example", 16, [])
            .Build();
        var m = DnsMessageReader.Parse(packet);
        var texts = m.Answers.Cast<TxtRecord>().Select(t => t.Text).ToArray();
        Assert.Equal("hello", texts[0]);
        Assert.Equal("ab", texts[1]);
        Assert.Equal(new string('x', 255) + new string('y', 255) + new string('z', 255), texts[2]);
        Assert.Equal(string.Empty, texts[3]);
    }

    [Fact]
    public void Txt_string_that_overruns_its_record_is_malformed()
    {
        var packet = PacketBuilder.Response(1, "t.example", DnsRecordType.TXT).Raw("t.example", 16, [5, (byte)'a', (byte)'b']).Build();
        var ex = Assert.Throws<DnsException>(() => DnsMessageReader.Parse(packet));
        Assert.Equal(DnsFailureReason.MalformedResponse, ex.Reason);
    }

    [Fact]
    public void Negative_ttl_is_the_smaller_of_soa_ttl_and_minimum()
    {
        var nx = DnsMessageReader.Parse(PacketBuilder.Response(1, "nope.example", DnsRecordType.A, rcode: 3).Soa("example", 900, 60).Build());
        Assert.Equal(DnsRcode.NameError, nx.Rcode);
        Assert.Empty(nx.Answers);
        Assert.Equal(60u, nx.NegativeTtl);

        var nodata = DnsMessageReader.Parse(PacketBuilder.Response(1, "x.example", DnsRecordType.A).Soa("example", 30, 600).Build());
        Assert.Equal(30u, nodata.NegativeTtl);

        var none = DnsMessageReader.Parse(PacketBuilder.Response(1, "x.example", DnsRecordType.A).Build());
        Assert.Null(none.NegativeTtl);
    }

    [Fact]
    public void Additional_section_is_counted_but_not_parsed()
    {
        // The additional record is garbage (bad A length) and must be ignored.
        var packet = PacketBuilder.Response(1, "a.example", DnsRecordType.A)
            .A("a.example", "192.0.2.1")
            .Add("glue.example", 1, 60, w => w.Bytes([1, 2, 3]), additional: true)
            .Build();
        var m = DnsMessageReader.Parse(packet);
        Assert.Single(m.Answers);
        Assert.Equal(1, m.AdditionalCount);
    }

    [Fact]
    public void Records_of_a_class_other_than_IN_are_skipped()
    {
        var packet = PacketBuilder.Response(1, "a.example", DnsRecordType.A)
            .Add("a.example", 1, 60, w => w.Bytes([1, 2, 3, 4]), cls: 3)
            .A("a.example", "192.0.2.9")
            .Build();
        var m = DnsMessageReader.Parse(packet);
        Assert.Equal(IPAddress.Parse("192.0.2.9"), Assert.IsType<ARecord>(Assert.Single(m.Answers)).Address);
    }

    [Fact]
    public void Ttl_with_the_high_bit_set_is_treated_as_zero()
    {
        var packet = PacketBuilder.Response(1, "a.example", DnsRecordType.A).A("a.example", "192.0.2.1", 0x80000001).Build();
        Assert.Equal(0u, DnsMessageReader.Parse(packet).Answers[0].Ttl);
    }

    [Fact]
    public void Flags_are_decoded()
    {
        var packet = PacketBuilder.Response(1, "a.example", DnsRecordType.A).Truncated().AuthenticData().Build();
        var m = DnsMessageReader.Parse(packet);
        Assert.True(m.Truncated);
        Assert.True(m.AuthenticData);
        var refused = DnsMessageReader.Parse(PacketBuilder.Response(1, "a.example", DnsRecordType.A, rcode: 5).Build());
        Assert.Equal(DnsRcode.Refused, refused.Rcode);
    }

    [Fact]
    public void Names_are_lowercased_and_odd_bytes_are_escaped()
    {
        var packet = PacketBuilder.Response(1, "a.example", DnsRecordType.A)
            .Add("MiXeD.Example", 5, 60, w => w.Bytes([3, (byte)'a', (byte)'.', (byte)'b', 1, (byte)'\\', 2, 0x20, 0xFF, 0]))
            .Build();
        var cname = Assert.IsType<CnameRecord>(Assert.Single(DnsMessageReader.Parse(packet).Answers));
        Assert.Equal("mixed.example", cname.Name);
        Assert.Equal("a\\.b.\\\\.\\032\\255", cname.Target);
    }

    [Fact]
    public void Rdata_with_the_wrong_length_is_malformed()
    {
        foreach (var (type, data) in new (ushort, byte[])[]
        {
            (1, [1, 2, 3]), (1, [1, 2, 3, 4, 5]), (28, new byte[15]), (15, [0, 1]), (52, [1, 2]),
            (5, [0, 0]),         // name followed by a stray byte
            (5, []),             // empty
            (6, [0, 0, 1, 2, 3]),
        })
        {
            var packet = PacketBuilder.Response(1, "a.example", DnsRecordType.A).Raw("a.example", type, data).Build();
            var ex = Assert.Throws<DnsException>(() => DnsMessageReader.Parse(packet));
            Assert.Equal(DnsFailureReason.MalformedResponse, ex.Reason);
        }
    }

    [Fact]
    public void A_name_inside_rdata_must_not_extend_beyond_the_record()
    {
        // CNAME rdata length is 1 but the inline name that starts there is 7 bytes long (05 'aaaaa' 00).
        var packet = Convert.FromHexString("000181800001000100000000" + "016100" + "00050001" + "c00c" + "0005" + "0001" + "0000003c" + "0001" + "05" + "6161616161" + "00");
        Assert.Throws<DnsException>(() => DnsMessageReader.Parse(packet));
    }

    [Fact]
    public void Self_pointing_compression_pointer_is_rejected()
    {
        // The question name is a pointer to offset 12, which is the pointer itself.
        var packet = Convert.FromHexString("000181800001000000000000" + "c00c" + "00010001");
        var ex = Assert.Throws<DnsException>(() => DnsMessageReader.Parse(packet));
        Assert.Equal(DnsFailureReason.MalformedResponse, ex.Reason);
    }

    [Fact]
    public void Forward_pointer_is_rejected()
    {
        // Answer owner points forward to a name that appears later in the packet.
        var packet = Convert.FromHexString("000181800000000100000000" + "c01a" + "0001" + "0001" + "00000000" + "0004" + "01020304" + "0161" + "00");
        Assert.Throws<DnsException>(() => DnsMessageReader.Parse(packet));
    }

    [Fact]
    public void Two_pointers_that_point_at_each_other_cannot_loop()
    {
        // offset 12: ptr -> 14 ; offset 14: ptr -> 12
        var packet = Convert.FromHexString("000181800001000000000000" + "c00e" + "c00c" + "00010001");
        Assert.Throws<DnsException>(() => DnsMessageReader.Parse(packet));
    }

    private static byte[] PointerChainPacket(int pointers)
    {
        // Question "a."; record 1 (type 99, never decoded) whose rdata is a chain of N pointers, each pointing at the
        // one before (the first at the question name); record 2 whose owner name points at the end of that chain.
        var packet = new List<byte>(Convert.FromHexString("000181800001000200000000"));
        packet.AddRange([1, (byte)'a', 0, 0, 1, 0, 1]);
        packet.AddRange([0xC0, 12, 0, 99, 0, 1, 0, 0, 0, 0, (byte)(pointers * 2 >> 8), (byte)(pointers * 2)]);
        int rdataStart = packet.Count;
        int previous = 12;
        for (int i = 0; i < pointers; i++)
        {
            packet.Add((byte)(0xC0 | (previous >> 8)));
            packet.Add((byte)previous);
            previous = rdataStart + 2 * i;
        }

        packet.Add((byte)(0xC0 | (previous >> 8)));
        packet.Add((byte)previous);
        packet.AddRange(Convert.FromHexString("0001" + "0001" + "00000000" + "0004" + "01020304"));
        return packet.ToArray();
    }

    [Fact]
    public void A_long_chain_of_backward_pointers_is_cut_off()
    {
        var ex = Assert.Throws<DnsException>(() => DnsMessageReader.Parse(PointerChainPacket(200)));
        Assert.Contains("compression", ex.Message);
    }

    [Fact]
    public void A_short_chain_of_backward_pointers_is_fine()
    {
        Assert.Equal("a", DnsMessageReader.Parse(PointerChainPacket(100)).Answers[1].Name);
    }

    [Fact]
    public void Reserved_label_types_and_oversized_names_are_rejected()
    {
        // 0x40 prefix is an (obsolete) extended label type
        Assert.Throws<DnsException>(() => DnsMessageReader.Parse(Convert.FromHexString("000181800001000000000000" + "4001" + "00010001")));

        // A 4 x 63-byte label name is 257 bytes on the wire.
        var name = new List<byte>();
        for (int i = 0; i < 4; i++)
        {
            name.Add(63);
            name.AddRange(Enumerable.Repeat((byte)'a', 63));
        }

        name.Add(0);
        var packet = new List<byte>(Convert.FromHexString("000181800001000000000000"));
        packet.AddRange(name);
        packet.AddRange(Convert.FromHexString("00010001"));
        Assert.Throws<DnsException>(() => DnsMessageReader.Parse(packet.ToArray()));
    }

    [Fact]
    public void A_name_of_exactly_255_wire_bytes_is_accepted()
    {
        var name = new List<byte>();
        foreach (int len in new[] { 63, 63, 63, 61 })
        {
            name.Add((byte)len);
            name.AddRange(Enumerable.Repeat((byte)'a', len));
        }

        name.Add(0);
        Assert.Equal(255, name.Count);
        var packet = new List<byte>(Convert.FromHexString("000181800001000000000000"));
        packet.AddRange(name);
        packet.AddRange(Convert.FromHexString("00010001"));
        var m = DnsMessageReader.Parse(packet.ToArray());
        Assert.Equal(253, m.QuestionName!.Length);
    }

    [Fact]
    public void Header_counts_larger_than_the_packet_are_rejected_without_huge_allocations()
    {
        var packet = Convert.FromHexString("000181800000ffff00000000");
        Assert.Throws<DnsException>(() => DnsMessageReader.Parse(packet));
    }

    [Fact]
    public void More_than_one_question_is_rejected()
    {
        Assert.Throws<DnsException>(() => DnsMessageReader.Parse(Convert.FromHexString("000181800002000000000000")));
    }

    [Fact]
    public void A_question_with_a_class_other_than_IN_is_rejected()
    {
        Assert.Throws<DnsException>(() => DnsMessageReader.Parse(Convert.FromHexString("000181800001000000000000" + "0161" + "00" + "0001" + "0003")));
    }

    public static IEnumerable<object[]> SamplePackets()
    {
        yield return [PacketBuilder.Response(1, "example.com", DnsRecordType.A).A("example.com", "192.0.2.1").Aaaa("example.com", "2001:db8::2").Build()];
        yield return [PacketBuilder.Response(2, "example.com", DnsRecordType.MX).Mx("example.com", 10, "mail.example.com").Mx("example.com", 20, "mail2.example.com").Build()];
        yield return [PacketBuilder.Response(3, "example.com", DnsRecordType.TXT).Txt("example.com", "v=spf1", " -all").Soa("example.com", 100, 50).Build()];
        yield return [PacketBuilder.Response(4, "www.example.com", DnsRecordType.A).Cname("www.example.com", "edge.cdn.example.net").A("edge.cdn.example.net", "198.51.100.7").Build()];
        yield return [PacketBuilder.Response(5, "x.example.com", DnsRecordType.A, rcode: 3).Soa("example.com", 100, 50).Build()];
        yield return [PacketBuilder.Response(6, "_25._tcp.mx.example.com", DnsRecordType.TLSA).Tlsa("_25._tcp.mx.example.com", 3, 1, 1, new byte[32]).Build()];
    }

    [Theory]
    [MemberData(nameof(SamplePackets))]
    public void Every_prefix_of_a_valid_packet_parses_or_throws_DnsException_only(byte[] packet)
    {
        Assert.NotNull(DnsMessageReader.Parse(packet));
        int failures = 0;
        for (int length = 0; length < packet.Length; length++)
        {
            try
            {
                DnsMessageReader.Parse(packet.AsSpan(0, length));
            }
            catch (DnsException)
            {
                failures++;
            }
        }

        Assert.True(failures > 0);
    }

    [Theory]
    [MemberData(nameof(SamplePackets))]
    public void Random_mutations_of_valid_packets_never_throw_anything_but_DnsException(byte[] packet)
    {
        var random = new Random(20260101);
        for (int i = 0; i < 4000; i++)
        {
            var mutated = (byte[])packet.Clone();
            int changes = random.Next(1, 6);
            for (int c = 0; c < changes; c++)
            {
                mutated[random.Next(mutated.Length)] = (byte)random.Next(256);
            }

            try
            {
                DnsMessageReader.Parse(mutated);
            }
            catch (DnsException)
            {
            }
        }
    }

    [Fact]
    public void Random_bytes_never_throw_anything_but_DnsException()
    {
        var random = new Random(12345);
        byte[] buffer = new byte[700];
        for (int i = 0; i < 20000; i++)
        {
            int length = random.Next(0, buffer.Length);
            random.NextBytes(buffer.AsSpan(0, length));
            if (length >= 12 && i % 2 == 0)
            {
                buffer[2] |= 0x80; // QR
                buffer[4] = 0;
                buffer[5] = (byte)(i % 3 == 0 ? 1 : 0);
                buffer[6] = 0;
                buffer[7] = (byte)random.Next(0, 4);
            }

            try
            {
                DnsMessageReader.Parse(buffer.AsSpan(0, length));
            }
            catch (DnsException)
            {
            }
        }
    }

    [Fact]
    public void Parsing_a_typical_answer_allocates_little()
    {
        var packet = PacketBuilder.Response(1, "example.com", DnsRecordType.A).A("example.com", "192.0.2.1").A("example.com", "192.0.2.2").Build();
        for (int i = 0; i < 100; i++)
        {
            DnsMessageReader.Parse(packet);
        }

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 1000; i++)
        {
            DnsMessageReader.Parse(packet);
        }

        long perParse = (GC.GetAllocatedBytesForCurrentThread() - before) / 1000;
        // Message + question string + array + 2 records + 2 addresses; the owner name string is shared between the records.
        Assert.True(perParse < 1100, $"allocated {perParse} bytes per parse");
    }

    [Fact]
    public void Response_identity_check_is_allocation_free_and_strict()
    {
        var query = DnsMessageWriter.BuildQuery(0x1234, "ExAmPlE.com", DnsRecordType.A, DnsQueryOptions.Default);
        var good = PacketBuilder.ReplyTo(query).A("example.com", "192.0.2.1").Build();
        Assert.True(DnsWire.IsResponseTo(query, good, caseSensitive: true));

        long before = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 1000; i++)
        {
            Assert.True(DnsWire.IsResponseTo(query, good, false));
        }

        Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);

        // lower-cased question: fine without 0x20, rejected with it
        var lowered = PacketBuilder.Response(0x1234, "example.com", DnsRecordType.A).Build();
        Assert.True(DnsWire.IsResponseTo(query, lowered, false));
        Assert.False(DnsWire.IsResponseTo(query, lowered, true));

        Assert.False(DnsWire.IsResponseTo(query, PacketBuilder.Response(0x1235, "ExAmPlE.com", DnsRecordType.A).Build(), false));       // ID
        Assert.False(DnsWire.IsResponseTo(query, PacketBuilder.Response(0x1234, "ExAmPlE.org", DnsRecordType.A).Build(), false));       // name
        Assert.False(DnsWire.IsResponseTo(query, PacketBuilder.Response(0x1234, "ExAmPlE.com", DnsRecordType.MX).Build(), false));      // type
        Assert.False(DnsWire.IsResponseTo(query, PacketBuilder.Response(0x1234, "ExAmPlE.com", DnsRecordType.A).NoQuestion().Build(), false));
        var notResponse = PacketBuilder.Response(0x1234, "ExAmPlE.com", DnsRecordType.A);
        notResponse.Flags = 0x0100;
        Assert.False(DnsWire.IsResponseTo(query, notResponse.Build(), false));
        Assert.False(DnsWire.IsResponseTo(query, good.AsSpan(0, 20), false));
        Assert.False(DnsWire.IsResponseTo(query, ReadOnlySpan<byte>.Empty, false));
        Assert.False(DnsWire.IsResponseTo(ReadOnlySpan<byte>.Empty, good, false));
    }
}
