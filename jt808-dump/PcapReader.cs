namespace Jt808Dump;

/// <summary>
/// Minimal pcap / pcapng reader that pulls TCP payloads out of a capture file.
///
/// This exists so a Wireshark or tcpdump capture can be dropped straight in - no conversion step,
/// no exporting hex by hand. Only what is needed to reach the JT808 bytes is implemented: if a
/// capture uses something exotic it says so rather than returning a plausible-looking empty result.
/// </summary>
public static class PcapReader
{
    public sealed class Result
    {
        public bool IsCapture;
        public int PacketsSeen;
        public int TcpPacketsWithPayload;
        public List<string> Notes = new();

        /// <summary>
        /// Payload grouped by TCP conversation, in the order the streams first appeared.
        ///
        /// Grouping is not cosmetic. Several cameras reporting at once means several concurrent
        /// connections; concatenating them all into one buffer would interleave their bytes and
        /// split frames down the middle, producing checksum failures that look like device faults.
        /// The two directions of one connection are kept apart for the same reason.
        /// </summary>
        public Dictionary<string, List<byte>> Streams = new();

        /// <summary>Every stream joined together - only safe when there is exactly one.</summary>
        public byte[] Payload => Streams.Values.SelectMany(x => x).ToArray();
    }

    public static bool LooksLikeCapture(byte[] raw)
    {
        if (raw.Length < 4) return false;
        uint m = BitConverter.ToUInt32(raw, 0);
        return m is 0xA1B2C3D4 or 0xD4C3B2A1 or 0xA1B23C4D or 0x4D3CB2A1 or 0x0A0D0D0A;
    }

    public static Result Read(byte[] raw)
    {
        var r = new Result();
        if (!LooksLikeCapture(raw)) return r;
        r.IsCapture = true;

        uint magic = BitConverter.ToUInt32(raw, 0);
        if (magic == 0x0A0D0D0A) ReadPcapNg(raw, r);
        else ReadPcap(raw, r);
        return r;
    }

    // ------------------------------------------------------------------ classic pcap

    static void ReadPcap(byte[] raw, Result r)
    {
        uint magic = BitConverter.ToUInt32(raw, 0);
        bool swap = magic is 0xD4C3B2A1 or 0x4D3CB2A1;
        bool nano = magic is 0xA1B23C4D or 0x4D3CB2A1;
        if (raw.Length < 24) { r.Notes.Add("pcap file is truncated - no global header"); return; }

        uint linkType = U32(raw, 20, swap);
        r.Notes.Add($"classic pcap, link type {linkType} ({LinkName(linkType)}){(nano ? ", nanosecond timestamps" : "")}");

        int p = 24;
        while (p + 16 <= raw.Length)
        {
            uint inclLen = U32(raw, p + 8, swap);
            p += 16;
            if (inclLen > int.MaxValue || p + (int)inclLen > raw.Length)
            {
                r.Notes.Add("capture ends mid-packet - reading what is complete");
                break;
            }
            r.PacketsSeen++;
            ExtractTcp(raw.AsSpan(p, (int)inclLen), linkType, r);
            p += (int)inclLen;
        }
    }

    // ------------------------------------------------------------------ pcapng

    static void ReadPcapNg(byte[] raw, Result r)
    {
        var linkTypes = new List<uint>();
        bool swap = false;
        int p = 0;

        while (p + 12 <= raw.Length)
        {
            uint blockType = BitConverter.ToUInt32(raw, p);
            if (blockType == 0x0A0D0D0A)
            {
                // Section Header Block: byte-order magic tells us the endianness from here on
                if (p + 12 > raw.Length) break;
                uint bom = BitConverter.ToUInt32(raw, p + 8);
                swap = bom != 0x1A2B3C4D;
                linkTypes.Clear();
            }
            uint blockLen = U32(raw, p + 4, swap);
            if (blockLen < 12 || p + blockLen > raw.Length)
            {
                r.Notes.Add("pcapng block length is out of range - stopping here");
                break;
            }

            if (blockType == 0x00000001) // Interface Description Block
            {
                linkTypes.Add(U16(raw, p + 8, swap));
            }
            else if (blockType == 0x00000006) // Enhanced Packet Block
            {
                uint ifaceId = U32(raw, p + 8, swap);
                uint capLen = U32(raw, p + 20, swap);
                int dataStart = p + 28;
                if (dataStart + capLen <= raw.Length)
                {
                    r.PacketsSeen++;
                    uint lt = ifaceId < linkTypes.Count ? linkTypes[(int)ifaceId] : 1;
                    ExtractTcp(raw.AsSpan(dataStart, (int)capLen), lt, r);
                }
            }
            else if (blockType == 0x00000003) // Simple Packet Block
            {
                int dataStart = p + 12;
                int capLen = (int)blockLen - 16;
                if (capLen > 0 && dataStart + capLen <= raw.Length)
                {
                    r.PacketsSeen++;
                    uint lt = linkTypes.Count > 0 ? linkTypes[0] : 1;
                    ExtractTcp(raw.AsSpan(dataStart, capLen), lt, r);
                }
            }

            p += (int)blockLen;
        }

        r.Notes.Add($"pcapng, {linkTypes.Count} interface(s)" +
                    (linkTypes.Count > 0 ? $", link type {linkTypes[0]} ({LinkName(linkTypes[0])})" : ""));
    }

    // ------------------------------------------------------------------ link / ip / tcp

    static void ExtractTcp(ReadOnlySpan<byte> frame, uint linkType, Result r)
    {
        int off;
        ushort etherType;

        switch (linkType)
        {
            case 1: // Ethernet
                if (frame.Length < 14) return;
                etherType = (ushort)((frame[12] << 8) | frame[13]);
                off = 14;
                while (etherType == 0x8100 || etherType == 0x88A8) // VLAN tags
                {
                    if (frame.Length < off + 4) return;
                    etherType = (ushort)((frame[off + 2] << 8) | frame[off + 3]);
                    off += 4;
                }
                break;
            case 113: // Linux cooked capture (tcpdump -i any)
                if (frame.Length < 16) return;
                etherType = (ushort)((frame[14] << 8) | frame[15]);
                off = 16;
                break;
            case 276: // Linux cooked capture v2
                if (frame.Length < 20) return;
                etherType = (ushort)((frame[0] << 8) | frame[1]);
                off = 20;
                break;
            case 0: // BSD loopback: 4-byte host-order address family
                if (frame.Length < 4) return;
                etherType = frame[0] == 2 ? (ushort)0x0800 : (ushort)0;
                off = 4;
                break;
            case 101:
            case 12:
            case 14: // raw IP
                etherType = (frame.Length > 0 && (frame[0] >> 4) == 4) ? (ushort)0x0800 : (ushort)0x86DD;
                off = 0;
                break;
            default:
                if (r.Notes.All(n => !n.StartsWith("unsupported link type")))
                    r.Notes.Add($"unsupported link type {linkType} ({LinkName(linkType)}) - cannot reach the TCP payload");
                return;
        }

        if (etherType != 0x0800)
        {
            if (etherType == 0x86DD && r.Notes.All(n => !n.Contains("IPv6")))
                r.Notes.Add("IPv6 packets present - not decoded (JT808 devices here are IPv4)");
            return;
        }

        if (frame.Length < off + 20) return;
        var ip = frame[off..];
        int ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20 || ip.Length < ihl) return;
        if (ip[9] != 6) return; // not TCP

        int totalLen = (ip[2] << 8) | ip[3];
        if (totalLen < ihl || totalLen > ip.Length) totalLen = ip.Length;

        string src = $"{ip[12]}.{ip[13]}.{ip[14]}.{ip[15]}";
        string dst = $"{ip[16]}.{ip[17]}.{ip[18]}.{ip[19]}";

        var tcp = ip[ihl..totalLen];
        if (tcp.Length < 20) return;
        int sport = (tcp[0] << 8) | tcp[1];
        int dport = (tcp[2] << 8) | tcp[3];
        int dataOff = (tcp[12] >> 4) * 4;
        if (dataOff < 20 || tcp.Length < dataOff) return;

        var data = tcp[dataOff..];
        if (data.Length == 0) return;

        r.TcpPacketsWithPayload++;
        string convo = $"{src}:{sport} -> {dst}:{dport}";
        if (!r.Streams.TryGetValue(convo, out var buf))
        {
            buf = new List<byte>();
            r.Streams[convo] = buf;
        }
        buf.AddRange(data.ToArray());
    }

    static uint U32(byte[] b, int off, bool swap)
    {
        uint v = BitConverter.ToUInt32(b, off);
        return swap ? ((v & 0x000000FF) << 24 | (v & 0x0000FF00) << 8 | (v & 0x00FF0000) >> 8 | (v & 0xFF000000) >> 24) : v;
    }

    static ushort U16(byte[] b, int off, bool swap)
    {
        ushort v = BitConverter.ToUInt16(b, off);
        return swap ? (ushort)((v << 8) | (v >> 8)) : v;
    }

    static string LinkName(uint lt) => lt switch
    {
        0 => "null/loopback",
        1 => "Ethernet",
        12 or 14 or 101 => "raw IP",
        113 => "Linux cooked",
        276 => "Linux cooked v2",
        _ => "unknown",
    };
}
