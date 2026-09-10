using System.Text;

namespace Jt808Dump;

/// <summary>Hex helpers that tolerate whatever a log file throws at them.</summary>
public static class Hex
{
    /// <summary>
    /// Pulls packet bytes out of arbitrary log text.
    ///
    /// Line-oriented and deliberately picky, because the obvious approach - "keep every hex
    /// digit in the file" - is wrong in a way that hides itself. A log line like
    /// "2026-09-10T13:25:23.591Z" is almost entirely hex digits; harvesting them yields
    /// 2026091013252359 and splices it onto the next real packet, at which point the tool
    /// reports a confident decode of a frame that never existed.
    ///
    /// So: strip comments, then take only runs of hex-and-whitespace long enough to be a
    /// packet (a JT808 frame cannot be shorter than about 13 bytes). Timestamps, terminal IDs
    /// in square brackets and log prefixes all fall below that bar and are ignored.
    /// </summary>
    public static byte[] FromLogText(string text)
    {
        const int MinHexDigits = 24; // 12 bytes - below any real JT808 frame

        var collected = new List<byte>();
        bool foundAny = false;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine;
            int hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];

            // walk the line, accumulating maximal runs of [hex digits + whitespace]
            int i = 0;
            while (i < line.Length)
            {
                if (!Uri.IsHexDigit(line[i])) { i++; continue; }
                int start = i;
                int digits = 0;
                while (i < line.Length && (Uri.IsHexDigit(line[i]) || line[i] == ' ' || line[i] == '\t' || line[i] == '\r'))
                {
                    if (Uri.IsHexDigit(line[i])) digits++;
                    i++;
                }
                if (digits >= MinHexDigits)
                {
                    var run = line[start..i];
                    var bytes = FromLooseText(run);
                    if (bytes.Length > 0) { collected.AddRange(bytes); foundAny = true; }
                }
            }
        }

        // A file that is nothing but short hex lines still deserves to be read.
        if (!foundAny) return FromLooseText(text);
        return collected.ToArray();
    }

    /// <summary>
    /// Pulls every hex digit pair out of a blob of text. Tolerates "7E 02 00", "7e0200",
    /// "0x7E,0x02", Wireshark "0000  7e 02 00 ...  ~.." lines and C# byte-array dumps.
    /// Use <see cref="FromLogText"/> for anything that might contain prose or timestamps.
    /// </summary>
    public static byte[] FromLooseText(string text)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            // skip "0x" / "0X" prefixes so the x doesn't break the pairing
            if ((c == 'x' || c == 'X') && sb.Length > 0 && sb[^1] == '0')
            {
                sb.Length -= 1;
                continue;
            }
            if (Uri.IsHexDigit(c)) sb.Append(c);
        }
        var s = sb.ToString();
        if (s.Length % 2 != 0) s = s[..^1]; // trailing half byte: drop it rather than throw
        var result = new byte[s.Length / 2];
        for (int i = 0; i < result.Length; i++)
            result[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return result;
    }

    public static string ToHex(ReadOnlySpan<byte> b, string sep = " ")
    {
        var sb = new StringBuilder(b.Length * 3);
        for (int i = 0; i < b.Length; i++)
        {
            if (i > 0) sb.Append(sep);
            sb.Append(b[i].ToString("X2"));
        }
        return sb.ToString();
    }

    /// <summary>Classic offset / hex / ascii dump, for payloads we cannot name.</summary>
    public static string Dump(ReadOnlySpan<byte> b, string indent = "      ")
    {
        var sb = new StringBuilder();
        for (int off = 0; off < b.Length; off += 16)
        {
            int len = Math.Min(16, b.Length - off);
            var line = b.Slice(off, len);
            sb.Append(indent).Append(off.ToString("X4")).Append("  ");
            for (int i = 0; i < 16; i++)
            {
                sb.Append(i < len ? line[i].ToString("X2") : "  ");
                sb.Append(i == 7 ? "  " : " ");
            }
            sb.Append(' ');
            for (int i = 0; i < len; i++)
            {
                char c = (char)line[i];
                sb.Append(c >= 0x20 && c < 0x7f ? c : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString().TrimEnd('\r', '\n');
    }
}

/// <summary>One JT808 frame, already unescaped, with its header split out.</summary>
public sealed class Jt808Frame
{
    public byte[] Escaped;          // exactly as it came off the wire, 7E..7E included
    public byte[] Unescaped;        // 7D01/7D02 resolved, 7E delimiters stripped
    public ushort MessageId;
    public ushort BodyProperty;
    public int BodyLength;
    public int Encryption;
    public bool IsSubpackage;
    public bool IsVersion2019;      // body-property bit 14
    public byte ProtocolVersion;    // 2019 only
    public string TerminalPhone;    // BCD, leading zeros trimmed
    public ushort SerialNumber;
    public ushort PackageTotal;
    public ushort PackageIndex;
    public byte[] Body = Array.Empty<byte>();
    public byte ChecksumInPacket;
    public byte ChecksumComputed;
    public bool ChecksumOk => ChecksumInPacket == ChecksumComputed;
    public List<string> Warnings = new();

    public int HeaderLength => (IsVersion2019 ? 2 + 2 + 1 + 10 + 2 : 2 + 2 + 6 + 2) + (IsSubpackage ? 4 : 0);
}

public static class Framing
{
    /// <summary>
    /// Splits a stream of bytes into 7E-delimited frames. Handles back-to-back frames that
    /// share a delimiter, leading rubbish, and half a frame at the end of a log.
    /// </summary>
    public static List<byte[]> SplitFrames(byte[] raw, out List<string> notes)
    {
        notes = new List<string>();
        var frames = new List<byte[]>();
        int i = 0;

        // skip anything before the first delimiter
        while (i < raw.Length && raw[i] != 0x7E) i++;
        if (i > 0) notes.Add($"skipped {i} byte(s) of non-JT808 data before the first 0x7E");

        while (i < raw.Length)
        {
            if (raw[i] != 0x7E) { i++; continue; }
            int start = i;
            int end = -1;
            for (int j = i + 1; j < raw.Length; j++)
            {
                if (raw[j] == 0x7E) { end = j; break; }
            }
            if (end < 0)
            {
                notes.Add($"trailing {raw.Length - start} byte(s) with no closing 0x7E - truncated capture?");
                break;
            }
            if (end == start + 1)
            {
                // "7E 7E" - two frames sharing a delimiter, or padding. Move on.
                i = end;
                continue;
            }
            var frame = new byte[end - start + 1];
            Array.Copy(raw, start, frame, 0, frame.Length);
            frames.Add(frame);
            i = end + 1;
            // a frame may immediately open the next one with the same byte
            if (i < raw.Length && raw[i] != 0x7E) i = end;
        }
        return frames;
    }

    public static byte[] Unescape(byte[] escapedWithDelimiters)
    {
        var src = escapedWithDelimiters;
        int from = (src.Length > 0 && src[0] == 0x7E) ? 1 : 0;
        int to = (src.Length > 1 && src[^1] == 0x7E) ? src.Length - 1 : src.Length;
        var outBuf = new List<byte>(to - from);
        for (int i = from; i < to; i++)
        {
            if (src[i] == 0x7D && i + 1 < to)
            {
                if (src[i + 1] == 0x01) { outBuf.Add(0x7D); i++; continue; }
                if (src[i + 1] == 0x02) { outBuf.Add(0x7E); i++; continue; }
            }
            outBuf.Add(src[i]);
        }
        return outBuf.ToArray();
    }

    public static byte[] Escape(byte[] unescaped)
    {
        var outBuf = new List<byte> { 0x7E };
        foreach (var b in unescaped)
        {
            if (b == 0x7E) { outBuf.Add(0x7D); outBuf.Add(0x02); }
            else if (b == 0x7D) { outBuf.Add(0x7D); outBuf.Add(0x01); }
            else outBuf.Add(b);
        }
        outBuf.Add(0x7E);
        return outBuf.ToArray();
    }

    public static byte Checksum(ReadOnlySpan<byte> headerAndBody)
    {
        byte x = 0;
        foreach (var b in headerAndBody) x ^= b;
        return x;
    }

    public static Jt808Frame Parse(byte[] escapedFrame)
    {
        var f = new Jt808Frame { Escaped = escapedFrame };
        var u = Unescape(escapedFrame);
        f.Unescaped = u;

        if (u.Length < 12)
        {
            f.Warnings.Add($"frame is only {u.Length} bytes after unescaping - too short to be a JT808 message");
            return f;
        }

        // last byte of the unescaped frame is the XOR checksum
        f.ChecksumInPacket = u[^1];
        f.ChecksumComputed = Checksum(u.AsSpan(0, u.Length - 1));

        int p = 0;
        f.MessageId = Be16(u, ref p);
        f.BodyProperty = Be16(u, ref p);
        f.BodyLength = f.BodyProperty & 0x03FF;
        f.Encryption = (f.BodyProperty >> 10) & 0x07;
        f.IsSubpackage = ((f.BodyProperty >> 13) & 0x01) == 1;
        f.IsVersion2019 = ((f.BodyProperty >> 14) & 0x01) == 1;

        int phoneBytes = 6;
        if (f.IsVersion2019)
        {
            f.ProtocolVersion = u[p++];
            phoneBytes = 10;
        }
        if (p + phoneBytes + 2 > u.Length)
        {
            f.Warnings.Add("frame ends inside the header - cannot read terminal phone / serial number");
            return f;
        }
        f.TerminalPhone = Bcd(u, p, phoneBytes).TrimStart('0');
        if (f.TerminalPhone.Length == 0) f.TerminalPhone = "0";
        p += phoneBytes;
        f.SerialNumber = Be16(u, ref p);

        if (f.IsSubpackage)
        {
            if (p + 4 > u.Length) { f.Warnings.Add("subpackage flag set but the 4 package bytes are missing"); return f; }
            f.PackageTotal = Be16(u, ref p);
            f.PackageIndex = Be16(u, ref p);
        }

        int available = u.Length - 1 - p; // minus checksum
        if (available < 0) available = 0;
        int take = f.BodyLength;
        if (take > available)
        {
            f.Warnings.Add($"header declares a {f.BodyLength}-byte body but only {available} byte(s) are present " +
                           "(wrong protocol version assumed, or the frame is truncated)");
            take = available;
        }
        else if (take < available)
        {
            f.Warnings.Add($"header declares a {f.BodyLength}-byte body but {available} byte(s) are present - " +
                           $"{available - take} unexplained byte(s) before the checksum");
        }
        f.Body = new byte[take];
        Array.Copy(u, p, f.Body, 0, take);
        return f;
    }

    public static ushort Be16(byte[] b, ref int p) { ushort v = (ushort)((b[p] << 8) | b[p + 1]); p += 2; return v; }
    public static uint Be32(byte[] b, ref int p) { uint v = (uint)((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]); p += 4; return v; }

    public static string Bcd(byte[] b, int offset, int len)
    {
        var sb = new StringBuilder(len * 2);
        for (int i = 0; i < len && offset + i < b.Length; i++) sb.Append(b[offset + i].ToString("X2"));
        return sb.ToString();
    }

    /// <summary>BCD YYMMDDhhmmss -> readable. Returns null when the digits are not a plausible date.</summary>
    public static string BcdTime(byte[] b, int offset)
    {
        if (offset + 6 > b.Length) return null;
        var s = Bcd(b, offset, 6);
        foreach (var c in s) if (!char.IsDigit(c)) return null;
        int yy = int.Parse(s[..2]), mm = int.Parse(s.Substring(2, 2)), dd = int.Parse(s.Substring(4, 2));
        int hh = int.Parse(s.Substring(6, 2)), mi = int.Parse(s.Substring(8, 2)), ss = int.Parse(s.Substring(10, 2));
        if (mm is < 1 or > 12 || dd is < 1 or > 31 || hh > 23 || mi > 59 || ss > 60) return null;
        return $"20{yy:00}-{mm:00}-{dd:00} {hh:00}:{mi:00}:{ss:00}";
    }
}
