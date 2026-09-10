using System.Text;

namespace Jt808Dump;

/// <summary>
/// Additional-information items from the JT/T 1078 video extension - the audio/video supplement
/// to JT808 that in-vehicle DVRs and dashcams implement.
///
/// Why this file exists: a camera that reports 0x14/0x15/0x16/0x17 is built on the 1078 video
/// family, which routes driver-behaviour alarms differently from the active-safety supplement
/// that defines 0x64/0x65. Under 1078 a fatigue or phone-use event shows up as a bit in the
/// 0x14 bitmask, with the specifics in a companion 0x18 item - not as a 0x65 block.
///
/// CONFIDENCE: the ID-and-length signature (0x14=4, 0x15=4, 0x16=4, 0x17=2, in that order) is
/// a strong match for this standard, and that is what the mapping rests on. It is not confirmed
/// against a Hikvision document. Anything below that cannot be read straight out of the bytes is
/// reported as unmapped rather than guessed.
/// </summary>
public static class Jt1078
{
    /// <summary>Bit meanings of item 0x14, the video-related alarm bitmask.</summary>
    static readonly (int Bit, string Meaning)[] VideoAlarmBits =
    {
        (0, "video signal loss"),
        (1, "video signal occluded / blocked"),
        (2, "storage unit fault"),
        (3, "other video equipment fault"),
        (4, "passenger overcrowding"),
        (5, "ABNORMAL DRIVING BEHAVIOUR  <-- fatigue / phone / smoking land here"),
        (6, "special alarm recording reached storage threshold"),
    };

    public static bool IsVideoExtensionItem(byte id) => id is 0x14 or 0x15 or 0x16 or 0x17 or 0x18;

    public static string Name(byte id) => id switch
    {
        0x14 => "video-related alarm bitmask (JT/T 1078 video extension)",
        0x15 => "video signal loss, per channel (JT/T 1078)",
        0x16 => "video signal occlusion, per channel (JT/T 1078)",
        0x17 => "storage fault status (JT/T 1078)",
        0x18 => "abnormal driving behaviour detail (JT/T 1078)",
        _ => null,
    };

    /// <summary>
    /// Renders an item. Returns null when the length does not match the standard, so the caller
    /// falls back to a hex dump instead of reading fields out of the wrong offsets.
    /// </summary>
    public static string TryDecode(byte id, byte[] d, out string mismatch)
    {
        mismatch = null;
        int expected = id switch { 0x14 => 4, 0x15 => 4, 0x16 => 4, 0x17 => 2, _ => -1 };
        if (id == 0x18)
        {
            // Seen as either a 2-byte type bitmask or that plus a fatigue-degree byte.
            if (d.Length is not (2 or 3))
            {
                mismatch = $"item 0x18 is {d.Length} bytes; expected 2 or 3. Not decoding it.";
                return null;
            }
            return DecodeBehaviourDetail(d);
        }
        if (expected < 0) return null;
        if (d.Length != expected)
        {
            mismatch = $"item 0x{id:X2} is {d.Length} bytes; the JT/T 1078 layout is {expected}. " +
                       "Not decoding it against that layout - the offsets would be wrong.";
            return null;
        }

        var sb = new StringBuilder();
        if (id == 0x14)
        {
            uint v = Be32(d);
            sb.AppendLine($"      value             : 0x{v:X8}");
            if (v == 0)
            {
                sb.Append("      no video alarm bits set - nothing active on this packet");
                return sb.ToString();
            }
            foreach (var (bit, meaning) in VideoAlarmBits)
                if ((v & (1u << bit)) != 0)
                    sb.AppendLine($"      bit {bit,-2}            : {meaning}");
            for (int b = 7; b < 32; b++)
                if ((v & (1u << b)) != 0)
                    sb.AppendLine($"      bit {b,-2}            : set, but reserved in the published table - UNMAPPED");
            return sb.ToString().TrimEnd('\r', '\n');
        }

        if (id is 0x15 or 0x16)
        {
            uint v = Be32(d);
            string what = id == 0x15 ? "signal lost" : "occluded";
            if (v == 0) return $"      value             : 0x{v:X8}   no channel reports {what}";
            var chans = new List<string>();
            for (int b = 0; b < 32; b++) if ((v & (1u << b)) != 0) chans.Add($"ch{b + 1}");
            return $"      value             : 0x{v:X8}   {what}: {string.Join(", ", chans)}";
        }

        // 0x17
        ushort s = (ushort)((d[0] << 8) | d[1]);
        if (s == 0) return $"      value             : 0x{s:X4}   no storage fault";
        var units = new List<string>();
        for (int b = 0; b < 16; b++) if ((s & (1 << b)) != 0) units.Add($"unit{b + 1}");
        return $"      value             : 0x{s:X4}   storage fault: {string.Join(", ", units)}";
    }

    static string DecodeBehaviourDetail(byte[] d)
    {
        ushort type = (ushort)((d[0] << 8) | d[1]);
        var sb = new StringBuilder();
        sb.AppendLine($"      behaviour bitmask : 0x{type:X4}");
        var known = new (int Bit, string Meaning)[]
        {
            (0, "fatigue driving"),
            (1, "phone call while driving"),
            (2, "smoking"),
        };
        bool any = false;
        foreach (var (bit, meaning) in known)
            if ((type & (1 << bit)) != 0) { sb.AppendLine($"      bit {bit}             : {meaning}"); any = true; }
        for (int b = 3; b < 16; b++)
            if ((type & (1 << b)) != 0)
            {
                sb.AppendLine($"      bit {b,-2}            : set, not in the published table - UNMAPPED, send me the bytes");
                any = true;
            }
        if (!any) sb.AppendLine("      no behaviour bits set");
        if (d.Length == 3) sb.AppendLine($"      fatigue degree    : {d[2]}  (1-10 scale)");
        return sb.ToString().TrimEnd('\r', '\n');
    }

    static uint Be32(byte[] d) => (uint)((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]);
}
