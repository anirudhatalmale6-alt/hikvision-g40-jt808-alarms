using System.Text;
using static Jt808Dump.Framing;

namespace Jt808Dump;

/// <summary>
/// Decoders for the ADAS / DSM "active safety" additional-info items (0x64 / 0x65 / 0x67)
/// as laid out in the JSATL12 supplement that Chinese ADAS dashcams follow.
///
/// IMPORTANT: this layout is the common one, not a Hikvision-confirmed one. Every decoder
/// checks the declared length first and refuses to pretend when it does not match, because a
/// decoder that quietly reads the wrong offsets produces plausible garbage - the worst outcome.
/// </summary>
public static class ActiveSafety
{
    public const int Len0x64 = 47;
    public const int Len0x65 = 47;
    public const int Len0x67 = 41;

    static readonly Dictionary<byte, string> AdasTypes = new()
    {
        [0x01] = "forward collision warning",
        [0x02] = "lane departure warning",
        [0x03] = "headway monitoring / following too close",
        [0x04] = "pedestrian collision warning",
        [0x05] = "frequent lane change",
        [0x06] = "road sign overrun",
        [0x07] = "obstacle detected",
        [0x08] = "driving assistance function failure",
        [0x10] = "road sign recognition event",
        [0x11] = "active capture event",
    };

    static readonly Dictionary<byte, string> DsmTypes = new()
    {
        [0x01] = "fatigue driving",
        [0x02] = "phone use while driving",
        [0x03] = "smoking",
        [0x04] = "distracted / long time not looking ahead",
        [0x05] = "driver abnormal / no driver detected",
        [0x06] = "both hands off the steering wheel",
        [0x07] = "driver monitoring system failure",
        [0x10] = "automatic capture event",
        [0x11] = "driver change event",
    };

    static readonly Dictionary<byte, string> BsdTypes = new()
    {
        [0x01] = "rear approach",
        [0x02] = "left rear approach",
        [0x03] = "right rear approach",
    };

    static string FlagState(byte b) => b switch
    {
        0x00 => "not applicable (instantaneous event)",
        0x01 => "ALARM START",
        0x02 => "ALARM END",
        _ => $"unexpected value 0x{b:X2}",
    };

    /// <summary>
    /// Renders a decode of an active-safety item. Returns null when the item length rules the
    /// layout out, so the caller falls back to a raw hex dump instead of printing invented fields.
    /// </summary>
    public static string TryDecode(byte id, byte[] d, out string mismatchReason)
    {
        mismatchReason = null;
        int expected = id switch { 0x64 => Len0x64, 0x65 => Len0x65, 0x67 => Len0x67, _ => -1 };
        if (expected < 0) return null;
        if (d.Length != expected)
        {
            mismatchReason =
                $"item 0x{id:X2} is {d.Length} bytes; the JSATL12 layout is {expected}. " +
                "Not decoding it against that layout - the offsets would be wrong and the output would look " +
                "credible while being nonsense. Raw bytes below; send them over and I will map the real layout.";
            return null;
        }

        var sb = new StringBuilder();
        int p = 0;
        uint alarmId = Be32(d, ref p);
        byte flagState = d[p++];
        byte alarmType = d[p++];
        byte level = d[p++];

        string typeName = id switch
        {
            0x64 => AdasTypes.TryGetValue(alarmType, out var a) ? a : null,
            0x65 => DsmTypes.TryGetValue(alarmType, out var s) ? s : null,
            0x67 => BsdTypes.TryGetValue(alarmType, out var b) ? b : null,
            _ => null,
        };
        // 0x67 has no separate level byte in the common layout; rewind if that is the item.
        if (id == 0x67) p--;

        sb.AppendLine($"      alarm id          : {alarmId} (0x{alarmId:X8})");
        sb.AppendLine($"      flag state        : 0x{flagState:X2}  {FlagState(flagState)}");
        sb.AppendLine($"      alarm/event type  : 0x{alarmType:X2}  {typeName ?? "NOT IN THE PUBLISHED TABLE - vendor specific, needs mapping"}");
        if (id != 0x67)
            sb.AppendLine($"      alarm level       : {level}  ({(level == 1 ? "level 1" : level == 2 ? "level 2" : "non-standard")})");

        if (id == 0x64)
        {
            byte frontSpeed = d[p++];
            byte frontDistance = d[p++];
            byte deviation = d[p++];
            byte signType = d[p++];
            byte signData = d[p++];
            sb.AppendLine($"      front veh. speed  : {frontSpeed} km/h");
            sb.AppendLine($"      front veh. dist.  : {frontDistance / 10.0:0.0} s headway (0.1 s units)");
            sb.AppendLine($"      deviation type    : 0x{deviation:X2}  {(deviation == 1 ? "left" : deviation == 2 ? "right" : "n/a")}");
            sb.AppendLine($"      road sign type    : 0x{signType:X2}   data: {signData}");
        }
        else if (id == 0x65)
        {
            byte fatigue = d[p++];
            var reserved = d.AsSpan(p, 4).ToArray(); p += 4;
            sb.AppendLine($"      fatigue degree    : {fatigue}  (1-10 scale, 0 = not reported)");
            sb.AppendLine($"      reserved 4 bytes  : {Hex.ToHex(reserved)}");
        }

        byte speed = d[p++];
        ushort altitude = Be16(d, ref p);
        double lat = Be32(d, ref p) / 1000000.0;
        double lng = Be32(d, ref p) / 1000000.0;
        string time = BcdTime(d, p) ?? $"unparseable BCD {Bcd(d, p, 6)}"; p += 6;
        ushort vehStatus = Be16(d, ref p);
        var alarmIdent = d.AsSpan(p, Math.Min(16, d.Length - p)).ToArray(); p += alarmIdent.Length;

        sb.AppendLine($"      speed             : {speed} km/h");
        sb.AppendLine($"      altitude          : {altitude} m");
        sb.AppendLine($"      position          : {lat:0.000000}, {lng:0.000000}");
        sb.AppendLine($"      alarm time        : {time}");
        sb.AppendLine($"      vehicle status    : 0x{vehStatus:X4}");
        sb.AppendLine($"      alarm identifier  : {Hex.ToHex(alarmIdent)}");
        if (alarmIdent.Length == 16)
        {
            string termId = Encoding.ASCII.GetString(alarmIdent, 0, 7).TrimEnd('\0', ' ');
            string idTime = BcdTime(alarmIdent, 7) ?? "unparseable";
            sb.AppendLine($"        terminal id     : \"{termId}\"");
            sb.AppendLine($"        time            : {idTime}");
            sb.AppendLine($"        sequence no     : {alarmIdent[13]}");
            sb.AppendLine($"        attachment count: {alarmIdent[14]}   <-- files the device expects to upload");
            sb.AppendLine($"        reserved        : 0x{alarmIdent[15]:X2}");
            if (alarmIdent[14] > 0)
                sb.AppendLine("        NOTE: a non-zero attachment count means the device is waiting for a 0x9208");
            sb.AppendLine("              attachment-upload instruction. Without one it may stop re-sending alarms.");
        }
        return sb.ToString().TrimEnd('\r', '\n');
    }
}
