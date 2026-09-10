using System.Text;
using static Jt808Dump.Framing;

namespace Jt808Dump;

/// <summary>One entry of the 0x0200 "additional information" list.</summary>
public sealed class AttachItem
{
    public byte Id;
    public int DeclaredLength;
    public byte[] Data = Array.Empty<byte>();
    public bool Truncated;
}

public static class Location
{
    public static readonly Dictionary<ushort, string> MessageNames = new()
    {
        [0x0001] = "terminal general response",
        [0x0002] = "terminal heartbeat",
        [0x0003] = "terminal deregister",
        [0x0100] = "terminal register",
        [0x0102] = "terminal authentication",
        [0x0104] = "query parameters response",
        [0x0107] = "query terminal properties response",
        [0x0200] = "location report",
        [0x0201] = "location query response",
        [0x0301] = "event report",
        [0x0302] = "question answer",
        [0x0500] = "vehicle control response",
        [0x0700] = "driving record data upload",
        [0x0701] = "electronic waybill report",
        [0x0702] = "driver identity report",
        [0x0704] = "batch location upload",
        [0x0705] = "CAN bus data upload",
        [0x0800] = "multimedia event info upload",
        [0x0801] = "multimedia data upload",
        [0x0805] = "camera shoot command response",
        [0x0900] = "data transparent transmission (vendor payload)",
        [0x0901] = "data compression report",
        [0x1210] = "alarm attachment info (active safety)",
        [0x1211] = "file info upload (active safety)",
        [0x1212] = "file upload complete (active safety)",
        [0x8001] = "platform general response",
        [0x8100] = "register response",
        [0x8103] = "set terminal parameters",
        [0x8104] = "query terminal parameters",
        [0x8106] = "query specific parameters",
        [0x8107] = "query terminal properties",
        [0x8201] = "location query",
        [0x8202] = "temporary location tracking control",
        [0x8300] = "text message",
        [0x8801] = "camera shoot command",
        [0x9101] = "realtime video request",
        [0x9208] = "alarm attachment upload instruction (active safety)",
    };

    static readonly Dictionary<byte, string> StandardAttachNames = new()
    {
        [0x01] = "mileage (0.1 km)",
        [0x02] = "fuel (0.1 L)",
        [0x03] = "speed from recorder (0.1 km/h)",
        [0x04] = "alarm event ID",
        [0x05] = "tyre pressure",
        [0x06] = "carriage temperature",
        [0x11] = "overspeed alarm detail",
        [0x12] = "area / route alarm detail",
        [0x13] = "route driving time alarm detail",
        [0x25] = "extended vehicle signal status",
        [0x2A] = "IO status",
        [0x2B] = "analog inputs",
        [0x30] = "wireless signal strength",
        [0x31] = "GNSS satellites in view",
    };

    static readonly string[] AlarmFlagBits =
    {
        /*0*/ "emergency / SOS", "overspeed", "fatigue driving", "dangerous driving warning",
        /*4*/ "GNSS module fault", "GNSS antenna disconnected", "GNSS antenna short circuit", "terminal main power undervoltage",
        /*8*/ "terminal main power cut", "LCD/display fault", "TTS module fault", "camera fault",
        /*12*/ "IC card module fault", "overspeed pre-warning", "fatigue pre-warning", "reserved(15)",
        /*16*/ "reserved(16)", "reserved(17)", "cumulative daily driving overtime", "parked overtime",
        /*20*/ "entering/leaving area", "entering/leaving route", "route driving time too short/long", "route deviation",
        /*24*/ "VSS fault", "abnormal fuel level", "vehicle stolen", "illegal ignition",
        /*28*/ "illegal displacement", "collision warning", "rollover warning", "illegal door open",
    };

    public sealed class Basic
    {
        public uint AlarmFlag, Status;
        public double Latitude, Longitude;
        public int Altitude, Speed, Direction;
        public string Time;
        public List<AttachItem> Attachments = new();
        public List<string> Warnings = new();
    }

    public static Basic ParseLocationBody(byte[] body)
    {
        var r = new Basic();
        if (body.Length < 28)
        {
            r.Warnings.Add($"0x0200 body is {body.Length} bytes; the fixed part alone needs 28");
            return r;
        }
        int p = 0;
        r.AlarmFlag = Be32(body, ref p);
        r.Status = Be32(body, ref p);
        r.Latitude = Be32(body, ref p) / 1000000.0;
        r.Longitude = Be32(body, ref p) / 1000000.0;
        r.Altitude = Be16(body, ref p);
        r.Speed = Be16(body, ref p);
        r.Direction = Be16(body, ref p);
        r.Time = BcdTime(body, p) ?? ("unparseable BCD " + Bcd(body, p, 6));
        p += 6;

        // additional information: id(1) len(1) data[len], repeated to the end of the body
        while (p < body.Length)
        {
            var item = new AttachItem { Id = body[p] };
            if (p + 1 >= body.Length)
            {
                r.Warnings.Add($"additional-info item 0x{item.Id:X2} has no length byte - body ends mid-item");
                item.Truncated = true;
                r.Attachments.Add(item);
                break;
            }
            item.DeclaredLength = body[p + 1];
            int dataStart = p + 2;
            int avail = body.Length - dataStart;
            int take = Math.Min(item.DeclaredLength, avail);
            if (take < item.DeclaredLength)
            {
                item.Truncated = true;
                r.Warnings.Add($"additional-info item 0x{item.Id:X2} declares {item.DeclaredLength} bytes " +
                               $"but only {avail} remain - the item list does not line up");
            }
            item.Data = new byte[take];
            Array.Copy(body, dataStart, item.Data, 0, take);
            r.Attachments.Add(item);
            p = dataStart + item.DeclaredLength;
            if (item.Truncated) break;
        }
        return r;
    }

    /// <summary>
    /// The 0x0200 status word. Worth reading in full: bit 0 is the ignition, and a camera with
    /// ACC off is a parked vehicle - ADAS and DSM do not run, so no alarm can be raised no
    /// matter how the server is configured.
    /// </summary>
    public static string DescribeStatus(uint s)
    {
        var parts = new List<string>
        {
            $"ACC {((s & 1) != 0 ? "ON (ignition on)" : "OFF (ignition off)")}",
            (s & (1u << 1)) != 0 ? "positioned" : "NOT POSITIONED (no GNSS fix)",
            (s & (1u << 2)) != 0 ? "south latitude" : "north latitude",
            (s & (1u << 3)) != 0 ? "west longitude" : "east longitude",
            (s & (1u << 4)) != 0 ? "out of service" : "in service",
        };
        if ((s & (1u << 5)) != 0) parts.Add("lat/lng ENCRYPTED");
        if ((s & (1u << 8)) != 0) parts.Add("fuel circuit disconnected");
        if ((s & (1u << 9)) != 0) parts.Add("electrical circuit disconnected");
        if ((s & (1u << 10)) != 0) parts.Add("doors locked");

        var sats = new List<string>();
        if ((s & (1u << 18)) != 0) sats.Add("GPS");
        if ((s & (1u << 19)) != 0) sats.Add("BeiDou");
        if ((s & (1u << 20)) != 0) sats.Add("GLONASS");
        if ((s & (1u << 21)) != 0) sats.Add("Galileo");
        parts.Add(sats.Count > 0 ? "using " + string.Join("+", sats) : "no constellation bits set");
        return string.Join(", ", parts);
    }

    public static string DescribeAlarmFlag(uint flag)
    {
        if (flag == 0) return "none";
        var set = new List<string>();
        for (int i = 0; i < 32; i++)
            if ((flag & (1u << i)) != 0)
                set.Add($"bit{i}={(i < AlarmFlagBits.Length ? AlarmFlagBits[i] : "reserved")}");
        return string.Join(", ", set);
    }

    public static string AttachName(byte id)
    {
        if (StandardAttachNames.TryGetValue(id, out var n)) return n;
        return id switch
        {
            0x64 => "ADAS alarm (active safety extension)",
            0x65 => "DSM / driver monitoring alarm (active safety extension)",
            0x66 => "tyre pressure alarm (active safety extension)",
            0x67 => "blind spot alarm (active safety extension)",
            >= 0xE0 => "vendor-defined",
            _ => "unknown / not in JT/T 808 base standard",
        };
    }
}
