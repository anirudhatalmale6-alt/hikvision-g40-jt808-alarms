using System.Text;

namespace Jt808Dump;

/// <summary>
/// Builds packets whose contents are known in advance, parses them back, and checks the answer.
/// This exists so the decoder cannot pass by finding nothing: there are negative cases here too -
/// a packet with no alarm must report no alarm, and a wrong-length item must be refused, not guessed.
/// </summary>
public static class SelfTest
{
    static int _pass, _fail;

    static void Check(string what, bool ok, string detail = null)
    {
        if (ok) { _pass++; Console.WriteLine($"  PASS  {what}"); }
        else { _fail++; Console.WriteLine($"  FAIL  {what}{(detail != null ? "  -> " + detail : "")}"); }
    }

    /// <summary>
    /// Runs one case in isolation. A case that throws is a failure like any other - it must not
    /// abort the run, or a single crash hides every check that comes after it.
    /// </summary>
    static void Case(string name, Action body)
    {
        try { body(); }
        catch (Exception ex) { _fail++; Console.WriteLine($"  FAIL  {name} threw {ex.GetType().Name}: {ex.Message}"); }
    }

    public static bool Run()
    {
        Console.WriteLine("jt808dump self-test");
        Console.WriteLine(new string('-', 60));

        Case("framing round trip", TestFramingRoundTrip);
        Case("escaping", TestEscaping);
        Case("2013 + DSM alarm", Test2013WithDsmAlarm);
        Case("2019 + ADAS alarm", Test2019WithAdasAlarm);
        Case("position only", TestPositionOnlyReportsNothing);
        Case("wrong length refused", TestWrongLengthItemIsRefused);
        Case("unknown vendor id", TestUnknownVendorIdIsStillListed);

        Console.WriteLine(new string('-', 60));
        Console.WriteLine($"{_pass} passed, {_fail} failed");
        return _fail == 0;
    }

    /// <summary>
    /// Writes a synthetic capture so the tool can be seen working before any real bytes exist.
    /// These packets are hand-built here, NOT recorded from a Hikvision device - they show the
    /// output format, they are not evidence of what a G40 sends.
    /// </summary>
    public static void WriteSample(string path)
    {
        var frames = new List<byte[]>
        {
            // heartbeat
            BuildFrame(0x0002, "013800138000", 1, Array.Empty<byte>(), false),

            // plain position, no alarm
            BuildFrame(0x0200, "013800138000", 2,
                LocationBody(0, 0x0003, 22.547, 114.085947, 100, 600, 90, "260909123040",
                    Item(0x01, new byte[] { 0, 0, 0x27, 0x10 }),
                    Item(0x30, new byte[] { 24 })), false),

            // DSM: phone use, alarm start, two attachments pending
            BuildFrame(0x0200, "013800138000", 3,
                LocationBody(0, 0x0003, 22.547, 114.085947, 100, 600, 90, "260909123045",
                    Item(0x01, new byte[] { 0, 0, 0x27, 0x10 }),
                    Item(0x65, DsmData(0x02, 0x01, 1, 0, 2)),
                    Item(0x30, new byte[] { 24 })), false),

            // ADAS forward collision, 2019 header
            BuildFrame(0x0200, "013800138000", 4,
                LocationBody(0, 0x0003, 22.547, 114.085947, 120, 720, 45, "260909124500",
                    Item(0x64, AdasData(0x01, 0x01, 2))), true),

            // DSM fatigue, 2019 header - the combination the G40s reportedly use
            BuildFrame(0x0200, "013800138000", 6,
                LocationBody(0, 0x0003, 22.547, 114.085947, 100, 600, 90, "260909125500",
                    Item(0x01, new byte[] { 0, 0, 0x27, 0x10 }),
                    Item(0x65, DsmData(0x01, 0x01, 2, 7, 3))), true),

            // something under an ID no public table covers
            BuildFrame(0x0200, "013800138000", 5,
                LocationBody(0, 0x0003, 22.547, 114.085947, 100, 600, 90, "260909124530",
                    Item(0xE7, BuildOpaqueVendorBlock())), false),
        };

        var sb = new StringBuilder();
        sb.AppendLine("# synthetic JT808 capture - built by jt808dump --gensample, not recorded from a device");
        foreach (var f in frames) sb.AppendLine(Hex.ToHex(f));
        File.WriteAllText(path, sb.ToString());
        Console.WriteLine($"wrote {frames.Count} synthetic frames to {path}");
    }

    static byte[] BuildOpaqueVendorBlock()
    {
        var b = new List<byte>();
        b.AddRange(Be32(0x000000FF));
        b.AddRange(Bcd("260909124530"));
        b.AddRange(Be32(22547000));
        b.AddRange(Be32(114085947));
        b.AddRange(Encoding.ASCII.GetBytes("CH01"));
        b.Add(0x03);
        return b.ToArray();
    }

    // ---------------------------------------------------------------- builders

    static byte[] Be16(ushort v) => new[] { (byte)(v >> 8), (byte)v };
    static byte[] Be32(uint v) => new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v };
    static byte[] Bcd(string digits)
    {
        var b = new byte[digits.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(digits.Substring(i * 2, 2), 16);
        return b;
    }

    static byte[] LocationBody(uint alarmFlag, uint status, double lat, double lng,
                               ushort alt, ushort speed, ushort dir, string bcdTime, params byte[][] items)
    {
        var b = new List<byte>();
        b.AddRange(Be32(alarmFlag));
        b.AddRange(Be32(status));
        b.AddRange(Be32((uint)Math.Round(lat * 1000000)));
        b.AddRange(Be32((uint)Math.Round(lng * 1000000)));
        b.AddRange(Be16(alt));
        b.AddRange(Be16(speed));
        b.AddRange(Be16(dir));
        b.AddRange(Bcd(bcdTime));
        foreach (var it in items) b.AddRange(it);
        return b.ToArray();
    }

    static byte[] Item(byte id, byte[] data)
    {
        var b = new List<byte> { id, (byte)data.Length };
        b.AddRange(data);
        return b.ToArray();
    }

    static byte[] AlarmIdentifier(string terminalId, string bcdTime, byte seq, byte attachCount)
    {
        var b = new List<byte>();
        var t = Encoding.ASCII.GetBytes(terminalId.PadRight(7, '\0'));
        b.AddRange(t.Take(7));
        b.AddRange(Bcd(bcdTime));
        b.Add(seq);
        b.Add(attachCount);
        b.Add(0x00);
        return b.ToArray();
    }

    /// <summary>DSM item, JSATL12 layout, 47 bytes.</summary>
    static byte[] DsmData(byte alarmType, byte flagState, byte level, byte fatigue, byte attachCount)
    {
        var b = new List<byte>();
        b.AddRange(Be32(0x0000002A));       // alarm id
        b.Add(flagState);
        b.Add(alarmType);
        b.Add(level);
        b.Add(fatigue);
        b.AddRange(new byte[4]);            // reserved
        b.Add(60);                          // speed
        b.AddRange(Be16(100));              // altitude
        b.AddRange(Be32(22547000));         // lat
        b.AddRange(Be32(114085947));        // lng
        b.AddRange(Bcd("260909123045"));    // time
        b.AddRange(Be16(0));                // vehicle status
        b.AddRange(AlarmIdentifier("G40TEST", "260909123045", 1, attachCount));
        return b.ToArray();
    }

    /// <summary>ADAS item, JSATL12 layout, 47 bytes.</summary>
    static byte[] AdasData(byte alarmType, byte flagState, byte level)
    {
        var b = new List<byte>();
        b.AddRange(Be32(0x0000002B));
        b.Add(flagState);
        b.Add(alarmType);
        b.Add(level);
        b.Add(45);                          // front vehicle speed
        b.Add(8);                           // front distance, 0.1s units
        b.Add(0x01);                        // deviation type: left
        b.Add(0x00);                        // road sign type
        b.Add(0x00);                        // road sign data
        b.Add(72);                          // speed
        b.AddRange(Be16(120));              // altitude
        b.AddRange(Be32(22547000));
        b.AddRange(Be32(114085947));
        b.AddRange(Bcd("260909124500"));
        b.AddRange(Be16(0));
        b.AddRange(AlarmIdentifier("G40TEST", "260909124500", 2, 3));
        return b.ToArray();
    }

    static byte[] BuildFrame(ushort msgId, string phone, ushort serial, byte[] body, bool v2019)
    {
        var head = new List<byte>();
        head.AddRange(Be16(msgId));
        ushort prop = (ushort)(body.Length & 0x03FF);
        if (v2019) prop |= 1 << 14;
        head.AddRange(Be16(prop));
        if (v2019)
        {
            head.Add(0x01);                          // protocol version
            head.AddRange(Bcd(phone.PadLeft(20, '0')));
        }
        else
        {
            head.AddRange(Bcd(phone.PadLeft(12, '0')));
        }
        head.AddRange(Be16(serial));
        var all = head.Concat(body).ToList();
        all.Add(Framing.Checksum(all.ToArray()));
        return Framing.Escape(all.ToArray());
    }

    // ---------------------------------------------------------------- cases

    static void TestFramingRoundTrip()
    {
        var body = LocationBody(0, 0x0003, 22.547, 114.085947, 100, 600, 90, "260909123045");
        var frame = BuildFrame(0x0200, "013800138000", 42, body, false);
        var f = Framing.Parse(frame);
        Check("2013 header: message id", f.MessageId == 0x0200, $"got 0x{f.MessageId:X4}");
        Check("2013 header: terminal phone", f.TerminalPhone == "13800138000", f.TerminalPhone);
        Check("2013 header: serial", f.SerialNumber == 42, f.SerialNumber.ToString());
        Check("2013 header: checksum verifies", f.ChecksumOk, $"{f.ChecksumInPacket:X2} vs {f.ChecksumComputed:X2}");
        Check("2013 header: body length matches", f.Body.Length == body.Length, $"{f.Body.Length} vs {body.Length}");
    }

    static void TestEscaping()
    {
        // altitude 0x7E7D forces both escape sequences into the body
        var body = LocationBody(0, 0, 22.547, 114.085947, 0x7E7D, 0, 0, "260909123045");
        var frame = BuildFrame(0x0200, "013800138000", 1, body, false);
        Check("escaping: 0x7E/0x7D do not appear unescaped inside the frame",
            !frame.Skip(1).Take(frame.Length - 2).Contains((byte)0x7E));
        var f = Framing.Parse(frame);
        var loc = Location.ParseLocationBody(f.Body);
        Check("escaping: value survives the round trip", loc.Altitude == 0x7E7D, $"got 0x{loc.Altitude:X4}");
    }

    static void Test2013WithDsmAlarm()
    {
        var body = LocationBody(0, 0x0003, 22.547, 114.085947, 100, 600, 90, "260909123045",
            Item(0x01, new byte[] { 0, 0, 0x27, 0x10 }),      // mileage
            Item(0x30, new byte[] { 24 }),                    // signal strength
            Item(0x65, DsmData(alarmType: 0x02, flagState: 0x01, level: 1, fatigue: 0, attachCount: 2)));

        var f = Framing.Parse(BuildFrame(0x0200, "013800138000", 7, body, false));
        var loc = Location.ParseLocationBody(f.Body);

        Check("DSM: three additional-info items found", loc.Attachments.Count == 3, loc.Attachments.Count.ToString());
        var dsm = loc.Attachments.FirstOrDefault(a => a.Id == 0x65);
        Check("DSM: 0x65 item present", dsm != null);
        if (dsm == null) { _fail += 6; Console.WriteLine("  FAIL  DSM: remaining 6 checks unreachable without the item"); return; }
        Check("DSM: 0x65 item is 47 bytes", dsm.Data.Length == ActiveSafety.Len0x65, dsm.Data.Length.ToString());

        var text = ActiveSafety.TryDecode(0x65, dsm.Data, out var mismatch);
        Check("DSM: decoder accepted the item", text != null, mismatch);
        Check("DSM: alarm type read as phone use", text != null && text.Contains("phone use while driving"));
        Check("DSM: flag state read as start", text != null && text.Contains("ALARM START"));
        Check("DSM: attachment count read as 2", text != null && text.Contains("attachment count: 2"));
        Check("DSM: position decoded", text != null && text.Contains("22.547000, 114.085947"));
        Check("DSM: alarm time decoded", text != null && text.Contains("2026-09-09 12:30:45"));
    }

    static void Test2019WithAdasAlarm()
    {
        var body = LocationBody(0, 0x0003, 22.547, 114.085947, 120, 720, 45, "260909124500",
            Item(0x64, AdasData(alarmType: 0x01, flagState: 0x01, level: 2)));

        var f = Framing.Parse(BuildFrame(0x0200, "013800138000", 9, body, true));
        Check("2019: version flag detected", f.IsVersion2019);
        Check("2019: protocol version byte", f.ProtocolVersion == 1, f.ProtocolVersion.ToString());
        Check("2019: phone read from the 10-byte BCD field", f.TerminalPhone == "13800138000", f.TerminalPhone);
        Check("2019: checksum verifies", f.ChecksumOk);

        var loc = Location.ParseLocationBody(f.Body);
        var adas = loc.Attachments.FirstOrDefault(a => a.Id == 0x64);
        Check("ADAS: 0x64 item present", adas != null);
        if (adas == null) { _fail += 4; Console.WriteLine("  FAIL  ADAS: remaining 4 checks unreachable without the item"); return; }
        var text = ActiveSafety.TryDecode(0x64, adas.Data, out var mismatch);
        Check("ADAS: decoder accepted the item", text != null, mismatch);
        Check("ADAS: forward collision recognised", text != null && text.Contains("forward collision warning"));
        Check("ADAS: level 2 read", text != null && text.Contains("alarm level       : 2"));
        Check("ADAS: headway 0.8 s read", text != null && text.Contains("0.8 s headway"));
    }

    /// <summary>Negative control: a plain position packet must not produce an alarm.</summary>
    static void TestPositionOnlyReportsNothing()
    {
        var body = LocationBody(0, 0x0003, 22.547, 114.085947, 100, 600, 90, "260909123045",
            Item(0x01, new byte[] { 0, 0, 0x27, 0x10 }),
            Item(0x30, new byte[] { 24 }));
        var f = Framing.Parse(BuildFrame(0x0200, "013800138000", 11, body, false));
        var loc = Location.ParseLocationBody(f.Body);
        Check("negative control: no active-safety item invented on a plain position packet",
            loc.Attachments.All(a => a.Id is not (0x64 or 0x65 or 0x66 or 0x67)));
        Check("negative control: the two ordinary items are still found", loc.Attachments.Count == 2);
    }

    /// <summary>A 0x65 of the wrong size must be refused, not decoded into plausible nonsense.</summary>
    static void TestWrongLengthItemIsRefused()
    {
        var short65 = DsmData(0x02, 0x01, 1, 0, 0).Take(40).ToArray();
        var text = ActiveSafety.TryDecode(0x65, short65, out var mismatch);
        Check("wrong length: decoder refused a 40-byte 0x65", text == null);
        Check("wrong length: refusal explains itself", mismatch != null && mismatch.Contains("40 bytes"));
    }

    /// <summary>A vendor ID nobody documents must still be surfaced with its bytes.</summary>
    static void TestUnknownVendorIdIsStillListed()
    {
        var payload = Encoding.ASCII.GetBytes("HIKVISION-BLOB");
        var body = LocationBody(0, 0x0003, 22.547, 114.085947, 100, 600, 90, "260909123045",
            Item(0xE7, payload));
        var f = Framing.Parse(BuildFrame(0x0200, "013800138000", 13, body, false));
        var loc = Location.ParseLocationBody(f.Body);
        var item = loc.Attachments.FirstOrDefault(a => a.Id == 0xE7);
        Check("unknown ID: 0xE7 surfaced rather than skipped", item != null);
        Check("unknown ID: payload preserved byte for byte",
            item != null && item.Data.SequenceEqual(payload));
        Check("unknown ID: labelled as vendor-defined", Location.AttachName(0xE7).Contains("vendor"));
    }
}
