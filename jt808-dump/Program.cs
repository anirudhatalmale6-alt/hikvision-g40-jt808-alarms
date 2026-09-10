using System.Text;
using static Jt808Dump.Framing;

namespace Jt808Dump;

public static class Program
{
    static int _framesSeen, _framesBadChecksum, _locationFrames;
    static readonly SortedDictionary<byte, int> _attachIdCounts = new();
    static readonly SortedDictionary<ushort, int> _messageIdCounts = new();
    static int _activeSafetyItems;

    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            Usage();
            return 0;
        }

        if (args[0] == "--selftest")
            return SelfTest.Run() ? 0 : 1;

        if (args[0] == "--gensample")
        {
            SelfTest.WriteSample(args.Length > 1 ? args[1] : "samples/synthetic.txt");
            return 0;
        }

        byte[] raw;
        bool binary = args.Contains("--bin");
        // First non-flag argument that is not the value belonging to --rawout.
        string path = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i].StartsWith("-")) continue;
            if (i > 0 && args[i - 1] == "--rawout") continue;
            path = args[i];
            break;
        }

        if (path == null)
        {
            var stdin = Console.In.ReadToEnd();
            raw = Hex.FromLooseText(stdin);
        }
        else
        {
            var fileBytes = File.ReadAllBytes(path);

            // A .pcap/.pcapng straight from Wireshark or tcpdump needs no conversion step.
            if (PcapReader.LooksLikeCapture(fileBytes))
            {
                var cap = PcapReader.Read(fileBytes);
                Console.WriteLine($"Capture file: {cap.PacketsSeen} packet(s), " +
                                  $"{cap.TcpPacketsWithPayload} TCP packet(s) carrying data");
                foreach (var n in cap.Notes) Console.WriteLine($"  note: {n}");
                if (cap.Streams.Count > 0)
                {
                    Console.WriteLine("  TCP streams found:");
                    foreach (var kv in cap.Streams)
                        Console.WriteLine($"    {kv.Key}   {kv.Value.Count} byte(s)");
                }
                Console.WriteLine();

                // --rawout writes each stream's payload to its own file, so the extraction can be
                // checked against another tool rather than taken on trust.
                int ri = Array.IndexOf(args, "--rawout");
                if (ri >= 0 && ri + 1 < args.Length)
                {
                    int n2 = 0;
                    foreach (var kv in cap.Streams)
                    {
                        var outPath = $"{args[ri + 1]}.{++n2}_{kv.Key.Replace(" -> ", "_to_").Replace(":", "-")}.bin";
                        File.WriteAllBytes(outPath, kv.Value.ToArray());
                        Console.WriteLine($"  wrote {kv.Value.Count} byte(s) to {outPath}");
                    }
                    Console.WriteLine();
                }

                if (cap.Streams.Count > 0)
                {
                    // Each stream is parsed on its own. Merging them would splice one camera's
                    // bytes into another's frames and manufacture checksum failures.
                    int si = 0;
                    foreach (var kv in cap.Streams)
                    {
                        si++;
                        Console.WriteLine(new string('#', 78));
                        Console.WriteLine($"STREAM {si} of {cap.Streams.Count}: {kv.Key}  ({kv.Value.Count} bytes)");
                        Console.WriteLine(new string('#', 78));
                        AnalyzeBytes(kv.Value.ToArray());
                        Console.WriteLine();
                    }
                    Summary();
                    return 0;
                }
                raw = cap.Payload;
                if (raw.Length == 0)
                {
                    Console.WriteLine("No TCP payload in that capture. Either the filter caught only handshake");
                    Console.WriteLine("packets, or the devices are on UDP - say so and I will add UDP extraction.");
                    return 1;
                }
            }
            else if (binary)
            {
                raw = fileBytes;
            }
            else
            {
                raw = Hex.FromLooseText(System.Text.Encoding.UTF8.GetString(fileBytes));
            }
        }

        if (raw.Length == 0)
        {
            Console.WriteLine("No bytes to work with. Pass a file of hex, add --bin for a raw binary capture, or pipe hex on stdin.");
            return 1;
        }

        Console.WriteLine($"Input: {raw.Length} bytes");
        AnalyzeBytes(raw);
        Summary();
        return 0;
    }

    static void AnalyzeBytes(byte[] raw)
    {
        var frames = Framing.SplitFrames(raw, out var notes);
        foreach (var n in notes) Console.WriteLine($"  note: {n}");
        Console.WriteLine($"Found {frames.Count} frame(s) delimited by 0x7E");
        Console.WriteLine();

        int index = 0;
        foreach (var fr in frames)
            ReportFrame(++index, fr);
    }

    static void Usage()
    {
        Console.WriteLine(@"jt808dump - raw JT/T 808 packet inspector, with ADAS / DSM active-safety decoding

  jt808dump capture.txt        hex text: ""7E 02 00 ..."", ""7e0200..."", Wireshark or C# dumps
  jt808dump capture.bin --bin  raw bytes straight off the socket
  cat capture.txt | jt808dump  hex on stdin
  jt808dump --selftest         build known packets, parse them back, prove the decoder works

It never skips an additional-information item it does not recognise. Every item is listed with
its ID, length and raw bytes, which is the whole point: the alarm you are missing is probably
under an ID your library silently drops.");
    }

    static void ReportFrame(int index, byte[] escaped)
    {
        _framesSeen++;
        var f = Framing.Parse(escaped);
        _messageIdCounts.TryGetValue(f.MessageId, out int mc);
        _messageIdCounts[f.MessageId] = mc + 1;

        string name = Location.MessageNames.TryGetValue(f.MessageId, out var n) ? n : "unknown message id";
        Console.WriteLine(new string('=', 78));
        Console.WriteLine($"FRAME {index}   msg 0x{f.MessageId:X4}  {name}");
        Console.WriteLine(new string('=', 78));
        Console.WriteLine($"  on the wire      : {escaped.Length} bytes ({f.Unescaped.Length} after unescaping)");
        Console.WriteLine($"  protocol version : {(f.IsVersion2019 ? $"2019 (version flag set, version byte = {f.ProtocolVersion})" : "2011/2013 (no version flag)")}");
        Console.WriteLine($"  terminal phone   : {f.TerminalPhone}");
        Console.WriteLine($"  serial number    : {f.SerialNumber}");
        Console.WriteLine($"  body length      : {f.BodyLength} declared, {f.Body.Length} present");
        if (f.Encryption != 0) Console.WriteLine($"  encryption bits  : {f.Encryption}  <-- body is encrypted, plain parsing will fail");
        if (f.IsSubpackage) Console.WriteLine($"  subpackage       : part {f.PackageIndex} of {f.PackageTotal}  <-- reassemble before parsing the body");
        Console.WriteLine($"  checksum         : packet 0x{f.ChecksumInPacket:X2}, computed 0x{f.ChecksumComputed:X2}  {(f.ChecksumOk ? "OK" : "MISMATCH")}");
        if (!f.ChecksumOk) _framesBadChecksum++;
        foreach (var w in f.Warnings) Console.WriteLine($"  WARNING: {w}");

        if (f.Body.Length == 0)
        {
            Console.WriteLine();
            return;
        }

        switch (f.MessageId)
        {
            case 0x0200:
            case 0x0201:
                ReportLocation(f.Body, f.MessageId == 0x0201 ? 2 : 0);
                break;
            case 0x0704:
                ReportBatch(f.Body);
                break;
            case 0x0900:
                Console.WriteLine();
                Console.WriteLine($"  transparent message type: 0x{f.Body[0]:X2}   payload {f.Body.Length - 1} bytes");
                Console.WriteLine("  Vendors sometimes tunnel their own alarm structures through here. Raw payload:");
                Console.WriteLine(Hex.Dump(f.Body.AsSpan(1)));
                break;
            default:
                Console.WriteLine();
                Console.WriteLine("  body:");
                Console.WriteLine(Hex.Dump(f.Body));
                break;
        }
        Console.WriteLine();
    }

    static void ReportBatch(byte[] body)
    {
        Console.WriteLine();
        if (body.Length < 3) { Console.WriteLine("  0x0704 body too short"); return; }
        int p = 0;
        ushort count = Be16(body, ref p);
        byte type = body[p++];
        Console.WriteLine($"  batch of {count} location report(s), type {type} ({(type == 1 ? "blind-spot / stored data" : "normal")})");
        Console.WriteLine("  NOTE: alarms hide in here too. A handler that only listens for 0x0200 will never see them.");
        for (int i = 0; i < count && p + 2 <= body.Length; i++)
        {
            ushort len = Be16(body, ref p);
            if (p + len > body.Length) { Console.WriteLine($"  item {i + 1}: declares {len} bytes, only {body.Length - p} remain"); break; }
            var sub = new byte[len];
            Array.Copy(body, p, sub, 0, len);
            p += len;
            Console.WriteLine($"  --- batch item {i + 1} of {count} ({len} bytes) ---");
            ReportLocation(sub, 2);
        }
    }

    static void ReportLocation(byte[] body, int indentLevel = 0)
    {
        string ind = new string(' ', indentLevel);
        _locationFrames++;
        var loc = Location.ParseLocationBody(body);
        Console.WriteLine();
        Console.WriteLine($"{ind}  position         : {loc.Latitude:0.000000}, {loc.Longitude:0.000000}   alt {loc.Altitude} m   speed {loc.Speed / 10.0:0.0} km/h   heading {loc.Direction}");
        Console.WriteLine($"{ind}  device time      : {loc.Time}");
        Console.WriteLine($"{ind}  status word      : 0x{loc.Status:X8}");
        Console.WriteLine($"{ind}  alarm flag       : 0x{loc.AlarmFlag:X8}  {Location.DescribeAlarmFlag(loc.AlarmFlag)}");
        foreach (var w in loc.Warnings) Console.WriteLine($"{ind}  WARNING: {w}");

        Console.WriteLine();
        if (loc.Attachments.Count == 0)
        {
            Console.WriteLine($"{ind}  additional information: NONE. This packet carries position only -");
            Console.WriteLine($"{ind}  there is no alarm payload in it at all.");
            return;
        }

        Console.WriteLine($"{ind}  additional information: {loc.Attachments.Count} item(s)");
        foreach (var a in loc.Attachments)
        {
            _attachIdCounts.TryGetValue(a.Id, out int c);
            _attachIdCounts[a.Id] = c + 1;

            Console.WriteLine($"{ind}    ---------------------------------------------------------------");
            Console.WriteLine($"{ind}    ID 0x{a.Id:X2}  len {a.DeclaredLength}  -  {Location.AttachName(a.Id)}{(a.Truncated ? "   [TRUNCATED]" : "")}");

            if (a.Id is 0x64 or 0x65 or 0x66 or 0x67) _activeSafetyItems++;

            string decoded = ActiveSafety.TryDecode(a.Id, a.Data, out var mismatch);
            if (decoded != null)
            {
                Console.WriteLine(decoded);
                Console.WriteLine($"{ind}      raw           : {Hex.ToHex(a.Data)}");
            }
            else
            {
                if (mismatch != null) Console.WriteLine($"{ind}      LENGTH MISMATCH: {mismatch}");
                Console.WriteLine(Hex.Dump(a.Data, ind + "      "));
                PrintNumericGuesses(a.Data, ind);
            }
        }
    }

    /// <summary>
    /// For items we cannot name, surface the handful of readings that make a layout obvious to a
    /// human: an embedded BCD timestamp, a plausible lat/lng pair, printable ASCII.
    /// </summary>
    static void PrintNumericGuesses(byte[] d, string ind)
    {
        if (d.Length < 4) return;
        var hints = new List<string>();

        for (int i = 0; i + 6 <= d.Length; i++)
        {
            var t = BcdTime(d, i);
            if (t != null && t.StartsWith("202")) hints.Add($"offset {i}: looks like a BCD timestamp -> {t}");
        }
        for (int i = 0; i + 8 <= d.Length; i++)
        {
            int p1 = i, p2 = i + 4;
            uint a = Be32(d, ref p1), b = Be32(d, ref p2);
            double la = a / 1000000.0, ln = b / 1000000.0;
            if (la is > 1 and < 90 && ln is > 1 and < 180)
                hints.Add($"offset {i}: could be lat/lng -> {la:0.000000}, {ln:0.000000}");
        }
        var ascii = new string(d.Select(b => b >= 0x20 && b < 0x7f ? (char)b : '\0').ToArray());
        foreach (var run in ascii.Split('\0'))
            if (run.Length >= 5) hints.Add($"printable text: \"{run}\"");

        if (hints.Count == 0) return;
        Console.WriteLine($"{ind}      structure hints:");
        foreach (var h in hints.Take(8)) Console.WriteLine($"{ind}        - {h}");
    }

    static void Summary()
    {
        Console.WriteLine(new string('#', 78));
        Console.WriteLine("SUMMARY");
        Console.WriteLine(new string('#', 78));
        Console.WriteLine($"  frames parsed            : {_framesSeen}");
        Console.WriteLine($"  checksum mismatches      : {_framesBadChecksum}");
        Console.WriteLine($"  location reports         : {_locationFrames}");
        Console.WriteLine();
        Console.WriteLine("  message ids seen:");
        foreach (var kv in _messageIdCounts)
        {
            string nm = Location.MessageNames.TryGetValue(kv.Key, out var n) ? n : "unknown";
            Console.WriteLine($"    0x{kv.Key:X4}  x{kv.Value,-5} {nm}");
        }
        Console.WriteLine();
        if (_attachIdCounts.Count == 0)
        {
            Console.WriteLine("  additional-information IDs seen: NONE");
            Console.WriteLine("  Every location report in this capture is position-only. The cameras are not");
            Console.WriteLine("  attaching alarm data to what they send, so no parser change can recover it -");
            Console.WriteLine("  the problem is on the device configuration side, not in the server code.");
        }
        else
        {
            Console.WriteLine("  additional-information IDs seen (THIS is the list that matters):");
            foreach (var kv in _attachIdCounts)
                Console.WriteLine($"    0x{kv.Key:X2}  x{kv.Value,-5} {Location.AttachName(kv.Key)}");
            Console.WriteLine();
            Console.WriteLine(_activeSafetyItems > 0
                ? $"  {_activeSafetyItems} active-safety item(s) present. The alarms ARE arriving - they are being"
                : "  No 0x64/0x65/0x66/0x67 items in this capture.");
            if (_activeSafetyItems == 0)
                Console.WriteLine("  If any ID above is unfamiliar, that is the candidate: the vendor's own alarm block.");
            else
                Console.WriteLine("  dropped somewhere between the socket and your handler.");
        }
    }
}
