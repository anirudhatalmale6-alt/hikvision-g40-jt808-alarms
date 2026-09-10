using JT808.Protocol;
using JT808.Protocol.MessageBody;

namespace HikvisionActiveSafety;

/// <summary>
/// Before/after proof, run with: dotnet run
///
/// Same bytes, two configs. The only difference is the registration call. If the "after" half
/// stops decoding, the fix has regressed and this program exits non-zero.
/// </summary>
public static class Program
{
    // A 2013-format 0x0200 carrying items 0x01 (mileage), 0x65 (DSM, 47 bytes), 0x30 (signal).
    // Hand-built, with known contents - phone use, alarm start, level 1, 2 attachments pending.
    const string SampleHex =
        "7E 02 00 00 56 01 38 00 13 80 00 00 03 00 00 00 00 00 00 00 03 01 58 0A 38 06 CC D0 3B " +
        "00 64 02 58 00 5A 26 09 09 12 30 45 01 04 00 00 27 10 65 2F 00 00 00 2A 01 02 01 00 00 " +
        "00 00 00 3C 00 64 01 58 0A 38 06 CC D0 3B 26 09 09 12 30 45 00 00 47 34 30 54 45 53 54 " +
        "26 09 09 12 30 45 01 02 00 30 01 18 AC 7E";

    // The same idea in JT/T 808-2019 framing: version flag set, 10-byte BCD phone number.
    // Fatigue driving, level 2, degree 7, 3 attachments pending. The client's G40s report 2019.
    const string SampleHex2019 =
        "7E 02 00 40 53 01 00 00 00 00 01 38 00 13 80 00 00 06 00 00 00 00 00 00 00 03 01 58 0A " +
        "38 06 CC D0 3B 00 64 02 58 00 5A 26 09 09 12 55 00 01 04 00 00 27 10 65 2F 00 00 00 2A " +
        "01 01 02 07 00 00 00 00 3C 00 64 01 58 0A 38 06 CC D0 3B 26 09 09 12 30 45 00 00 47 34 " +
        "30 54 45 53 54 26 09 09 12 30 45 01 03 00 E2 7E";

    static int _failures;

    static void Expect(string what, bool ok, string detail = null)
    {
        if (ok) Console.WriteLine($"  PASS  {what}");
        else { _failures++; Console.WriteLine($"  FAIL  {what}{(detail != null ? "  -> " + detail : "")}"); }
    }

    public static int Main(string[] args)
    {
        var bytes = SampleHex.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                             .Select(x => Convert.ToByte(x, 16)).ToArray();

        Console.WriteLine("================================================================");
        Console.WriteLine(" BEFORE - stock JT808 config, nothing registered");
        Console.WriteLine("================================================================");
        var before = Parse(bytes, register: false);
        Console.WriteLine(LocationDiagnostics.Describe(before));
        Console.WriteLine();

        bool foundBefore = before.CustomLocationAttachData != null &&
                           before.CustomLocationAttachData.ContainsKey(0x65);
        Expect("before: CustomLocationAttachData.TryGetValue(0x65) fails, as reported", !foundBefore);
        Expect("before: the 0x65 bytes are sitting in UnknownLocationAttachData",
            before.UnknownLocationAttachData != null && before.UnknownLocationAttachData.ContainsKey(0x65));

        Console.WriteLine();
        Console.WriteLine("================================================================");
        Console.WriteLine(" AFTER - same bytes, config.UseActiveSafetyAlarms() called");
        Console.WriteLine("================================================================");
        var after = Parse(bytes, register: true);
        Console.WriteLine(LocationDiagnostics.Describe(after));
        Console.WriteLine();

        bool found = after.CustomLocationAttachData != null &&
                     after.CustomLocationAttachData.TryGetValue(0x65, out var raw65);
        Expect("after: CustomLocationAttachData.TryGetValue(0x65) succeeds", found);
        if (!found)
        {
            Console.WriteLine($"\n{_failures} check(s) failed");
            return 1;
        }

        var dsm = (JT808_0x0200_0x65)after.CustomLocationAttachData[0x65];
        Console.WriteLine("  decoded DSM alarm:");
        Console.WriteLine($"    item id / length : 0x{dsm.AttachInfoId:X2} / {dsm.AttachInfoLength}");
        Console.WriteLine($"    alarm id         : {dsm.AlarmId}");
        Console.WriteLine($"    flag state       : {dsm.FlagState} ({ActiveSafetyNames.FlagState(dsm.FlagState)})");
        Console.WriteLine($"    alarm type       : 0x{dsm.AlarmOrEventType:X2} {ActiveSafetyNames.Dsm(dsm.AlarmOrEventType)}");
        Console.WriteLine($"    level            : {dsm.AlarmLevel}");
        Console.WriteLine($"    fatigue degree   : {dsm.Fatigue}");
        Console.WriteLine($"    speed            : {dsm.Speed} km/h");
        Console.WriteLine($"    position         : {dsm.Latitude / 1000000.0:0.000000}, {dsm.Longitude / 1000000.0:0.000000}");
        Console.WriteLine($"    alarm time       : {dsm.AlarmTime:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"    terminal id      : \"{dsm.TerminalId}\"");
        Console.WriteLine($"    sequence no      : {dsm.SequenceNo}");
        Console.WriteLine($"    attachment count : {dsm.AttachmentCount}");
        Console.WriteLine();

        Expect("field: item id is 0x65", dsm.AttachInfoId == 0x65, $"0x{dsm.AttachInfoId:X2}");
        Expect("field: declared length is 47", dsm.AttachInfoLength == 47, dsm.AttachInfoLength.ToString());
        Expect("field: alarm id 42", dsm.AlarmId == 42, dsm.AlarmId.ToString());
        Expect("field: flag state is alarm start", dsm.FlagState == 1, dsm.FlagState.ToString());
        Expect("field: type 0x02 maps to phone use", ActiveSafetyNames.Dsm(dsm.AlarmOrEventType) == "Phone use while driving");
        Expect("field: level 1", dsm.AlarmLevel == 1, dsm.AlarmLevel.ToString());
        Expect("field: speed 60", dsm.Speed == 60, dsm.Speed.ToString());
        Expect("field: latitude 22.547000", dsm.Latitude == 22547000, dsm.Latitude.ToString());
        Expect("field: longitude 114.085947", dsm.Longitude == 114085947, dsm.Longitude.ToString());
        Expect("field: alarm time 2026-09-09 12:30:45",
            dsm.AlarmTime == new DateTime(2026, 9, 9, 12, 30, 45), dsm.AlarmTime.ToString("O"));
        Expect("field: terminal id G40TEST", dsm.TerminalId == "G40TEST", dsm.TerminalId);
        Expect("field: attachment count 2", dsm.AttachmentCount == 2, dsm.AttachmentCount.ToString());

        // The registration must not cost us the ordinary items.
        Expect("regression: 0x01 mileage still parsed",
            after.BasicLocationAttachData != null && after.BasicLocationAttachData.ContainsKey(0x01));
        Expect("regression: 0x30 signal strength still parsed",
            after.BasicLocationAttachData != null && after.BasicLocationAttachData.ContainsKey(0x30));
        Expect("regression: nothing left stranded in UnknownLocationAttachData",
            after.UnknownLocationAttachData == null || after.UnknownLocationAttachData.Count == 0,
            after.UnknownLocationAttachData == null ? "null" : string.Join(",", after.UnknownLocationAttachData.Keys.Select(k => $"0x{k:X2}")));

        Run2019Case();

        Console.WriteLine();
        Console.WriteLine(_failures == 0 ? "ALL CHECKS PASSED" : $"{_failures} CHECK(S) FAILED");
        return _failures == 0 ? 0 : 1;
    }

    /// <summary>
    /// Same registration, JT/T 808-2019 framing. The 2019 header is a different length (version
    /// byte plus a 10-byte BCD phone number), so this is not a formality - if the version were
    /// mis-detected the body would be read at the wrong offset and nothing below would decode.
    /// </summary>
    static void Run2019Case()
    {
        Console.WriteLine();
        Console.WriteLine("================================================================");
        Console.WriteLine(" JT/T 808-2019 framing - the version the G40s report");
        Console.WriteLine("================================================================");

        var bytes = SampleHex2019.Split(' ', StringSplitOptions.RemoveEmptyEntries)
                                 .Select(x => Convert.ToByte(x, 16)).ToArray();

        var before = Parse(bytes, register: false);
        Expect("2019 before: 0x65 stranded in UnknownLocationAttachData",
            before.UnknownLocationAttachData != null && before.UnknownLocationAttachData.ContainsKey(0x65));

        var after = Parse(bytes, register: true);
        Console.WriteLine(LocationDiagnostics.Describe(after));
        Console.WriteLine();

        bool found = after.CustomLocationAttachData != null &&
                     after.CustomLocationAttachData.ContainsKey(0x65);
        Expect("2019 after: 0x65 decoded from a 2019-framed packet", found);
        if (!found) return;

        var dsm = (JT808_0x0200_0x65)after.CustomLocationAttachData[0x65];
        Console.WriteLine($"  decoded: {ActiveSafetyNames.Dsm(dsm.AlarmOrEventType)}, " +
                          $"{ActiveSafetyNames.FlagState(dsm.FlagState)}, level {dsm.AlarmLevel}, " +
                          $"fatigue degree {dsm.Fatigue}, {dsm.AttachmentCount} attachment(s)");
        Console.WriteLine();

        Expect("2019 field: fatigue driving", dsm.AlarmOrEventType == 0x01, $"0x{dsm.AlarmOrEventType:X2}");
        Expect("2019 field: level 2", dsm.AlarmLevel == 2, dsm.AlarmLevel.ToString());
        Expect("2019 field: fatigue degree 7", dsm.Fatigue == 7, dsm.Fatigue.ToString());
        Expect("2019 field: attachment count 3", dsm.AttachmentCount == 3, dsm.AttachmentCount.ToString());
        Expect("2019 field: position survived the longer header",
            dsm.Latitude == 22547000 && dsm.Longitude == 114085947, $"{dsm.Latitude},{dsm.Longitude}");
        Expect("2019 regression: 0x01 mileage still parsed",
            after.BasicLocationAttachData != null && after.BasicLocationAttachData.ContainsKey(0x01));
    }

    static JT808_0x0200 Parse(byte[] bytes, bool register)
    {
        var config = new ActiveSafetyConfig();
        if (register) config.UseActiveSafetyAlarms();
        var serializer = new JT808Serializer(config);
        var pkg = serializer.Deserialize(bytes);
        return (JT808_0x0200)pkg.Bodies;
    }
}
