namespace HikvisionActiveSafety;

/// <summary>
/// Alarm-type code to English text.
///
/// These names come from the public active-safety supplement that ADAS dashcams follow. A code
/// that is not in the table is reported as unmapped rather than guessed at - if a G40 turns out
/// to use a code that is not here, that is a finding to record, not something to paper over.
/// </summary>
public static class ActiveSafetyNames
{
    static readonly Dictionary<byte, string> AdasMap = new()
    {
        [0x01] = "Forward collision warning",
        [0x02] = "Lane departure warning",
        [0x03] = "Headway monitoring / following too close",
        [0x04] = "Pedestrian collision warning",
        [0x05] = "Frequent lane change",
        [0x06] = "Road sign overrun",
        [0x07] = "Obstacle detected",
        [0x08] = "Driving assistance function failure",
        [0x10] = "Road sign recognition event",
        [0x11] = "Active capture event",
    };

    static readonly Dictionary<byte, string> DsmMap = new()
    {
        [0x01] = "Fatigue driving warning",
        [0x02] = "Phone use while driving",
        [0x03] = "Smoking warning",
        [0x04] = "Long time without looking ahead / distracted",
        [0x05] = "No driver detected",
        [0x06] = "Both hands off steering wheel",
        [0x07] = "Driver monitoring system failure",
        [0x10] = "Automatic capture event",
        [0x11] = "Driver change event",
    };

    public static string Adas(byte code) =>
        AdasMap.TryGetValue(code, out var s) ? s : $"UNMAPPED ADAS code 0x{code:X2}";

    public static string Dsm(byte code) =>
        DsmMap.TryGetValue(code, out var s) ? s : $"UNMAPPED DSM code 0x{code:X2}";

    public static bool IsMappedAdas(byte code) => AdasMap.ContainsKey(code);
    public static bool IsMappedDsm(byte code) => DsmMap.ContainsKey(code);

    public static string FlagState(byte code) => code switch
    {
        0x00 => "instantaneous event",
        0x01 => "alarm start",
        0x02 => "alarm end",
        _ => $"unexpected flag state 0x{code:X2}",
    };
}
