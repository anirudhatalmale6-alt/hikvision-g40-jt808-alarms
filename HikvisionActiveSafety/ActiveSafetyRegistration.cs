using JT808.Protocol;
using JT808.Protocol.MessageBody;

namespace HikvisionActiveSafety;

/// <summary>
/// Wires the active-safety item types into a JT808 config.
///
/// This is the step whose absence causes the symptom "I tried 0x65 and it did not work": with no
/// registration the library does not throw and does not log - it files the bytes under
/// UnknownLocationAttachData and carries on, so CustomLocationAttachData.TryGetValue(0x65, ...)
/// returns false on a packet that plainly contains the alarm.
/// </summary>
/// <summary>
/// A concrete config. GlobalConfigBase is abstract with a protected constructor, so a gateway
/// needs its own subclass before it can register anything.
/// </summary>
public class ActiveSafetyConfig : JT808.Protocol.Interfaces.GlobalConfigBase
{
    public override string ConfigId { get; protected set; } = "ActiveSafety";
}

public static class ActiveSafetyRegistration
{
    public static IJT808Config UseActiveSafetyAlarms(this IJT808Config config)
    {
        config.JT808_0X0200_Custom_Factory
              .SetMap<JT808_0x0200_0x64>()
              .SetMap<JT808_0x0200_0x65>();
        return config;
    }
}

/// <summary>
/// Reports what a location report actually contains, across every bucket the library files
/// items into. Run this before deciding anything: it turns "the alarm never arrives" into a
/// list of the IDs that did arrive.
/// </summary>
public static class LocationDiagnostics
{
    public static string Describe(JT808_0x0200 loc)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"position {loc.Lat / 1000000.0:0.000000}, {loc.Lng / 1000000.0:0.000000}  " +
                      $"speed {loc.Speed / 10.0:0.0} km/h  time {loc.GPSTime:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"alarm flag 0x{loc.AlarmFlag:X8}   status 0x{loc.StatusFlag:X8}");

        sb.AppendLine($"BasicLocationAttachData   : {Keys(loc.BasicLocationAttachData)}");
        sb.AppendLine($"CustomLocationAttachData  : {Keys(loc.CustomLocationAttachData)}");
        sb.AppendLine($"CustomLocationAttachData2 : {Keys(loc.CustomLocationAttachData2)}");
        sb.AppendLine($"CustomLocationAttachData3 : {Keys(loc.CustomLocationAttachData3)}");
        sb.AppendLine($"CustomLocationAttachData4 : {Keys(loc.CustomLocationAttachData4)}");

        if (loc.UnknownLocationAttachData != null && loc.UnknownLocationAttachData.Count > 0)
        {
            sb.AppendLine("UnknownLocationAttachData : items the library could not map -");
            foreach (var kv in loc.UnknownLocationAttachData)
                sb.AppendLine($"    0x{kv.Key:X2}  {kv.Value.Length} bytes  {BitConverter.ToString(kv.Value).Replace("-", " ")}");
            sb.AppendLine("    ^ anything listed here is present in the packet and being thrown away.");
        }
        else
        {
            sb.AppendLine("UnknownLocationAttachData : (empty)");
        }

        if (loc.ExceptionLocationAttachOriginalData != null && loc.ExceptionLocationAttachOriginalData.Count > 0)
        {
            sb.AppendLine("ExceptionLocationAttachOriginalData : items that threw while parsing -");
            foreach (var b in loc.ExceptionLocationAttachOriginalData)
                sb.AppendLine($"    {BitConverter.ToString(b).Replace("-", " ")}");
        }
        return sb.ToString().TrimEnd();
    }

    // CustomLocationAttachData2/3 are keyed by ushort, not byte - hence the open key type.
    static string Keys<TKey, TValue>(Dictionary<TKey, TValue> d) =>
        d == null || d.Count == 0 ? "(empty)" : string.Join(", ", d.Keys.Select(k => $"0x{k:X}"));
}
