using System.Text.Json;
using JT808.Protocol;
using JT808.Protocol.Formatters;
using JT808.Protocol.Interfaces;
using JT808.Protocol.MessageBody;
using JT808.Protocol.MessagePack;

namespace HikvisionActiveSafety;

/// <summary>
/// DSM / driver monitoring alarm - additional-information item 0x65 of a 0x0200 location report.
///
/// Property names deliberately match the ones already used in the client's handler
/// (FlagState, AlarmOrEventType, AlarmLevel, Fatigue, AlarmTime, Latitude, Longitude) so the
/// existing switch statement compiles against this type without edits.
///
/// The item's own ID and length bytes are part of what this formatter reads: the library hands
/// the reader over positioned at the ID byte, not after it.
/// </summary>
public class JT808_0x0200_0x65 : JT808MessagePackFormatter<JT808_0x0200_0x65>, JT808_0x0200_CustomBodyBase, IJT808Analyze
{
    /// <summary>Payload length of this item, excluding the 2-byte ID+length header.</summary>
    public const int PayloadLength = 47;

    /// <summary>
    /// MUST default to 0x65: the custom factory builds a throwaway instance and uses this property
    /// as the map key. Leave it at 0 and every registered type collides on key 0 - SetMap throws
    /// "An element with the same key already exists" the moment you register a second item type.
    /// </summary>
    public byte AttachInfoId { get; set; } = 0x65;
    public byte AttachInfoLength { get; set; }

    /// <summary>Platform-assigned alarm serial. 0 when the device has no alarm number for it.</summary>
    public uint AlarmId { get; set; }
    /// <summary>0 = instantaneous event, 1 = alarm start, 2 = alarm end.</summary>
    public byte FlagState { get; set; }
    public byte AlarmOrEventType { get; set; }
    public byte AlarmLevel { get; set; }
    /// <summary>1-10 where reported; 0 means the device did not supply a degree.</summary>
    public byte Fatigue { get; set; }
    public byte[] Reserved { get; set; } = new byte[4];
    /// <summary>km/h, as reported inside the alarm block (not the 0.1 km/h of the outer report).</summary>
    public byte Speed { get; set; }
    public ushort Altitude { get; set; }
    /// <summary>Degrees x 1,000,000 - divide by 1000000.0 for decimal degrees.</summary>
    public int Latitude { get; set; }
    public int Longitude { get; set; }
    public DateTime AlarmTime { get; set; }
    public ushort VehicleStatus { get; set; }

    /// <summary>The 16-byte alarm identifier, kept whole because it is the key for attachment upload.</summary>
    public byte[] AlarmIdentifier { get; set; } = new byte[16];
    public string TerminalId { get; set; }
    public DateTime IdentifierTime { get; set; }
    public byte SequenceNo { get; set; }
    /// <summary>Number of photo/video files the device intends to upload for this alarm.</summary>
    public byte AttachmentCount { get; set; }

    public override JT808_0x0200_0x65 Deserialize(ref JT808MessagePackReader reader, IJT808Config config)
    {
        var v = new JT808_0x0200_0x65();
        v.AttachInfoId = reader.ReadByte();
        v.AttachInfoLength = reader.ReadByte();

        v.AlarmId = reader.ReadUInt32();
        v.FlagState = reader.ReadByte();
        v.AlarmOrEventType = reader.ReadByte();
        v.AlarmLevel = reader.ReadByte();
        v.Fatigue = reader.ReadByte();
        v.Reserved = reader.ReadArray(4).ToArray();
        v.Speed = reader.ReadByte();
        v.Altitude = reader.ReadUInt16();
        v.Latitude = reader.ReadInt32();
        v.Longitude = reader.ReadInt32();
        v.AlarmTime = reader.ReadDateTime_yyMMddHHmmss();
        v.VehicleStatus = reader.ReadUInt16();

        v.AlarmIdentifier = reader.ReadArray(16).ToArray();
        v.TerminalId = System.Text.Encoding.ASCII.GetString(v.AlarmIdentifier, 0, 7).TrimEnd('\0', ' ');
        v.IdentifierTime = AlarmIdentifierHelper.ReadBcdTime(v.AlarmIdentifier, 7);
        v.SequenceNo = v.AlarmIdentifier[13];
        v.AttachmentCount = v.AlarmIdentifier[14];
        return v;
    }

    public override void Serialize(ref JT808MessagePackWriter writer, JT808_0x0200_0x65 value, IJT808Config config)
    {
        byte id = 0x65, len = PayloadLength;
        writer.WriteByte(id);
        writer.WriteByte(len);
        writer.WriteUInt32(value.AlarmId);
        writer.WriteByte(value.FlagState);
        writer.WriteByte(value.AlarmOrEventType);
        writer.WriteByte(value.AlarmLevel);
        writer.WriteByte(value.Fatigue);
        var reserved = (value.Reserved ?? new byte[4]).AsSpan();
        writer.WriteArray(reserved);
        writer.WriteByte(value.Speed);
        writer.WriteUInt16(value.Altitude);
        writer.WriteInt32(value.Latitude);
        writer.WriteInt32(value.Longitude);
        var t = value.AlarmTime;
        writer.WriteDateTime_yyMMddHHmmss(t);
        writer.WriteUInt16(value.VehicleStatus);
        var ident = (value.AlarmIdentifier ?? new byte[16]).AsSpan();
        writer.WriteArray(ident);
    }

    public void Analyze(ref JT808MessagePackReader reader, Utf8JsonWriter writer, IJT808Config config)
    {
        var v = Deserialize(ref reader, config);
        writer.WriteNumber("AttachInfoId", v.AttachInfoId);
        writer.WriteNumber("AttachInfoLength", v.AttachInfoLength);
        writer.WriteNumber("AlarmId", v.AlarmId);
        writer.WriteNumber("FlagState", v.FlagState);
        writer.WriteNumber("AlarmOrEventType", v.AlarmOrEventType);
        writer.WriteString("AlarmDescription", ActiveSafetyNames.Dsm(v.AlarmOrEventType));
        writer.WriteNumber("AlarmLevel", v.AlarmLevel);
        writer.WriteNumber("Fatigue", v.Fatigue);
        writer.WriteNumber("Speed", v.Speed);
        writer.WriteNumber("Latitude", v.Latitude);
        writer.WriteNumber("Longitude", v.Longitude);
        writer.WriteString("AlarmTime", v.AlarmTime.ToString("yyyy-MM-dd HH:mm:ss"));
        writer.WriteString("TerminalId", v.TerminalId);
        writer.WriteNumber("AttachmentCount", v.AttachmentCount);
    }
}

public static class AlarmIdentifierHelper
{
    /// <summary>BCD yyMMddHHmmss inside the 16-byte alarm identifier. Returns default on junk.</summary>
    public static DateTime ReadBcdTime(byte[] b, int offset)
    {
        if (b == null || offset + 6 > b.Length) return default;
        try
        {
            var s = string.Concat(b.Skip(offset).Take(6).Select(x => x.ToString("X2")));
            return DateTime.ParseExact("20" + s, "yyyyMMddHHmmss", null);
        }
        catch { return default; }
    }
}
