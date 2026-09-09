using System.Text.Json;
using JT808.Protocol;
using JT808.Protocol.Formatters;
using JT808.Protocol.Interfaces;
using JT808.Protocol.MessageBody;
using JT808.Protocol.MessagePack;

namespace HikvisionActiveSafety;

/// <summary>
/// ADAS alarm - additional-information item 0x64 of a 0x0200 location report.
/// Forward collision, lane departure, headway, pedestrian collision and friends.
/// </summary>
public class JT808_0x0200_0x64 : JT808MessagePackFormatter<JT808_0x0200_0x64>, JT808_0x0200_CustomBodyBase, IJT808Analyze
{
    public const int PayloadLength = 47;

    /// <summary>
    /// MUST default to 0x64: the custom factory builds a throwaway instance and uses this property
    /// as the map key. Leave it at 0 and every registered type collides on key 0 - SetMap throws
    /// "An element with the same key already exists" the moment you register a second item type.
    /// </summary>
    public byte AttachInfoId { get; set; } = 0x64;
    public byte AttachInfoLength { get; set; }

    public uint AlarmId { get; set; }
    public byte FlagState { get; set; }
    public byte AlarmOrEventType { get; set; }
    public byte AlarmLevel { get; set; }
    /// <summary>Speed of the vehicle in front, km/h. Only meaningful for headway/collision types.</summary>
    public byte FrontVehicleSpeed { get; set; }
    /// <summary>Headway to the vehicle in front, in 0.1 second units.</summary>
    public byte FrontVehicleDistance { get; set; }
    /// <summary>1 = left, 2 = right. Only meaningful for lane departure.</summary>
    public byte DeviationType { get; set; }
    public byte RoadSignType { get; set; }
    public byte RoadSignData { get; set; }
    public byte Speed { get; set; }
    public ushort Altitude { get; set; }
    public int Latitude { get; set; }
    public int Longitude { get; set; }
    public DateTime AlarmTime { get; set; }
    public ushort VehicleStatus { get; set; }

    public byte[] AlarmIdentifier { get; set; } = new byte[16];
    public string TerminalId { get; set; }
    public DateTime IdentifierTime { get; set; }
    public byte SequenceNo { get; set; }
    public byte AttachmentCount { get; set; }

    public override JT808_0x0200_0x64 Deserialize(ref JT808MessagePackReader reader, IJT808Config config)
    {
        var v = new JT808_0x0200_0x64();
        v.AttachInfoId = reader.ReadByte();
        v.AttachInfoLength = reader.ReadByte();

        v.AlarmId = reader.ReadUInt32();
        v.FlagState = reader.ReadByte();
        v.AlarmOrEventType = reader.ReadByte();
        v.AlarmLevel = reader.ReadByte();
        v.FrontVehicleSpeed = reader.ReadByte();
        v.FrontVehicleDistance = reader.ReadByte();
        v.DeviationType = reader.ReadByte();
        v.RoadSignType = reader.ReadByte();
        v.RoadSignData = reader.ReadByte();
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

    public override void Serialize(ref JT808MessagePackWriter writer, JT808_0x0200_0x64 value, IJT808Config config)
    {
        byte id = 0x64, len = PayloadLength;
        writer.WriteByte(id);
        writer.WriteByte(len);
        writer.WriteUInt32(value.AlarmId);
        writer.WriteByte(value.FlagState);
        writer.WriteByte(value.AlarmOrEventType);
        writer.WriteByte(value.AlarmLevel);
        writer.WriteByte(value.FrontVehicleSpeed);
        writer.WriteByte(value.FrontVehicleDistance);
        writer.WriteByte(value.DeviationType);
        writer.WriteByte(value.RoadSignType);
        writer.WriteByte(value.RoadSignData);
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
        writer.WriteNumber("AlarmId", v.AlarmId);
        writer.WriteNumber("FlagState", v.FlagState);
        writer.WriteNumber("AlarmOrEventType", v.AlarmOrEventType);
        writer.WriteString("AlarmDescription", ActiveSafetyNames.Adas(v.AlarmOrEventType));
        writer.WriteNumber("AlarmLevel", v.AlarmLevel);
        writer.WriteNumber("FrontVehicleSpeed", v.FrontVehicleSpeed);
        writer.WriteNumber("FrontVehicleDistance", v.FrontVehicleDistance);
        writer.WriteNumber("Speed", v.Speed);
        writer.WriteNumber("Latitude", v.Latitude);
        writer.WriteNumber("Longitude", v.Longitude);
        writer.WriteString("AlarmTime", v.AlarmTime.ToString("yyyy-MM-dd HH:mm:ss"));
        writer.WriteNumber("AttachmentCount", v.AttachmentCount);
    }
}
