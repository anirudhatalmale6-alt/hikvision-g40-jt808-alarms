# Hikvision G40 — JT808 ADAS / DSM alarm integration

Two things live here:

| Folder | What it is |
|---|---|
| `HikvisionActiveSafety/` | The fix for the JT808 C# library: ADAS (`0x64`) and DSM (`0x65`) item types, the registration they need, and a diagnostic that shows what a location report *actually* contained. Includes a before/after proof you can run. |
| `jt808-dump/` | A standalone raw-packet inspector. No library, no assumptions — feed it bytes off the socket and it lists every additional-information item present, decoding the ones it knows and hex-dumping the ones it doesn't. |

---

## The finding

`CustomLocationAttachData.TryGetValue(0x65, out var raw65)` cannot succeed on a stock config,
**even when the packet plainly contains a valid 0x65 DSM alarm.**

That is reproduced, not theorised. `HikvisionActiveSafety` parses a hand-built packet containing a
correct 47-byte DSM item, twice, with the only difference being one registration call:

```
BEFORE - stock JT808 config, nothing registered
  BasicLocationAttachData   : 0x1, 0x30
  CustomLocationAttachData  : (empty)          <-- TryGetValue(0x65) returns false
  UnknownLocationAttachData : items the library could not map -
      0x65  49 bytes  65 2F 00 00 00 2A 01 02 01 00 ...
      ^ anything listed here is present in the packet and being thrown away.

AFTER - same bytes, config.UseActiveSafetyAlarms() called
  BasicLocationAttachData   : 0x1, 0x30
  CustomLocationAttachData  : 0x65             <-- TryGetValue(0x65) returns true
  UnknownLocationAttachData : (empty)

  decoded DSM alarm:
    alarm type       : 0x02 Phone use while driving
    flag state       : 1 (alarm start)
    alarm time       : 2026-09-09 12:30:45
    attachment count : 2
```

The library does not throw and does not log when it meets an item ID it has no type for. It files
the raw bytes under `UnknownLocationAttachData` and carries on. From the outside that is
indistinguishable from "the camera never sent an alarm" — which is exactly the wrong conclusion.

**What this does and does not prove.** It proves the handler could never have fired, whatever the
cameras send. It does *not* prove the G40s are sending `0x65` — that needs real bytes from real
devices. The point of `LocationDiagnostics` below is that your own server will now tell you.

### Two gotchas that cost time

1. **`AttachInfoId` must have a default value on the class.** The custom factory constructs a
   throwaway instance and uses that property as the map key. Left at `0`, every registered type
   collides and `SetMap` throws *"An element with the same key already exists"* on the second one.
2. **The formatter is handed the reader positioned at the item's ID byte, not after it.** So
   `Deserialize` reads `AttachInfoId` and `AttachInfoLength` itself before the payload. The
   49-byte blob in `UnknownLocationAttachData` above (2 header + 47 payload) is the evidence.

---

## Using it

### 1. Find out what your cameras actually send

Drop this in wherever you handle a location report:

```csharp
var loc = (JT808_0x0200)package.Bodies;
Console.WriteLine(LocationDiagnostics.Describe(loc));
```

It prints every bucket the library files items into, including the raw bytes of anything
unmapped. Run it against live traffic with the alarms enabled and drive the triggers.

- **Unmapped IDs appear** → those bytes are your alarms. If they aren't `0x64`/`0x65`, send the
  hex over and the layout gets mapped.
- **No additional items at all** → the cameras are sending position only. No amount of server-side
  work recovers that; it is a device configuration problem, and the next step is the terminal
  parameter set, not the parser.

### 2. Turn the alarms on

```csharp
var config = new ActiveSafetyConfig();   // or your existing IJT808Config
config.UseActiveSafetyAlarms();          // registers 0x64 and 0x65
var serializer = new JT808Serializer(config);
```

Your existing handler compiles unchanged — the property names (`FlagState`,
`AlarmOrEventType`, `AlarmLevel`, `Fatigue`, `AlarmTime`, `Latitude`) are matched deliberately.

### 3. Run the proof

```bash
cd HikvisionActiveSafety && dotnet run     # exits non-zero if any check fails
```

### 4. Inspect raw bytes off the wire

```bash
cd jt808-dump
dotnet run -- capture.txt        # hex text, any format: "7E 02 00", "7e0200", Wireshark, C# dumps
dotnet run -- capture.bin --bin  # raw bytes
dotnet run -- --selftest         # 32 checks, incl. negative controls
dotnet run -- --gensample out.txt
```

It never skips an item it does not recognise — that is the entire point. Unknown payloads get a
hex dump plus structure hints (embedded BCD timestamps, plausible lat/lng pairs, printable text).

---

## On the decoding tables

The `0x64` / `0x65` layouts and the alarm-type names come from the public active-safety
supplement that ADAS dashcams follow. They are **not** confirmed against a Hikvision document.

Both tools are built to fail loudly rather than quietly:

- `jt808-dump` refuses to decode an item whose length rules the layout out, and says why, instead
  of reading the wrong offsets and printing credible nonsense.
- An alarm-type code that is not in the table is reported as `UNMAPPED code 0x..`, never guessed.

If a G40 turns out to differ, it will show up as a length mismatch or an unmapped code — not as
plausible-looking wrong data.

## Tests

`jt808-dump --selftest` — 32 checks. It includes negative controls (a position-only packet must
report *no* alarm; a wrong-length item must be *refused*), and the suite has been mutation-tested:
breaking the unknown-ID handling fails 15 checks, removing the length guard fails 2, and changing
the headway scale fails 1.

`HikvisionActiveSafety` — 17 checks covering the before/after behaviour, every decoded field, and
regressions (registration must not cost the ordinary `0x01`/`0x30` items).
