# Matrix RS3 Server — Revision 876 → 946 Upgrade Guide
### Java / Kotlin Edition
**Date:** 2026-03-22  
**Authority sources:** `FINDINGS_matri_exe.md`, `UPGRADE_946.md`, `RE_GUIDE_x64dbg_Ghidra.md`,  
`DOCUMENTATION.md`, static analysis of `matri.exe` (official Jagex NXT build, revision 946)

---

## Table of Contents

1. [Scope and Reading Order](#1-scope-and-reading-order)
2. [Settings.java — Revision + RSA Keypair](#2-settingsjava--revision--rsa-keypair)
3. [JS5 Server — Sub-revision Exchange](#3-js5-server--sub-revision-exchange)
4. [Login Handler — New Fields, 2048-bit RSA, 4-byte Response](#4-login-handler--new-fields-2048-bit-rsa-4-byte-response)
5. [WorldPacketsDecoder — Full Opcode Renumber (Client→Server)](#5-worldpacketsdecoder--full-opcode-renumber-clientserver)
6. [All Encoder Classes — Full Opcode Renumber (Server→Client)](#6-all-encoder-classes--full-opcode-renumber-serverclient)
7. [Packet Size Table for Login Validation](#7-packet-size-table-for-login-validation)
8. [Player Update — 24-bit Mask + Three New Sub-blocks](#8-player-update--24-bit-mask--three-new-sub-blocks)
9. [NPC Update — Overhead Text + Move Speed Sub-blocks](#9-npc-update--overhead-text--move-speed-sub-blocks)
10. [New Server→Client Packets](#10-new-serverclient-packets)
11. [Walk Packet — moveSpeed Field Replaces ctrlHeld](#11-walk-packet--movespeed-field-replaces-ctrlheld)
12. [New Client→Server Packets to Handle](#12-new-clientserver-packets-to-handle)
13. [PING / PING_REPLY — Mandatory in 946](#13-ping--ping_reply--mandatory-in-946)
14. [Cache — Index 22 + Huffman Archive Relocation](#14-cache--index-22--huffman-archive-relocation)
15. [ConfigLoader — New Definition Opcodes](#15-configloader--new-definition-opcodes)
16. [Build / Gradle Changes](#16-build--gradle-changes)
17. [Verification Checklist](#17-verification-checklist)
18. [Complete Opcode Reference 876 → 946](#18-complete-opcode-reference-876--946)

---

## 1. Scope and Reading Order

This guide covers every server-side change required to move the **Matrix RS3 Java/Kotlin server** from revision 876 to revision 946 so that it is fully wire-compatible with the C++ client (`matri.exe`, the official Jagex NXT binary, confirmed revision 946 via static analysis).

**Work in this order.** Each section is a prerequisite for the one that follows.

1. `Settings.java` (§2) — revision constant and RSA key, the foundation everything else reads
2. JS5 handshake (§3) — the client will not request a single cache file until this succeeds
3. Login handler (§4) — the client will not enter the game world until login succeeds
4. Opcode renumber (§5 and §6) — every packet silently misdispatches until these are correct
5. Player/NPC update (§8, §9) — game state will desync silently until these are correct
6. Everything else in order

---

## 2. Settings.java — Revision + RSA Keypair

**File:** `src/main/java/com/rs/Settings.java` (exact path varies by distribution)

### 2.1 Revision constant

```java
// Before
public static final int REVISION = 876;

// After
public static final int REVISION = 946;
```

Some distributions also store the revision as a field in `GameWorld.java` or `Constants.java`.
Search the project for `876` and update every occurrence.

### 2.2 RSA keypair — upgrade to 2048-bit

The revision 946 login protocol uses a **2048-bit RSA modulus** (256 bytes).
The 876 modulus is 1024-bit (128 bytes). The encrypted login block will be
the wrong size until the keypair is regenerated.

**Generate a new 2048-bit keypair** (run once on any machine with OpenSSL or Java):

```bash
# OpenSSL
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_private.pem
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
openssl rsa -in rsa_private.pem -text -noout 2>/dev/null \
    | grep -A 50 "modulus" | head -40
```

Or generate programmatically in Java:

```java
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;

KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
gen.initialize(2048);
KeyPair pair = gen.generateKeyPair();
RSAPrivateCrtKey priv = (RSAPrivateCrtKey) pair.getPrivate();

String modulus  = priv.getModulus().toString(16);            // 512 hex chars
String pubExp   = priv.getPublicExponent().toString(16);     // "10001"
String privExp  = priv.getPrivateExponent().toString(16);
System.out.println("MODULUS:  " + modulus);
System.out.println("PUB_EXP:  " + pubExp);
System.out.println("PRIV_EXP: " + privExp);
```

Then update `Settings.java`:

```java
// 2048-bit public modulus — 512 hex characters
public static final BigInteger PUBLIC_KEY_MODULUS =
    new BigInteger("PASTE_YOUR_512_HEX_CHAR_MODULUS_HERE", 16);

// Public exponent — always 65537 (0x10001) for all known Matrix distributions
public static final BigInteger PUBLIC_KEY_EXPONENT =
    new BigInteger("10001", 16);

// Private exponent (used on the server to decrypt the login block)
public static final BigInteger PRIVATE_KEY_MODULUS =
    new BigInteger("PASTE_YOUR_512_HEX_CHAR_MODULUS_HERE", 16);  // same as public
public static final BigInteger PRIVATE_KEY_EXPONENT =
    new BigInteger("PASTE_YOUR_PRIVATE_EXPONENT_HERE", 16);
```

**CRITICAL — copy the exact same `PUBLIC_KEY_MODULUS` string to `src/Config.hpp`
in the C++ client** (`rsaModulus` field). A mismatch causes a silent disconnect with
no error message — the server decrypts garbage and drops the session.

---

## 3. JS5 Server — Sub-revision Exchange

**File:** `src/main/java/com/rs/net/decoders/JS5Decoder.java`
(or whichever class handles `connection type 15` packets)

Revision 946 adds a **JS5 sub-revision exchange** after the `0x00` acceptance byte.
The server must:
1. Send `0x00` acceptance byte (unchanged)
2. Send its JS5 sub-revision as a **big-endian int32** (4 bytes)
3. Read the client's **8-byte acknowledgement** (`00 00 00 0F` + echoed sub-revision)

Without this exchange the client silently ignores all JS5 file responses.

### Wire sequence

```
Client → Server:  0F 00 00 03 B2            (connection type 15, revision 946)
Server → Client:  00                         (acceptance byte)
Server → Client:  XX XX XX XX               (sub-revision as big-endian int32)
Client → Server:  00 00 00 0F XX XX XX XX   (8-byte acknowledgement)
```

### Java implementation

```java
// In your JS5 connection handler, after sending the 0x00 acceptance byte:

private static final int JS5_SUB_REVISION = 1; // Use 0 or 1 for most distributions

public void sendHandshakeResponse(IoSession session, PacketBuffer out) {
    // 1. Acceptance byte (unchanged from 876)
    out.put((byte) 0x00);

    // 2. NEW in 946: JS5 sub-revision (big-endian int32)
    out.putInt(JS5_SUB_REVISION);

    session.write(out);
}

public void readHandshakeAck(IoSession session, PacketBuffer in) {
    // 3. NEW in 946: read the 8-byte client ack
    // First 4 bytes: fixed marker (0x0000000F)
    int marker = in.getInt();          // expect 0x0000000F
    int echoedRev = in.getInt();       // client echoes JS5_SUB_REVISION back

    if (marker != 0x0000000F) {
        session.close(true);
        return;
    }
    // echoedRev may differ from JS5_SUB_REVISION on some forks; log but don't reject
    Logger.log(this, "JS5 handshake ack — marker=0x" + Integer.toHexString(marker)
                    + " sub_rev=" + echoedRev);
    // Proceed to normal file-request loop
}
```

### Kotlin equivalent

```kotlin
companion object {
    const val JS5_SUB_REVISION = 1
}

fun sendHandshakeResponse(channel: Channel, out: ByteBuf) {
    out.writeByte(0x00)           // acceptance
    out.writeInt(JS5_SUB_REVISION) // sub-revision (new in 946)
    channel.writeAndFlush(out)
}

fun readHandshakeAck(buf: ByteBuf): Boolean {
    val marker    = buf.readInt()    // 0x0000000F
    val echoedRev = buf.readInt()
    if (marker != 0x0000000F) return false
    log.debug { "JS5 ack: marker=0x${marker.toString(16)}, sub_rev=$echoedRev" }
    return true
}
```

---

## 4. Login Handler — New Fields, 2048-bit RSA, 4-byte Response

**File:** `src/main/java/com/rs/net/decoders/LoginProtocol.java`
(or `WorldFullLoginHandler.java`, `WorldLoginDecoder.java` — varies by distribution)

Four changes are required. A wrong change here causes the server to decrypt garbage
from the RSA block and silently drop the connection.

### 4.1 Client-type field (byte offset 21–22 in the RSA plaintext)

The 946 client inserts a **2-byte client-type field** at byte offset 21 of the RSA
plaintext block (after the 4-byte UID at offset 17–20). The value is:
- `0x0001` — Java applet (legacy)
- `0x0002` — NXT/native C++ client

The server must read this field and advance the buffer cursor past it before reading
the username. Failure to do so shifts every subsequent read by 2 bytes, causing the
username and password to decode as garbage.

```java
// In the RSA plaintext parsing block, after decrypting:
// buffer layout in 946:
//   byte  0      magic         = 0x0A
//   bytes 1-8    clientKey     (int64)
//   bytes 9-16   serverKey     (int64)
//   bytes 17-20  uid           (int32)
//   bytes 21-22  clientType    (int16)  ← NEW in 946
//   bytes 23+    username      (null-terminated)
//   after user   password      (null-terminated)

int magic      = rsaBuf.get() & 0xFF;          // 0x0A
long clientKey = rsaBuf.getLong();
long serverKey = rsaBuf.getLong();
int  uid       = rsaBuf.getInt();
int  clientType = rsaBuf.getShort() & 0xFFFF;  // NEW — 0x0002 for C++ client
String username = rsaBuf.getString();
String password = rsaBuf.getString();
```

If you have a strict `clientType` check, accept both `0x0001` and `0x0002` during
the transition period so the Java client (if still in use) also connects.

### 4.2 RSA block size — 256 bytes (2048-bit)

Update the RSA decryption buffer allocation. The encrypted block is now **256 bytes**
instead of 128. The in-packet RSA length field (a `uint16` before the encrypted bytes)
tells you the actual size, so most Matrix distributions read it dynamically — verify
yours does:

```java
// Reading the RSA block — most distributions already do this correctly:
int rsaBlockLen = loginBuf.getUShort();   // reads the 2-byte length prefix
byte[] rsaBytes = new byte[rsaBlockLen];
loginBuf.get(rsaBytes);                   // rsaBlockLen will be 256 in 946

// Decrypt with private key:
BigInteger cipherBig = new BigInteger(1, rsaBytes);
BigInteger plainBig  = cipherBig.modPow(Settings.PRIVATE_KEY_EXPONENT,
                                         Settings.PRIVATE_KEY_MODULUS);

byte[] plainBytes = plainBig.toByteArray();
// BigInteger.toByteArray() may prepend a 0x00 sign byte; strip it:
if (plainBytes[0] == 0) {
    byte[] stripped = new byte[plainBytes.length - 1];
    System.arraycopy(plainBytes, 1, stripped, 0, stripped.length);
    plainBytes = stripped;
}
```

### 4.3 Cache CRC loop — 23 indices

The outer login packet now sends **23 CRC int32 values** (indices 0–22) instead of 21.
Update the skip loop that reads and ignores them:

```java
// Before (876): 21 CRC values
for (int i = 0; i < 21; i++) loginBuf.getInt();

// After (946): 23 CRC values (index 0 through index 22 inclusive)
for (int i = 0; i < 23; i++) loginBuf.getInt();
```

If your distribution verifies CRCs against the local cache, add `idx22.getCRC()` as
the 23rd entry in the server's CRC table.

### 4.4 Login response — 4 bytes instead of 3

Revision 946 sends **4 bytes** in the successful login response because the player
index is now a 16-bit value (world capacity increased):

```java
// Before (876): 3-byte response
// [status][privilege][playerIndex_as_byte]
out.put((byte) LoginResult.SUCCESS.getCode());
out.put((byte) player.getPrivilege());
out.put((byte) player.getIndex());

// After (946): 4-byte response
// [status][privilege][playerIndex_high][playerIndex_low]
out.put((byte) LoginResult.SUCCESS.getCode());
out.put((byte) player.getPrivilege());
out.put((byte) (player.getIndex() >> 8));   // high byte
out.put((byte) (player.getIndex() & 0xFF)); // low byte
```

Player indices fit in 15 bits (maximum 32767 players per world), so this is safe.

---

## 5. WorldPacketsDecoder — Full Opcode Renumber (Client→Server)

**File:** `src/main/java/com/rs/net/decoders/WorldPacketsDecoder.java`

Approximately **80% of client→server opcodes changed** between 876 and 946.
This is a bulk find-and-replace. Do it with the complete table from §18.

The pattern in most Matrix distributions is a large `switch (opcode)` block.
Replace every case constant using the table below. Constants that are equal in
both revisions are marked **unchanged** — do not touch those.

```java
// ─── Renamed constants (update these in your constant file or inline) ─────────

// Movement
static final int WALK            = 23;   // was 67
static final int WALK_MINIMAP    = 57;   // was 170
static final int CLICK_WORLD     = 88;   // NEW in 946

// Combat
static final int ATTACK_NPC      = 155;  // was 131
static final int TALK_NPC        = 40;   // was 155
static final int EXAMINE_NPC     = 125;  // was 8
static final int ATTACK_PLAYER   = 73;   // UNCHANGED
static final int MAGIC_ON_NPC    = 50;   // was 1
static final int MAGIC_ON_PLAYER = 224;  // was 24
static final int MAGIC_ON_OBJECT = 8;    // was 195
static final int MAGIC_ON_ITEM   = 25;   // UNCHANGED

// Objects
static final int CLICK_OBJECT1   = 64;   // was 75
static final int CLICK_OBJECT2   = 186;  // was 17
static final int CLICK_OBJECT3   = 211;  // was 44

// Ground items
static final int PICKUP_GROUND_ITEM = 77;  // was 54
static final int CLICK_GROUND_ITEM  = 104; // was 236

// Inventory
static final int DROP_ITEM       = 87;   // UNCHANGED

// Interface buttons
static final int IF_BUTTON1      = 70;   // was 142
static final int IF_BUTTON2      = 43;   // was 41
static final int IF_BUTTON3      = 85;   // was 116
static final int IF_BUTTON4      = 119;  // was 123
static final int IF_BUTTON5      = 152;  // was 161
static final int IF_BUTTON6      = 96;   // was 182
static final int IF_BUTTON7      = 34;   // was 200
static final int IF_BUTTON8      = 183;  // was 215
static final int IF_BUTTON_ON_OBJECT = 131; // was 57
static final int IF_BUTTON_ON_NPC    = 49;  // was 119
static final int IF_BUTTON_ON_PLAYER = 162; // was 72
static final int IF_BUTTON_ON_ITEM   = 203; // was 53

// Chat
static final int CHAT            = 21;   // was 4
static final int CHAT_PRIVATE    = 190;  // was 95
static final int CLIENT_CHEAT    = 4;    // was 21  (note: CHAT and CHEAT swapped!)
static final int CLOSE_MODAL     = 145;  // was 217
static final int ENTER_INTEGER   = 188;  // was 60
static final int ENTER_STRING    = 116;  // UNCHANGED

// Misc
static final int KEEP_ALIVE      = 0;    // UNCHANGED
static final int CAMERA_ROTATED  = 143;  // UNCHANGED
static final int CLAN_CHAT_KICK  = 178;  // was 100

// NEW in 946
static final int PING_REPLY      = 118;  // NEW — client must respond to PING
static final int SET_DISPLAY_MODE = 197; // NEW — window/fullscreen toggle
```

**Important:** `CHAT` (opcode 4 in 876) and `CLIENT_CHEAT` (opcode 21 in 876) swap
opcodes in 946. `CHAT` becomes 21, `CLIENT_CHEAT` becomes 4. If you handle chat and
cheat commands in the same switch block, double-check you have not created duplicate
case labels.

---

## 6. All Encoder Classes — Full Opcode Renumber (Server→Client)

Each encoder class that writes a packet to the client must have its `PACKET_OPCODE`
constant (or inline literal) updated. Use the table in §18 as the reference.
The most commonly edited encoders are listed below with the change.

```java
// ─── High-traffic encoders — update these first ───────────────────────────────

// PlayerUpdateEncoder (player sync)
int PLAYER_UPDATE_OPCODE  = 81;  // was 89

// NpcUpdateEncoder (NPC sync)
int NPC_UPDATE_OPCODE     = 38;  // was 30

// MapRegionEncoder
int MAP_REGION_OPCODE     = 49;  // was 166
int DYNAMIC_SCENE_OPCODE  = 119; // was 241

// InterfaceEncoder
int IF_OPEN_TOP_OPCODE    = 160; // was 109
int IF_OPEN_SUB_OPCODE    = 22;  // was 0
int IF_CLOSE_SUB_OPCODE   = 183; // was 68
int IF_SET_TEXT_OPCODE    = 6;   // was 142
int IF_SET_HIDDEN_OPCODE  = 171; // was 165
int IF_SET_EVENTS_OPCODE  = 98;  // was 85
int IF_SET_SCROLL_OPCODE  = 75;  // was 79
int IF_SET_ANGLE_OPCODE   = 3;   // UNCHANGED — but payload WIDENED (see §6.1)
int RUN_CLIENTSCRIPT_OPCODE = 67; // was 51

// Player state encoders
int UPDATE_SKILLS_OPCODE  = 136; // was 134
int UPDATE_RUNERGY_OPCODE = 87;  // was 110
int UPDATE_WEIGHT_OPCODE  = 197; // was 167
int UPDATE_VARP_OPCODE    = 34;  // was 63
int UPDATE_VARP_LARGE_OPCODE = 207; // was 84
int UPDATE_VARBIT_OPCODE  = 62;  // was 27

// Inventory
int UPDATE_INV_FULL_OPCODE    = 44;  // was 97
int UPDATE_INV_PARTIAL_OPCODE = 27;  // was 213

// Chat
int MESSAGE_GAME_OPCODE    = 99;  // was 58
int MESSAGE_PUBLIC_OPCODE  = 78;  // was 219
int MESSAGE_PRIVATE_OPCODE = 166; // was 45

// Sound
int MIDI_SONG_OPCODE    = 212; // was 54
int SOUND_AREA_OPCODE   = 25;  // was 208
int SOUND_SYNTH_OPCODE  = 141; // was 53

// Camera
int CAM_MOVE_TO_OPCODE  = 238; // was 25 — also PAYLOAD WIDENED (see §6.2)

// Misc
int LOGOUT_OPCODE       = 93;  // was 5
int PING_OPCODE         = 118; // was 228
```

### 6.1 IF_SET_ANGLE payload — 2 new bytes (zoom level)

The opcode is unchanged (still 3), but the payload **grows from 8 to 10 bytes**.
Add the zoom level at the end:

```java
// Before (876): 8 bytes
void sendIfSetAngle(Player player, int ifId, int compId, int xAngle, int yAngle) {
    PacketBuilder pb = new PacketBuilder(3);
    pb.writeInt((ifId << 16) | compId);
    pb.writeShort(xAngle);
    pb.writeShort(yAngle);
    player.getSession().write(pb.toPacket());
}

// After (946): 10 bytes — zoom added at the end
void sendIfSetAngle(Player player, int ifId, int compId,
                    int xAngle, int yAngle, int zoom) {
    PacketBuilder pb = new PacketBuilder(3);
    pb.writeInt((ifId << 16) | compId);
    pb.writeShort(xAngle);
    pb.writeShort(yAngle);
    pb.writeShort(zoom);  // NEW — default 2000
    player.getSession().write(pb.toPacket());
}
```

Update all call sites; pass `2000` as the default zoom where not specified.

### 6.2 CAM_MOVE_TO payload — 2 new bytes (easing + duration)

The opcode changes from 25 to 238, and the payload **grows from 8 to 10 bytes**:

```java
// Before (876): 8 bytes, opcode 25
// After (946): 10 bytes, opcode 238
void sendCamMoveTo(Player player, int x, int y, int z,
                   int speed, int accel, int easing, int duration) {
    PacketBuilder pb = new PacketBuilder(238);
    pb.writeShort(x);
    pb.writeShort(y);
    pb.writeShort(z);
    pb.writeByte(speed);
    pb.writeByte(accel);
    pb.writeByte(easing);    // NEW — 0=linear, 1=ease-in, 2=ease-out
    pb.writeShort(duration); // NEW — movement duration in ticks
    player.getSession().write(pb.toPacket());
}
```

---

## 7. Packet Size Table for Login Validation

Some Matrix distributions verify that the client-sent inner login block is an
expected size before attempting RSA decryption. Update the size constant:

```java
// Before (876): RSA block = 128 bytes (1024-bit modulus)
// Plus clientType(2) + sub-rev(4) + memory(1) + CRC loop(21×4=84) + ushort(2)
// = 128 + 2 + 4 + 1 + 84 + 2 = 221 bytes inner block

// After (946): RSA block = 256 bytes (2048-bit modulus)
// Plus clientType(2) + sub-rev(4) + memory(1) + CRC loop(23×4=92) + ushort(2)
// = 256 + 2 + 4 + 1 + 92 + 2 = 357 bytes inner block
// (actual size varies by username/password length — just remove the hard check)

// Recommended: remove any hard-coded inner-block size check entirely.
// The RSA length field (uint16 before the encrypted bytes) is authoritative.
```

---

## 8. Player Update — 24-bit Mask + Three New Sub-blocks

**File:** `src/main/java/com/rs/game/player/content/PlayerUpdate.java`
(or `PlayerUpdateEncoder.java` depending on distribution)

### 8.1 Mask encoding — expand from 16 to 24 bits

```java
// Before (876): 16-bit mask, 0x80 signals second byte
private static void writeMask(OutputStream out, int mask) throws IOException {
    if (mask >= 0x100) {
        mask |= 0x80;
        out.writeByte(mask & 0xFF);
        out.writeByte(mask >> 8);
    } else {
        out.writeByte(mask);
    }
}

// After (946): 24-bit mask, 0x8000 signals third byte
private static void writeMask(OutputStream out, int mask) throws IOException {
    if (mask >= 0x10000) {
        // 3-byte path: set 0x80 on byte 0, set 0x8000 on bytes 0-1
        mask |= 0x80;
        mask |= 0x8000;
        out.writeByte(mask & 0xFF);          // low byte
        out.writeByte((mask >> 8) & 0xFF);   // mid byte (has 0x80 set = third follows)
        out.writeByte((mask >> 16) & 0xFF);  // high byte
    } else if (mask >= 0x100) {
        // 2-byte path (unchanged)
        mask |= 0x80;
        out.writeByte(mask & 0xFF);
        out.writeByte(mask >> 8);
    } else {
        out.writeByte(mask);
    }
}
```

### 8.2 Three new mask bits

| Bit | Hex | Sub-block | Notes |
|-----|-----|-----------|-------|
| bit 8 | `0x100` | `HITSPLAT_V2` | Extended hit, 2-byte type field |
| bit 9 | `0x200` | `MOVE_SPEED` | 1 byte: 0=walk 1=run 2=sprint |
| bit 10 | `0x400` | `OVERHEAD_TEXT` | null-term string + 2-byte duration |

### 8.3 Sub-block writers

Add these alongside the existing sub-block methods:

```java
// HITSPLAT_V2 (mask bit 0x100)
private static void writeHitsplatV2(OutputStream out, Player p) throws IOException {
    List<Hit> hits = p.getPendingHitsV2();
    out.writeByte(hits.size());
    for (Hit h : hits) {
        out.writeShort(h.getDamage());
        out.writeShort(h.getType());   // 2-byte type, indexes hitsplatDefs table
    }
}

// MOVE_SPEED (mask bit 0x200)
private static void writeMoveSpeed(OutputStream out, Player p) throws IOException {
    out.writeByte(p.getMoveSpeed());   // 0=walk, 1=run, 2=sprint
}

// OVERHEAD_TEXT (mask bit 0x400)
private static void writeOverheadText(OutputStream out, Player p) throws IOException {
    out.writeString(p.getOverheadText());
    out.writeShort(p.getOverheadDuration()); // ticks
}
```

### 8.4 Ordering in the update loop

Sub-blocks **must be written in ascending mask-bit order**. The 946 order is:

```
0x001 GRAPHIC
0x002 ANIMATION
0x004 CHAT
0x008 FACE_ENTITY
0x010 APPEARANCE
0x020 FACE_COORD
0x040 HIT (original)
0x080 FORCE_MOVE
0x100 HITSPLAT_V2  ← new
0x200 MOVE_SPEED   ← new
0x400 OVERHEAD_TEXT ← new
```

---

## 9. NPC Update — Overhead Text + Move Speed Sub-blocks

**File:** `src/main/java/com/rs/game/npc/NPCUpdate.java`

Add two new mask bits to the NPC update encoder:

| Bit | Hex | Sub-block |
|-----|-----|-----------|
| bit 6 | `0x40` | `OVERHEAD_TEXT` |
| bit 7 | `0x80` | `MOVE_SPEED` |

```java
// NPC update sub-blocks (add after existing blocks)

// OVERHEAD_TEXT (mask bit 0x40)
if ((mask & 0x40) != 0) {
    out.writeString(npc.getOverheadText());
    out.writeShort(npc.getOverheadDuration());
}

// MOVE_SPEED (mask bit 0x80)
if ((mask & 0x80) != 0) {
    out.writeByte(npc.getMoveSpeed());
}
```

Also update `writeMask` for NPCs to support 3-byte if needed (same logic as §8.1).

---

## 10. New Server→Client Packets

These packets are **new in 946** and have no 876 equivalent. Add a method for each.

### 10.1 UPDATE_HITSPLAT_TYPES (opcode 204, variable-short)

Sends the client the hitsplat icon definition table. Call once after login.

```java
void sendHitsplatTypeDefs(Player player, List<HitsplatDef> defs) {
    PacketBuilder pb = new PacketBuilder(204, PacketType.SHORT);
    for (HitsplatDef d : defs) {
        pb.writeShort(d.getTypeId());
        pb.writeShort(d.getSpriteId());
        pb.writeMedium(d.getColour());   // 3 bytes
    }
    pb.writeShort(0xFFFF);  // end-of-table sentinel
    player.getSession().write(pb.toPacket());
}
```

### 10.2 OVERHEAD_TEXT (opcode 137, variable-byte)

Dedicated overhead text packet for players/NPCs outside of the update protocol.
Useful for NPC dialogue bubbles not tied to the update cycle.

```java
void sendOverheadText(Player player, int entityType, int index,
                      String text, int colour, int duration) {
    PacketBuilder pb = new PacketBuilder(137, PacketType.BYTE);
    pb.writeByte(entityType);  // 0=player, 1=NPC
    pb.writeShort(index);
    pb.writeString(text);
    pb.writeByte(colour);
    pb.writeShort(duration);   // ticks
    player.getSession().write(pb.toPacket());
}
```

### 10.3 CLEAR_ENTITIES (opcode 59, size 0)

Sent on teleport to clear the local entity list. The client wipes all
player/NPC visuals immediately. **Always send before MAP_REGION on teleport.**

```java
void sendClearEntities(Player player) {
    PacketBuilder pb = new PacketBuilder(59);
    player.getSession().write(pb.toPacket());
}
```

### 10.4 SET_MOVE_SPEED (opcode 241, size 1)

Explicitly sets the local player's movement mode on the client.

```java
void sendMoveSpeed(Player player, int speed) {
    // 0 = walk, 1 = run, 2 = sprint (sprint is new in 946)
    PacketBuilder pb = new PacketBuilder(241);
    pb.writeByte(speed);
    player.getSession().write(pb.toPacket());
}
```

### 10.5 INVENTORY_FULL_V2 (opcode 185, variable-short)

Extended inventory packet supporting more than 28 slots. Drop-in alongside the
existing `UPDATE_INV_FULL` (opcode 44) for containers with more slots.

```java
void sendInvFullV2(Player player, int containerId, List<Item> items) {
    PacketBuilder pb = new PacketBuilder(185, PacketType.SHORT);
    pb.writeShort(containerId);
    pb.writeShort(items.size());
    for (Item item : items) {
        pb.writeInt(item == null ? -1 : item.getId());
        pb.writeInt(item == null ? 0  : item.getAmount());
    }
    player.getSession().write(pb.toPacket());
}
```

### 10.6 AREA_SOUND (opcode 108, size 10)

Positional 3D audio tied to a world coordinate. The client attenuates the
sound based on player distance to the source tile.

```java
void sendAreaSound(Player player, int soundId, int x, int y,
                   int radius, int volume, int delay) {
    PacketBuilder pb = new PacketBuilder(108);
    pb.writeShort(soundId);
    pb.writeShort(x);
    pb.writeShort(y);
    pb.writeShort(radius);
    pb.writeByte(volume);
    pb.writeByte(delay);   // delay in ticks before playback
    player.getSession().write(pb.toPacket());
}
```

---

## 11. Walk Packet — moveSpeed Field Replaces ctrlHeld

**File:** `WorldPacketsDecoder.java`, handler for `WALK` (opcode 23) and
`WALK_MINIMAP` (opcode 57)

In 946 the walk packet carries a **1-byte move-speed flag** at the end instead of
the old "ctrlHeld" boolean. The byte layout is:

```
876 walk: [ShortA z][Byte128 ctrlHeld][ShortA x]
946 walk: [ShortA z][Byte128 moveSpeed][ShortA x]
          where moveSpeed: 0=walk, 1=run, 2=sprint
```

```java
// Handler for WALK (opcode 23 in 946)
case WALK: {
    int z         = in.readShortA();      // target Z (or Y in some coord systems)
    int moveSpeed = (in.readByte128() & 0xFF); // 0=walk 1=run 2=sprint
    int x         = in.readShortA();      // target X
    player.getWalkQueue().addStep(x, z);
    player.setMoveSpeed(moveSpeed);
    break;
}
```

---

## 12. New Client→Server Packets to Handle

### 12.1 CLICK_WORLD (opcode 88, size 5)

"Walk here" from right-click menu. Different from the standard walk.

```java
case CLICK_WORLD: {
    int x     = in.readShortA();
    int z     = in.readShortA();
    int plane = in.readUByte();
    player.getWalkQueue().addStep(x, z);
    break;
}
```

### 12.2 SET_DISPLAY_MODE (opcode 197, size 1)

Client notifies server of a window/fullscreen toggle. Usually informational only.

```java
case SET_DISPLAY_MODE: {
    int mode = in.readUByte();  // 0=fixed, 1=resizable, 2=fullscreen
    player.setDisplayMode(mode);
    break;
}
```

---

## 13. PING / PING_REPLY — Mandatory in 946

In revision 946 the server **must send a periodic PING** (opcode 118, size 0) and
the client **must reply with PING_REPLY** (opcode 118 client→server, size 0) within
10 seconds or it disconnects the session.

### Server-side: send PING every ~15 seconds

```java
// In your world game-loop, tick handler, or PlayerHandler:
private static final int PING_INTERVAL_TICKS = 25; // 25 × 600ms = 15 seconds

// Each player session tick:
if (player.getTick() % PING_INTERVAL_TICKS == 0) {
    sendPing(player);
    player.setPingSent(System.currentTimeMillis());
}

void sendPing(Player player) {
    PacketBuilder pb = new PacketBuilder(118);  // PING opcode
    player.getSession().write(pb.toPacket());
}
```

### Handle PING_REPLY from client

```java
case PING_REPLY: {
    // Client replies to our ping — record the round trip time
    long rtt = System.currentTimeMillis() - player.getPingSent();
    player.setLatency((int) rtt);
    break;
}
```

**If you do NOT send periodic pings** the client will not disconnect, but many
946 interface scripts check the latency value and display a warning indicator.
The ping handler is non-blocking to implement and should not be skipped.

---

## 14. Cache — Index 22 + Huffman Archive Relocation

### 14.1 Index 22 support

Revision 946 adds **cache index 22** for new content categories. Your JS5 server
must serve this index, and your `FileStore` must be able to open `idx22`.

```java
// In your FileStore or CacheManager:
// Before: supported indices 0–21 and 255
// After:  supported indices 0–22 and 255

// If you have a hard-coded maximum index, update it:
private static final int MAX_INDEX = 22;  // was 21
```

Ensure `main_file_cache.idx22` is present in your cache directory. Copy it from
your 946 cache distribution.

### 14.2 Huffman codec archive relocation

The Huffman chat-compression frequency table moved from archive 765 to archive 959
within cache index 10. This is a **one-line change** that silently breaks all chat
decoding if missed.

```java
// In your Huffman init code:

// Before (876)
byte[] huffData = Cache.getArchive(10, 765).decompressData();
HuffmanCodec.init(huffData);

// After (946)
byte[] huffData = Cache.getArchive(10, 959).decompressData();
HuffmanCodec.init(huffData);
```

---

## 15. ConfigLoader — New Definition Opcodes

**File:** `src/main/java/com/rs/cache/loaders/` (ItemDefinitions, NPCDefinitions, etc.)

Unknown opcodes are skipped in most Matrix distributions, so these do not break
anything — you simply lose those data fields. Add them when you need them.

```java
// ItemDefinitions.java — new in 946:
case 150: examine = readString(buffer); break;
case 151: readUnsignedShort(buffer); break;   // placeholder item ID
case 152: membersOnly = true; break;
case 163: readInt(buffer); break;             // destroy option script ID
case 168: readUnsignedShort(buffer); break;   // bonuses table index

// NPCDefinitions.java — new in 946:
case 74:  combatLevel = readUnsignedShort(buffer); break;
case 89:  readUnsignedShort(buffer); break;   // sprint animation ID
case 90:  readUnsignedShort(buffer); break;   // sprint back animation
case 113: hitpoints   = readUnsignedShort(buffer); break;
case 115: attackSpeed = readUnsignedByte(buffer);  break;

// ObjectDefinitions.java — new in 946:
case 85: readUnsignedByte(buffer); break;     // supports items
case 86: readUnsignedByte(buffer); break;     // block range flag
case 249: {                                   // arbitrary params table
    int n = readUnsignedByte(buffer);
    for (int i = 0; i < n; i++) {
        boolean isString = readUnsignedByte(buffer) == 1;
        readInt(buffer);                      // key
        if (isString) readString(buffer);
        else readInt(buffer);                 // value
    }
    break;
}
```

---

## 16. Build / Gradle Changes

If your project uses a `build.gradle` or `pom.xml` with a version field,
bump the server version string:

```groovy
// build.gradle
version = '946.1'
```

If you have any Gradle or Maven dependency that vendors a specific RS3 cache
revision, update it to the 946 version.

No new Java/Kotlin language-level dependencies are introduced by this upgrade.
The only runtime requirement change is that **RSA key generation for 2048-bit**
requires Java 8+ which all current distributions already use.

---

## 17. Verification Checklist

Work top-to-bottom. Each failure points to the specific section to re-check.

- [ ] **`Settings.REVISION` = 946** — everything else reads this constant
- [ ] **RSA modulus is 512 hex characters** (2048-bit) — `modulus.length() == 512`
- [ ] **Same modulus in `Settings.java` AND `src/Config.hpp`** — copy exactly
- [ ] **JS5 sub-revision exchange implemented** (§3) — client hangs at 0% cache if missing
- [ ] **Client connects and JS5 begins downloading** — watch JS5 decoder log
- [ ] **Login block parses without exception** — `clientType` field consumed (§4.1)
- [ ] **Login response is 4 bytes** (§4.4) — client logs "Login successful" not "bad response"
- [ ] **CRC loop reads 23 ints** (§4.3) — login buffer corruption if 21 or 22
- [ ] **All client→server opcodes updated** (§5) — test: walk, click NPC, click button, chat
- [ ] **All server→client opcodes updated** (§6) — test: interface loads, skills show, chat visible
- [ ] **IF_SET_ANGLE sends 10 bytes** (§6.1) — zoom level appended
- [ ] **CAM_MOVE_TO uses opcode 238 and sends 10 bytes** (§6.2)
- [ ] **Player update 24-bit mask** (§8) — no crash on login; player appears
- [ ] **NPC update 2 new sub-blocks** (§9) — NPCs visible with correct animations
- [ ] **CLEAR_ENTITIES sent before MAP_REGION on teleport** (§10.3) — no ghost entities
- [ ] **Walk packet reads moveSpeed field** (§11) — not ctrlHeld
- [ ] **PING sent every ~15s; PING_REPLY handled** (§13) — client does not disconnect
- [ ] **Huffman archive = cache index 10 archive 959** (§14.2) — chat is readable
- [ ] **Cache idx22 present and served by JS5** (§14.1) — no "index 22 not found" errors
- [ ] **CHAT opcode = 21, CLIENT_CHEAT opcode = 4** (§5) — swapped in 946
- [ ] **Zero unknown-opcode log warnings after 30s in-game**

---

## 18. Complete Opcode Reference 876 → 946

### Server → Client

| Packet | 876 opcode | 946 opcode | Size | Notes |
|--------|------------|------------|------|-------|
| MAP_REGION | 166 | **49** | -2 | |
| DYNAMIC_SCENE | 241 | **119** | -2 | |
| PLAYER_UPDATE | 89 | **81** | -2 | mask now 24-bit |
| NPC_UPDATE | 30 | **38** | -2 | 2 new sub-blocks |
| IF_OPEN_TOP | 109 | **160** | 2 | |
| IF_OPEN_SUB | 0 | **22** | 8 | |
| IF_CLOSE_SUB | 68 | **183** | 4 | |
| IF_SET_TEXT | 142 | **6** | -2 | |
| IF_SET_HIDDEN | 165 | **171** | 5 | |
| IF_SET_EVENTS | 85 | **98** | 10 | |
| IF_SET_SCROLL | 79 | **75** | 6 | |
| IF_SET_ANGLE | 3 | 3 | **10** | opcode unchanged, size grew from 8 |
| IF_SET_ANIM | 200 | 200 | 8 | unchanged |
| IF_SET_SPRITE | 233 | 233 | 6 | unchanged |
| IF_SET_COLOR | 122 | 122 | 6 | unchanged |
| IF_SET_MODEL | 246 | 246 | 10 | unchanged |
| IF_MOVE_SUB | 253 | 253 | 8 | unchanged |
| RUN_CLIENTSCRIPT | 51 | **67** | -2 | |
| UPDATE_SKILLS | 134 | **136** | 6 | |
| UPDATE_RUNENGERY | 110 | **87** | 1 | |
| UPDATE_WEIGHT | 167 | **197** | 2 | |
| UPDATE_VARP | 63 | **34** | 6 | |
| UPDATE_VARP_LARGE | 84 | **207** | 8 | |
| UPDATE_VARBIT | 27 | **62** | 6 | |
| RESET_VARP | 148 | 148 | 0 | unchanged |
| RESET_CLIENT_VARCACHE | 24 | 24 | 0 | unchanged |
| UPDATE_INV_FULL | 97 | **44** | -2 | |
| UPDATE_INV_PARTIAL | 213 | **27** | -2 | |
| INVENTORY_FULL_V2 | — | **185** | -2 | NEW |
| MESSAGE_GAME | 58 | **99** | -2 | |
| MESSAGE_PUBLIC | 219 | **78** | -1 | |
| MESSAGE_PRIVATE | 45 | **166** | -1 | |
| CHAT_FILTER_SETTINGS | 213 | 213 | 3 | unchanged |
| MIDI_SONG | 54 | **212** | 6 | |
| SOUND_AREA | 208 | **25** | 7 | |
| SOUND_SYNTH | 53 | **141** | 5 | |
| AREA_SOUND | — | **108** | 10 | NEW — positional 3D audio |
| LOGOUT | 5 | **93** | 0 | |
| PING | 228 | **118** | 0 | client must reply in 946 |
| RESET_ANIMS | 1 | 1 | 0 | unchanged |
| UPDATE_ZONE | 46 | 46 | -2 | unchanged |
| CAM_MOVE_TO | 25 | **238** | **10** | opcode + size both changed |
| CAMERA_SHAKE | 10 | 10 | 6 | unchanged |
| RESET_CAMERA | 161 | 161 | 0 | unchanged |
| MINI_MAP_STATE | 160 | 160 | 1 | unchanged |
| HINT_ARROW | 170 | 170 | -1 | unchanged |
| SET_PLAYER_OPTION | 104 | 104 | -1 | unchanged |
| UPDATE_REBOOT_TIMER | 222 | 222 | 2 | unchanged |
| UNLOCK_MUSIC | 74 | 74 | -2 | unchanged |
| FRIEND_LIST | 101 | 101 | -2 | unchanged |
| IGNORE_LIST | 226 | 226 | -2 | unchanged |
| UPDATE_PRAYER_BOOK | 177 | 177 | 1 | unchanged |
| UPDATE_HITSPLAT_TYPES | — | **204** | -2 | NEW |
| OVERHEAD_TEXT | — | **137** | -1 | NEW |
| CLEAR_ENTITIES | — | **59** | 0 | NEW |
| SET_MOVE_SPEED | — | **241** | 1 | NEW |

### Client → Server

| Packet | 876 opcode | 946 opcode | Size | Notes |
|--------|------------|------------|------|-------|
| KEEP_ALIVE | 0 | 0 | 0 | unchanged |
| WALK | 67 | **23** | -1 | moveSpeed byte replaces ctrlHeld |
| WALK_MINIMAP | 170 | **57** | -1 | |
| CLICK_WORLD | — | **88** | 5 | NEW |
| ATTACK_NPC | 131 | **155** | 2 | |
| TALK_NPC | 155 | **40** | 2 | |
| EXAMINE_NPC | 8 | **125** | 2 | |
| ATTACK_PLAYER | 73 | 73 | 2 | unchanged |
| IF_BUTTON1 | 142 | **70** | -1 | |
| IF_BUTTON2 | 41 | **43** | -1 | |
| IF_BUTTON3 | 116 | **85** | -1 | |
| IF_BUTTON4 | 123 | **119** | -1 | |
| IF_BUTTON5 | 161 | **152** | -1 | |
| IF_BUTTON6 | 182 | **96** | -1 | |
| IF_BUTTON7 | 200 | **34** | -1 | |
| IF_BUTTON8 | 215 | **183** | -1 | |
| IF_BUTTON_ON_OBJECT | 57 | **131** | -1 | |
| IF_BUTTON_ON_NPC | 119 | **49** | -1 | |
| IF_BUTTON_ON_PLAYER | 72 | **162** | -1 | |
| IF_BUTTON_ON_ITEM | 53 | **203** | -1 | |
| CLICK_OBJECT1 | 75 | **64** | -1 | |
| CLICK_OBJECT2 | 17 | **186** | -1 | |
| CLICK_OBJECT3 | 44 | **211** | -1 | |
| DROP_ITEM | 87 | 87 | 8 | unchanged |
| PICKUP_GROUND_ITEM | 54 | **77** | 6 | |
| CHAT | 4 | **21** | -1 | swapped with CLIENT_CHEAT! |
| CHAT_PRIVATE | 95 | **190** | -1 | |
| CLIENT_CHEAT | 21 | **4** | -1 | swapped with CHAT! |
| CLOSE_MODAL | 217 | **145** | 0 | |
| ENTER_INTEGER | 60 | **188** | 4 | |
| ENTER_STRING | 116 | 116 | -1 | unchanged |
| CAMERA_ROTATED | 143 | 143 | 4 | unchanged |
| MAGIC_ON_NPC | 1 | **50** | -1 | |
| MAGIC_ON_PLAYER | 24 | **224** | -1 | |
| MAGIC_ON_OBJECT | 195 | **8** | -1 | |
| MAGIC_ON_ITEM | 25 | 25 | -1 | unchanged |
| PING_REPLY | — | **118** | 0 | NEW — required in 946 |
| SET_DISPLAY_MODE | — | **197** | 1 | NEW |

---

*Cross-reference all opcodes against your specific Matrix 946 fork's
`WorldPacketsDecoder.java` and encoder classes before committing —
Matrix distributions occasionally diverge from the canonical NXT opcode table
documented here. The static analysis of `matri.exe` (the authoritative
Jagex NXT binary for revision 946) is the primary source for these values.*
