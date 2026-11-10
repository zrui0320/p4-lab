# Week 5 assignment — Put a limit on the tunnel

Student ID (last 4 digits only): **3540** (so my hosts are 10.40.0.1–3)

## 1. Analysis: the loop

**How I made the loop.** With a fresh network running the finished lab program
(`tunnel.p4`, identical to `tunnel_v1.p4`), I dumped s2's tunnel table: exit 3 is entry
handle `0x2`, forwarding to port 3 (h3). I re-pointed it at port 1, i.e. back to s1:

```
sh ./p4cli s2 "table_modify MyIngress.myTunnel_exact MyIngress.myTunnel_forward 2 1"
```

s1 still sends `dst_id` 3 out of port 2 (to s2), so one packet sent with
`send.py 10.40.0.3 "loop" --tunnel 3` bounces s1 → s2 → s1 → … for ever.

**What the logs showed** (`evidence/loop-before.txt`):

| | s1 packets processed | s2 packets processed |
|---|---|---|
| right after sending one packet | 892 | 890 |
| 5 s later | 1444 | 1443 |

One packet became ~550 more "Processing packet received" events per switch in 5 seconds
(~110 passes per second per switch, limited only by BMv2's debug logging). The counts are
even a lower bound: BMv2 rotated s2's log during the run (`logs/s2.1.txt` appeared), and
`grep -c` only counts the current file. The two switches stay within one or two packets of each
other because they hand the same packet back and forth. Nothing in the tunnel path ever
looks at a counter, so the packet would loop until the network was stopped — which is why I
had to `exit`.

**Does the IPv4 TTL stop an IPv4 loop in this program? No.** `ipv4_forward` does
`hdr.ipv4.ttl = hdr.ipv4.ttl - 1`, but nothing ever *tests* the TTL:

* there is no `if (hdr.ipv4.ttl == 0)` / `<= 1` check anywhere in `MyIngress`, so a packet
  with TTL 1 is decremented to 0 and still forwarded to the port the LPM table chose;
* `ttl` is a `bit<8>`, and P4 arithmetic on unsigned bit types wraps modulo 2⁸, so at the
  next switch 0 − 1 = **255**, and the packet carries on with a "fresh" TTL;
* `MyComputeChecksum` recomputes the IPv4 checksum after every decrement, so the looping
  packet always looks perfectly valid to the next switch.

So an IPv4 loop through these switches would cycle TTL 64 → 0 → 255 → … → 0 → 255 for ever,
just like the tunnel loop. (The TTL decrement does work as a *counter* — the plain ping in
`evidence/delivery.txt` arrives with `ttl=62` after two switches — it just never triggers a
drop.) And on the tunnel path the TTL is not touched at all: the tunnelled packet in Step 5
arrived with TTL 64, and in C4 all tunnelled packets still arrive with TTL 64.

## 2. Design: the hop limit

**Field and position.** I added `bit<8> hop_limit` to `myTunnel_t`, **after** `proto_id` and
`dst_id`, making the tunnel header 5 bytes:

```
| proto_id (16) | dst_id (16) | hop_limit (8) |
```

* *Size:* 8 bits, like IPv4's TTL and IPv6's Hop Limit. 255 switches is far more than any
  tunnel path needs, and a byte is the smallest field that keeps the header byte-aligned (P4
  headers on BMv2 must be a whole number of bytes). A bigger field would only cost bandwidth.
* *Position:* at the end, so `proto_id` and `dst_id` keep exactly the same byte offsets as in
  v1. A v1 switch therefore still reads the right `dst_id` and forwards correctly; only the
  bytes *after* the old 4-byte header are seen differently. Putting it first would have shifted
  `dst_id` and made every old switch mis-forward or drop. (Section 5a shows that "end" is not
  fully compatible either.)

**Meaning and starting value.** `hop_limit` = how many more switches the packet may cross.
`send.py` sets it to **8** by default and accepts `--hops H` (0–255) to override it. The lab
path h1 → s1 → s2 → h2/h3 crosses 2 switches, so 8 gives room for the topology to grow to
about 4× its diameter while bounding the damage of a loop to 8 extra transmissions. (IP's
default of 64 suits the Internet's diameter; this tunnel is a two-switch network, so a much
smaller budget is safer — a loop wastes at most 8 link transmissions, not 64.)

**Where it is checked and decremented.** In `MyIngress`, at the very start of the tunnel
branch, *before* `myTunnel_exact` is applied:

```p4
if (hdr.myTunnel.isValid()) {
    if (hdr.myTunnel.hop_limit == 0) {
        drop();
    } else {
        hdr.myTunnel.hop_limit = hdr.myTunnel.hop_limit - 1;
        myTunnel_exact.apply();
    }
}
```

* Checking on arrival (rather than "decrement, then drop if it became 0") matches the
  definition: a packet that arrives with 1 may still cross this switch and leaves with 0; the
  next switch drops it. A packet sent with H crosses at most H switches, and hosts see
  `H − (switches crossed)`.
* Doing it in ingress, before the table, means a spent packet never takes a forwarding
  decision and is dropped (`mark_to_drop`, egress port 511) whatever its `dst_id` says. It also
  can never wrap: we only subtract when the value is ≥ 1.

**What else had to agree.** The parser and deparser need no code change — they
`extract`/`emit` `hdr.myTunnel`, whose length now comes from the new header type — but every
party that reads or writes the header bytes must use the same 5-byte layout:
`send.py` builds it, `receive.py` decodes it (otherwise, as in Step 6, the receiver would read
the hop limit as the first byte of IPv4 and decode garbage), and every switch on the path must
run the new program (section 5a shows what happens when one doesn't).

## 3. Implementation

* **`tunnel.p4`** — `hop_limit` added to `myTunnel_t`; the ingress check/decrement shown
  above. The IPv4 path, the tables, the parser, checksum and deparser are unchanged, so the
  same `s1-commands.txt` / `s2-commands.txt` still load.
* **`send.py`** — `ByteField("hop_limit", 8)` appended to the Scapy `MyTunnel` layer, and a
  `--hops H` option validated to 0–255 (argparse rejects anything that doesn't fit the 8-bit
  field instead of letting Scapy truncate it).
* **`receive.py`** — the same field added to its `MyTunnel` layer, and the hop limit printed
  for tunnelled packets: `Received (tunnelled, dst_id=2, hop_limit=6) …`.

Things a reviewer might not see from the diff: `send.py` and `receive.py` each define their own
copy of the header, so the two must be kept in step with `tunnel.p4` by hand — there is no
shared definition. I left the IPv4 TTL behaviour from section 1 unchanged on purpose to keep
this change about the tunnel. The same `ttl <= 1 → drop` check would fix it, but that belongs
in a separate change.

## 4. Evidence: it works

**Delivery** (`evidence/delivery.txt`, fresh network, new program on both switches):

```
Received (tunnelled, dst_id=2, hop_limit=6) from 10.40.0.1 to 10.40.0.2, TTL 64: 'to h2'
Received (tunnelled, dst_id=3, hop_limit=6) from 10.40.0.1 to 10.40.0.3, TTL 64: 'to h3'
Received (tunnelled, dst_id=3, hop_limit=3) from 10.40.0.1 to 10.40.0.3, TTL 64: 'to h3, 5 hops'
```

Sent with 8 (default), arrived with 6 after s1 and s2; sent with `--hops 5`, arrived with 3.
I also sent `--hops 1` to h2: s1 forwarded it with 0 and s2 dropped it —
`Condition "hdr.myTunnel.hop_limit == 0" (node_3) is true`, `mark_to_drop`, `Egress port is
511` — and nothing new appeared in `logs/h2.txt`. Plain IPv4 still works:
`h1 ping -c 2 h3` → `2 packets transmitted, 2 received, 0% packet loss`, `ttl=62`.

**The same loop, now** (`evidence/loop-after.txt`, a freshly started network, same
`table_modify` on handle 2):

| | s1 | s2 |
|---|---|---|
| right after sending | 6 | 4 |
| 5 s later | 6 | 4 |

The counts stop. One of s1's 6 is not the loop packet: the timeline shows an IPv6 frame
(`key is 86dd`) on s1 port 2 at 10:42:19, 26 s before I sent anything, dropped by the default
branch. The loop packet itself was processed **9 times: 5 on s1, 4 on s2**. The timeline shows
`hop_limit == 0` false 8 times (s1, s2, s1, s2, s1, s2, s1, s2), then true on s1's 5th
arrival → egress port 511. So the packet crossed **8 switches** and was dropped on arriving at
the 9th, which is exactly the design: hop limit 8 = at most 8 switch crossings. It went
around the s1⇄s2 loop 4 times instead of ~1000+.

## 5. Evaluation

### a) The mixed rollout (`evidence/mixed.txt`)

`python3 topo.py --id 3540 --s2-program tunnel_v1.p4`: s1 runs the new program, s2 the old.

**Prediction (written before sending).** s1 sends a 5-byte tunnel header with hop limit 7.
The old s2 parses only 4 bytes: `proto_id` (0x0800) and `dst_id` are at the same offsets, so
it should still forward `--tunnel 2` to h2, without touching the hop limit, so the bytes
reaching h2 should carry hop limit 7. But s2's parser goes straight to `parse_ipv4` after 4 bytes, so its "IPv4
header" starts one byte early, at the hop-limit byte. On the tunnel path s2 does not change
any IPv4 field, but its `MyComputeChecksum` still runs (`hdr.ipv4.isValid()` is true) and
writes a checksum computed over the misaligned header into bytes 10–11 *of that misaligned
header*, which are really the IP **protocol** byte and the first checksum byte. I expected that
write to corrupt the packet, so `receive.py` would not recognise it as UDP. For the loop, I
predicted it would still end, because s1 decrements on every pass even though s2 doesn't: s1
should handle the packet 9 times (8 → 1 forwarded, 0 dropped) and s2 8 times, 17 passes
instead of 9.

**What happened.** s2's log: `Parser state 'parse_myTunnel': key is 0800`, `Bytes parsed: 18`,
then `Bytes parsed: 38` (14 + 4 + 20: a 20-byte "IPv4" read one byte early), `dst_id : 0002`,
`Egress port is 2`, `Updating checksum 'cksum'`, `Transmitting packet of size 52`. So the
forwarding decision was right. But `logs/h2.txt` shows only `Listening on h2-eth0...`, and
nothing was received. The capture at h2 explains why, byte by byte:

```
0x0000:  ffff ffff ffff 0000 0000 0001 1212 0800   Ethernet …, type 0x1212 | proto_id 0x0800
0x0010:  0002 0745 0000 2100 0100 0040 0d66 780a   dst_id 2 | hop_limit 07 | 45 00 0021 0001 0000 40 [0d] 66 78 0a…
0x0020:  2800 010a 2800 0310 e110 e100 0d7f ef6d   …28 00 01 | 0a 28 00 03 | UDP 10e1 10e1 000d 7fef | 'm'
0x0030:  6978 6564                                  'ixed'
```

* `hop_limit` arrived as **07**: s1 decremented it, s2 didn't know it existed.
* The real IPv4 header is intact except byte 9, the **protocol**: send.py's `show2()`
  shows `proto = udp` (0x11) and `chksum = 0x6678`, but h2 received **0x0d** there.
* That is s2's checksum. Its misaligned "IPv4" header, read from the `07` byte, is
  `0745 0000 2100 0100 0040 [csum] 780a 2800 010a 2800`. The one's-complement sum of those
  words is 0xF299, and ~0xF299 = **0x0D66**. s2 wrote 0x0D66 over the real bytes 9–10:
  0x11 → 0x0d (protocol), and 0x66 → 0x66 (the high checksum byte happened to be unchanged).
* So h2 got IP protocol 13 with a now-wrong header checksum. It isn't UDP, so `receive.py`
  (which filters on UDP port 4321) printed nothing. The packet was delivered to the right host
  but silently corrupted. No error appeared anywhere: s2 believes it forwarded a valid packet.

The loop behaved exactly as predicted: from a baseline of s1 1 / s2 1, the loop packet took
both to **s1 10 / s2 9**, i.e. 9 passes on s1 and 8 on s2, and the counts stayed the same 5 s
later. s1's log shows `hop_limit == 0` false 8 times, then true. The data-plane protection
still works with one old switch in the loop, but the loop lasts twice as long (17 passes instead
of 9), because only half the switches count.

The part I had to reason through, rather than read from the log, was the corruption. Delivery
"succeeded" at the forwarding level, so the logs look healthy, and only the bytes show the
damage. An appended field is *not* backward compatible when the old program parses *and
rewrites* the bytes that follow the header.

### b) A safe rollout for a header change

1. **Same EtherType, field appended (what I did).** Old switches forward correctly (good), but
   misparse and, through the checksum update, corrupt the payload (very bad, and silent). Unsafe
   unless every switch is upgraded before the first sender uses the new header.
2. **New EtherType for the new format (e.g. 0x1213 = "myTunnel v2").** An old switch doesn't
   know 0x1213, so its parser accepts with neither `myTunnel` nor `ipv4` valid, and ingress drops
   the packet. That is a *loud, clean* failure instead of silent corruption. Rollout:
   (i) upgrade switches one at a time to a program that parses **both** 0x1212 (v1) and 0x1213
   (v2) and forwards each in its own format; v1 traffic is unaffected throughout; (ii) once
   every switch on a path is dual-stack (the controller knows), switch the senders/ingress
   switches to v2; (iii) when no v1 traffic remains, remove v1 from the parser. Cost: one more
   parser state and an EtherType to allocate. Every step is reversible.
3. **A version field (or a header-length field) in the tunnel header.** This is the long-term
   fix: an old switch reads `version`/`length`, can drop unknown versions or *skip* over
   unknown trailing bytes (as IPv4 IHL, IPv6 extension headers and Geneve's option length allow)
   instead of misparsing. Our v1 header has neither, so it can't be added compatibly now. It
   would come in through option 2, and then all future changes are easy.
4. **Translate at the boundary.** A new switch keeps a per-port table "neighbour speaks v2?"
   (set by the control plane). Towards an old neighbour it strips `hop_limit` and sends v1, and
   on receiving v1 from an old neighbour it adds a conservative hop limit. This lets the hop limit
   protect the upgraded part of the network immediately, at the cost of an extra table and
   `setValid/setInvalid` header rewriting.
5. **(No header change at all.)** Use the inner IPv4 TTL as the tunnel hop count: new switches
   decrement and check `hdr.ipv4.ttl` on the tunnel path, and old switches simply don't. Fully
   compatible, but it only works when the payload is IPv4 and it mixes layers.

**My proposal:** option 2 (new EtherType + dual-stack phase) as the rollout mechanism, and while
doing it, add a `version` field to v2 so the next change can use option 3. Option 4 can cover
islands of old switches that cannot be upgraded for a long time.

### c) Data-plane vs control-plane loop protection

* **Week 3's `check_paths()` (control plane)** looks at the forwarding state the controller is
  about to install and finds loops *before any packet is affected*. It can say *which* entries
  form the loop, and it also finds problems a hop limit never sees, such as black holes (paths
  that end nowhere) and wrong-but-loop-free paths. But it only sees what the controller
  *believes* is installed. It can't catch state changed behind its back (exactly my manual
  `table_modify` on s2), a switch that failed to apply an update, transient loops while updates
  reach switches in different orders, or bugs in the switch itself.
* **The hop limit (data plane)** catches *any* loop that actually happens, whatever caused it,
  per packet, within H hops, with no controller involved and even mid-update. But it doesn't
  prevent anything: the looping traffic is still lost, it still consumes up to H transmissions
  per packet, and it says nothing about *where* or *why* (the switch that drops it is just
  wherever the budget ran out). It also can't detect a loop-free misroute. If the budget is set
  too low, it drops legitimate traffic on long paths.
* **Real networks use both** for these complementary reasons: the control plane keeps the
  network *correct*, and the data-plane TTL/hop limit is the safety net that bounds the damage
  when the control plane's view and reality disagree, which they always do briefly during
  convergence. My experiment is a small example: `check_paths()` on the controller's intended
  tables would have passed, yet the loop happened, and only the hop limit stopped it.

### d) Cost on a hardware switch at line rate

* **Per-packet work:** one 8-bit compare and one 8-bit subtract, no table lookup and no
  per-flow state or registers. On a PISA/Tofino-style pipeline this is a gateway condition
  plus a simple ALU action. It is stateless and fixed-cost, so it does **not** reduce
  throughput. At most it needs a match-action stage (or shares one) *before* `myTunnel_exact`,
  because the table must only be applied when the check passes. On a pipeline with spare
  stages, that adds roughly zero latency.
* **Parser/PHV:** one more byte to extract and 8 more bits of packet header vector, which is
  negligible.
* **Bandwidth:** +1 byte per tunnelled packet: about 1.5 % on a minimum-size 64-byte frame and
  about 0.07 % on a 1500-byte frame. It also makes the tunnel header 5 bytes, which leaves the inner
  IPv4 header at an odd offset. Some hardware parsers/deparsers prefer 2- or 4-byte-aligned
  headers, and the inner IPv4 header no longer starts on a 2-byte boundary. On hardware, I would
  therefore make it `bit<8> hop_limit; bit<8> version_or_reserved;` (6-byte header). That costs
  one byte more and fixes alignment, and it provides the version field that section 5b asks for.
* **Mutable header:** the field changes at every hop, so anything that authenticates or
  checksums the tunnel header would need recomputing per hop. Nothing does in this design.

## AI use

I used **Claude Code (Anthropic)** for this assignment.
- It help me dubug the error occur and guide step to resolve the issue
- I go through each step for the lab and assigment

## Evidence files

| File | What it shows |
|---|---|
| `evidence/loop-before.txt` | The loop with the finished lab program: 892/890 → 1444/1443 packets processed in 5 s, never stopping |
| `evidence/delivery.txt` | Tunnelled delivery to h2 and h3 with hop limit 8 → 6 (and 5 → 3), `--hops 1` dropped at s2, and a plain `ping` with 0 % loss |
| `evidence/loop-after.txt` | The same loop with the hop limit: 5 passes on s1 + 4 on s2 (6/4 counted, incl. one unrelated IPv6 frame), stopped, with a pass-by-pass timeline |
| `evidence/mixed.txt` | s1 new, s2 old: tunnelled packet forwarded but corrupted (IP protocol 0x11 → 0x0d), h2 prints nothing; loop still ends after 9 + 8 passes |
