# ip-xfrm Command Syntax (Linux Netlink XFRM Interface)

Source: `ip xfrm help` / `ip xfrm state help` / `ip xfrm policy help` — real output captured from iproute2 6.1.0 on Ubuntu 24.04. This is the authoritative local syntax Agent 3 must compile commands against.

## Top-level usage

```
ip xfrm XFRM-OBJECT { COMMAND | help }
where  XFRM-OBJECT := state | policy | monitor
```

## `ip xfrm state` — manages Security Associations (SAs)

```
ip xfrm state { add | update } ID [ ALGO-LIST ] [ mode MODE ]
    [ mark MARK [ mask MASK ] ] [ reqid REQID ] [ seq SEQ ]
    [ replay-window SIZE ] [ flag FLAG-LIST ] [ sel SELECTOR ]
    [ LIMIT-LIST ] [ encap ENCAP ] [ if_id IF_ID ]

ip xfrm state { delete | get } ID [ mark MARK [ mask MASK ] ]
ip xfrm state deleteall [ ID ] [ mode MODE ] [ reqid REQID ] [ flag FLAG-LIST ]
ip xfrm state list [ nokeys ] [ ID ] [ mode MODE ] [ reqid REQID ]
ip xfrm state flush [ proto XFRM-PROTO ]
ip xfrm state count
```

### Field definitions
- `ID` := `[ src ADDR ] [ dst ADDR ] [ proto XFRM-PROTO ] [ spi SPI ]`
- `XFRM-PROTO` := `esp | ah | comp | route2 | hao`
- `ALGO-LIST` := one or more `ALGO`:
  - `{ enc | auth } ALGO-NAME ALGO-KEYMAT`
  - `auth-trunc ALGO-NAME ALGO-KEYMAT ALGO-TRUNC-LEN`
  - `aead ALGO-NAME ALGO-KEYMAT ALGO-ICV-LEN` ← this project uses `aead "rfc4106(gcm(aes))" <64-hex-char key + 8-hex-char salt> 128`
  - `comp ALGO-NAME`
- `MODE` := `transport | tunnel | beet | ro | in_trigger` — this project uses `transport`
- `FLAG` := `noecn | decap-dscp | nopmtudisc | wildrecv | icmp | af-unspec | align4 | esn`
- `SELECTOR` := `[ src ADDR[/PLEN] ] [ dst ADDR[/PLEN] ] [ dev DEV ] [ UPSPEC ]`
- `UPSPEC` (protocol/port selector) := `proto { { tcp | udp | sctp | dccp } [ sport PORT ] [ dport PORT ] | ... }`

### Project-relevant example (AES-256-GCM, transport mode, TCP 8080)
```bash
ip xfrm state add src 172.28.0.20 dst 172.28.0.10 proto esp spi 0x1001 \
    mode transport aead "rfc4106(gcm(aes))" <64hex-key><8hex-salt> 128
```
- Key material: 256-bit key (64 hex chars) + 32-bit salt (8 hex chars) = 72 hex chars total.
- `128` at the end is the ICV (Integrity Check Value) authentication tag length in bits.
- `spi` is a chosen 32-bit Security Parameter Index distinguishing this SA.

## `ip xfrm policy` — manages Security Policies (SPs), which bind traffic selectors to SAs

```
ip xfrm policy { add | update } SELECTOR dir DIR [ ctx CTX ]
    [ mark MARK [ mask MASK ] ] [ index INDEX ] [ ptype PTYPE ]
    [ action ACTION ] [ priority PRIORITY ] [ flag FLAG-LIST ]
    [ if_id IF_ID ] [ LIMIT-LIST ] [ TMPL-LIST ]

ip xfrm policy { delete | get } { SELECTOR | index INDEX } dir DIR
ip xfrm policy { deleteall | list } [ nosock ] [ SELECTOR ] [ dir DIR ]
ip xfrm policy flush [ ptype PTYPE ]
ip xfrm policy count
ip xfrm policy setdefault DIR ACTION [ DIR ACTION ] [ DIR ACTION ]
ip xfrm policy getdefault
```

### Field definitions
- `DIR` := `in | out | fwd`
- `PTYPE` := `main | sub`
- `ACTION` := `allow | block`
- `TMPL-LIST` := one or more `tmpl TMPL`, where `TMPL` := `ID [ mode MODE ] [ reqid REQID ] [ level LEVEL ]`
- `LEVEL` := `required | use` — this project uses `required` (traffic MUST be ESP-wrapped, no plaintext fallback)

### Project-relevant example (mandate ESP on TCP 8080, both directions)
```bash
ip xfrm policy add src 172.28.0.20 dst 172.28.0.10 proto tcp dir out \
    tmpl src 172.28.0.20 dst 172.28.0.10 proto esp mode transport level required

ip xfrm policy add src 172.28.0.10 dst 172.28.0.20 proto tcp dir in \
    tmpl src 172.28.0.10 dst 172.28.0.20 proto esp mode transport level required
```

## Rollback (used by the 500ms health-verification engine on failure)
```bash
ip xfrm state flush && ip xfrm policy flush
```
