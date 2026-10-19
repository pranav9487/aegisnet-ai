# RFC 4303 — IP Encapsulating Security Payload (ESP) (Summary)

Source: RFC 4303 (S. Kent, December 2005, obsoletes RFC 2406). Public-domain IETF standard. This file summarizes the ESP packet format and processing relevant to the project's kernel-level ESP transport-mode enforcement; it is not a full reproduction of the RFC.

## ESP packet format (fields, in order)

```
+-------------------------------------------------------------+
|               Security Parameters Index (SPI)               |  <- 32 bits, authenticated
+-------------------------------------------------------------+
|                      Sequence Number                        |  <- 32 bits (64-bit extended seq optional), authenticated
+-------------------------------------------------------------+
|                    Payload Data* (variable)                 |  <- encrypted
~                                                               ~
+-------------------------------------------------------------+
|               |     Padding (0-255 bytes)                   |  <- encrypted
+-------------------------------------------------------------+
|                               |  Pad Length  |  Next Header  |  <- encrypted
+-------------------------------------------------------------+
|                 Authentication Data (variable)               |  <- ICV, not encrypted
+-------------------------------------------------------------+
```

### Field definitions
- **Security Parameters Index (SPI)** — unsigned 32-bit value that, combined with the destination address and protocol (ESP), uniquely identifies the SA for this packet. This is the same SPI the project assigns via `ip xfrm state add ... spi 0x1001` / `0x1002`.
- **Sequence Number** — a monotonically increasing 32-bit counter, incremented per packet sent on this SA. Provides anti-replay protection; the receiver maintains a sliding replay window and rejects packets with sequence numbers outside it or already seen.
- **Payload Data** — the actual encrypted content. In transport mode (used throughout this project) this is the original upper-layer segment (TCP header + data), not a re-encapsulated IP header.
- **Padding** — 0–255 bytes added before encryption so the plaintext aligns to the cipher's block-size requirement, and to optionally obscure the true payload length.
- **Pad Length** — one byte stating how many padding bytes were added, so the receiver can strip them correctly.
- **Next Header** — one byte identifying the protocol of the data in the Payload field (e.g. TCP = 6), analogous to the IP header's Protocol field.
- **Authentication Data (ICV)** — the Integrity Check Value, computed over the ESP header, payload, and trailer. For AEAD ciphers like AES-GCM (used in this project), authentication and encryption happen in one operation rather than as a separate HMAC step. This is the field whose length AegisNet-AI's defense policy schema fixes at 128 bits via the `aead ... 128` parameter to `ip xfrm state add`.

## Header placement
The ESP header (SPI + Sequence Number) is inserted between the IP header and the upper-layer protocol header. In **transport mode** — the mode this project uses exclusively — the original IP header is left mostly intact (only the Protocol field changes to 50, signaling ESP) and only the upper-layer payload (TCP segment) is encrypted and wrapped:

```
Before: [ IP Header ][ TCP Header ][ Data ]
After:  [ IP Header ][ ESP Header ][ TCP Header ][ Data ][ ESP Trailer ][ ESP Auth ]
                       (encrypted: TCP Header + Data + Trailer)
```

This is why an on-path attacker (`red-attacker`) who previously captured plaintext TCP payloads via ARP poisoning sees only ciphertext once the project's enforcement engine establishes the ESP SA — the IP addresses remain visible (needed for routing) but the TCP header, sequence numbers, and application data are encrypted and integrity-protected.

## Relevance to this project
- The project's SPI values (`spi 0x1001`, `spi 0x1002`) map directly to this field.
- The 128-bit ICV length in the schema's `ipsec_enforcement` policy corresponds to the Authentication Data field length for AES-GCM.
- Sequence-number anti-replay is a built-in ESP property that compounds the project's own TCP-layer sequence-drift detection (Module 1) — ESP prevents replay at the IPsec layer independently of whatever the application-layer TCP sequence numbers do.
