# RFC 4301 — Security Architecture for the Internet Protocol (Summary)

Source: RFC 4301 (S. Kent, K. Seo, December 2005, obsoletes RFC 2401). Public-domain IETF standard. This file summarizes, in original wording, only the sections relevant to AegisNet-AI's Security Association (SA) provisioning; it is not a full reproduction of the RFC.

## What IPsec provides
IPsec is a suite of protocols operating at the IP layer that provides access control, connectionless integrity, data origin authentication, anti-replay protection, confidentiality, and limited traffic-flow confidentiality. The two security protocols defined for this are the Authentication Header (AH) and Encapsulating Security Payload (ESP) — this project uses ESP exclusively.

## Security Associations (SA)
A Security Association is the foundational concept of the architecture: it is a one-way (simplex) logical connection that provides a security service to the traffic carried over it. Because an SA is unidirectional, bidirectional communication between two hosts requires **two** SAs — one per direction. This matches the project's design: an outbound SA (server → client) and an inbound SA (client → server) are provisioned as a pair for every protected session.

An SA is uniquely identified by the combination of three values:
1. **Security Parameter Index (SPI)** — an arbitrary 32-bit value chosen by the SA's creator.
2. **Destination IP address** — the endpoint the SA terminates at.
3. **Security protocol identifier** — ESP or AH (this project: ESP only).

## Security Association Database (SAD)
Each IPsec implementation maintains an SAD, a table of active SAs. Each SAD entry records at minimum:
- SPI, destination address, protocol (AH/ESP)
- the cryptographic algorithm(s) and key(s) in use
- SA lifetime (time- or byte-based expiry)
- sequence number counter (anti-replay)
- mode: **transport** or **tunnel**

This project always uses **transport mode**, which protects the payload of the original IP packet (the TCP segment) without adding a second, encapsulating IP header — appropriate here because both endpoints are the actual communicating hosts, not security gateways relaying traffic for others (which would require tunnel mode).

## Security Policy Database (SPD)
Separately from the SAD, an SPD determines, for each outbound or inbound packet, whether to apply IPsec processing, bypass it, or discard the packet, based on selectors (source/destination address, protocol, ports). AegisNet-AI's `ip xfrm policy` rules are SPD entries: they mandate (`level required`) that TCP port 8080 traffic between the victim-client and target-server must be ESP-protected, with no plaintext fallback permitted.

## Relevance to this project
The project's kernel enforcement engine (Module 4) directly implements this architecture: `ip xfrm state add` provisions SAD entries (keys, algorithm, mode, SPI), and `ip xfrm policy add` provisions SPD entries (which traffic is mandated to use which SA). The AES-256-GCM AEAD cipher and HMAC-SHA-256 fallback used by the project are standard IPsec ESP transform choices layered on top of this RFC 4301 architecture (the transform details themselves are specified in RFC 4303 — see `rfc4303_esp.md` — and the IANA IKEv2 algorithm registry, not RFC 4301 itself).
