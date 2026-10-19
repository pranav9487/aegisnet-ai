# arptables Command Syntax (Linux ARP-Layer Firewall)

Source: `arptables --help` — real output captured from arptables v1.8.10 (nf_tables backend) on Ubuntu 24.04. Used as a second, independent layer of attacker isolation alongside ebtables (arptables filters specifically on ARP opcode/hardware fields, which ebtables's generic L2 matching does not expose).

## Usage forms
```
arptables -[ACD] chain rule-specification [options]
arptables -I chain [rulenum] rule-specification [options]
arptables -R chain rulenum rule-specification [options]
arptables -D chain rulenum [options]
arptables -[LS] [chain [rulenum]] [options]
arptables -[FZ] [chain] [options]
arptables -[NX] chain
arptables -E old-chain-name new-chain-name
arptables -P chain target [options]
```

## Commands
| Flag | Long form | Meaning |
|---|---|---|
| `-A` | `--append` | append to chain |
| `-C` | `--check` | check for existence of a rule |
| `-D` | `--delete` | delete matching rule (or by rulenum) |
| `-I` | `--insert` | insert as rulenum (default 1 = first) |
| `-R` | `--replace` | replace rule at rulenum |
| `-L` | `--list` | list rules |
| `-F` | `--flush` | delete all rules in chain or all chains |
| `-Z` | `--zero` | zero counters |
| `-N` | `--new` | create user-defined chain |
| `-X` | `--delete-chain` | delete user-defined chain |
| `-P` | `--policy` | change chain policy |

## Options relevant to ARP-specific filtering
| Flag | Meaning |
|---|---|
| `[!] -s, --source-ip address[/mask]` | source IP specification |
| `[!] -d, --destination-ip address[/mask]` | destination IP specification |
| `[!] --source-mac address[/mask]` | source MAC |
| `[!] --destination-mac address[/mask]` | destination MAC |
| `--opcode code[/mask]` | ARP operation code (2 bytes) — e.g. `2` = Reply |
| `--h-type type[/mask]` | hardware type (2 bytes hex) — `1` = Ethernet |
| `--proto-type type[/mask]` | protocol type (2 bytes) — `0x800` = IPv4 |
| `-i, --in-interface` | input interface name |
| `-j, --jump target` | target for the rule (may load target extension) |
| `-t, --table table` | table to manipulate (default `filter`) |

### ARP opcode reference
```
1 = Request         5 = DRARP_Request     8 = InARP_Request
2 = Reply            6 = DRARP_Reply       9 = ARP_NAK
3 = Request_Reverse  7 = DRARP_Error
4 = Reply_Reverse
```

## Project-relevant example (drop ARP replies forged by the attacker MAC)
```bash
arptables -A INPUT --source-mac 02:42:ac:1c:00:42 --opcode 2 -j DROP
```
Matches ARP Replies (`opcode 2`, the message type used in gratuitous ARP poisoning) carrying the attacker's hardware address, and drops them before they reach this host's ARP cache.

## Rollback (used by the atomic rollback engine on health-check failure)
```bash
arptables -F
```
