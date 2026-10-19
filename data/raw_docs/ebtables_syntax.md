# ebtables Command Syntax (Linux Bridge/Layer-2 Firewall)

Source: `ebtables --help` — real output captured from ebtables 1.8.10 (nf_tables backend) on Ubuntu 24.04. This is the authoritative local syntax for Layer-2 MAC isolation (the attacker-MAC drop step).

## Usage forms
```
ebtables -[ADI] chain rule-specification [options]
ebtables -P chain target
ebtables -[LFZ] [chain]
ebtables -[NX] [chain]
ebtables -E old-chain-name new-chain-name
```

## Commands
| Flag | Long form | Meaning |
|---|---|---|
| `-A` | `--append` | append to chain |
| `-D` | `--delete` | delete matching rule from chain |
| `-I` | `--insert` | insert rule at position rulenum in chain |
| `-L` | `--list` | list rules in a chain or all chains |
| `-F` | `--flush` | delete all rules in chain or all chains |
| `-Z` | `--zero` | zero counters |
| `-P` | `--policy` | change policy on chain to target |
| `-N` | `--new-chain` | create a user-defined chain |
| `-X` | `--delete-chain` | delete a user-defined chain |
| `-E` | `--rename-chain` | rename a chain |

## Options
| Flag | Long form | Meaning |
|---|---|---|
| `-p` | `--proto [!] proto` | protocol, by hex code, name, or LENGTH |
| `-s` | `--src [!] address[/mask]` | source **MAC** address (what this project matches on) |
| `-d` | `--dst [!] address[/mask]` | destination MAC address |
| `-i` | `--in-if [!] name[+]` | network input interface name |
| `-o` | `--out-if [!] name[+]` | network output interface name |
| | `--logical-in / --logical-out` | logical bridge interface name |
| `-j` | (implied, jump) | target for the rule (e.g. `DROP`, `ACCEPT`) |
| `-v` | `--verbose` | verbose mode |

## Project-relevant example (drop all frames from attacker's MAC)
```bash
ebtables -A INPUT -s 02:42:ac:1c:00:42 -j DROP
```
- `-A INPUT` appends to the built-in `INPUT` chain (frames destined for this host).
- `-s <mac>` matches on source hardware address — this is why ebtables isolates by MAC rather than IP, which matters because an ARP-poisoning attacker forges the victim's IP but cannot forge away their own NIC's MAC at the frame level.
- `-j DROP` is the target action.

## Rollback (used by the atomic rollback engine on health-check failure)
```bash
ebtables -F
```
Flushes all chains back to empty — must run alongside `arptables -F` and `ip xfrm state/policy flush` for a full rollback.
