# Test fixtures (real data slices)

Small slices of real Hayabusa v4.4.0 output (`-t jsonl -p super-verbose -U -b`, rules commit
`58f8f145c65ed0bc0dcf888efde4ca9ca87ba846`) plus the matching Station 1 SQLite rows.

| Fixture | Source EVTX (EVTX-ATTACK-SAMPLES) | Alerts | Events |
| --- | --- | ---: | ---: |
| `UACME_59_Sysmon.*` | `UACME_59_Sysmon.evtx` | 2 | 1 |
| `CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.*` | `Credential Access/CA_Mimikatz_Memssp_Default_Logs_Sysmon_11.evtx` | 2 | 1 |
| `DE_sysmon-3-rdp-tun.*` | `Command and Control/DE_sysmon-3-rdp-tun.evtx` | 19 | 9 |

- `*.hayabusa.jsonl`: unmodified Hayabusa rows, except `EvtxFile` reduced to the basename.
- `*.events.json`: Station 1 rows (frozen schema columns, Sigma columns excluded).

## Attribution & License Notes
- **EVTX-ATTACK-SAMPLES** (`https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES`): Public Windows event log attack samples created by Samir Bousseaden (MIT License). Used here solely as small unit-test fixtures for logic verification.
- **Hayabusa & Hayabusa Rules** (`https://github.com/Yamato-Security/hayabusa`, `https://github.com/Yamato-Security/hayabusa-rules`): Created by Yamato Security (AGPL-3.0 / Sigma Detection Rules License). Only small JSONL alert slices are stored in `tests/fixtures/` for parser and join-key regression testing.
- No evaluation metrics or benchmark claims are derived from these public fixtures.
