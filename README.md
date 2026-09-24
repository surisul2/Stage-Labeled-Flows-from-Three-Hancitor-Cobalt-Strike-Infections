# Stage-Labeled Flows from Three Hancitor–Cobalt Strike Infections

Labels and reproduction materials for the paper:

> [TODO: final title], [TODO: authors], [TODO: journal, year].

This repository provides the flow-level stage labels, the IOC-based labeling rules, and the evaluation setup used in the paper. The original packet captures are **not** redistributed here; they are available from Malware-Traffic-Analysis.net (MTA) and can be matched to our labels with the identifiers below.

## Contents

| File | Description |
|---|---|
| `rules.csv` | One row per labeling rule: the IOC, where it appears in the MTA IOC file, and the Wireshark display filter used to select flows. |
| `flow_labels.csv` | One row per TCP flow: flow identifiers (5-tuple, timestamps), size, assigned label, and the `rule_id` that produced the label. |
| `stage_summary.csv` | Flow counts per case and label, compared with the counts reported in the paper. |

`flow_labels.csv` references `rules.csv` through `rule_id`. To see why a flow received its label, look up its `rule_id` in `rules.csv`.

## Source traffic

| Case | MTA post | Original pcap | SHA-256 | Infected host | IOC txt
|---|---|---|---|---|---| 
| Case 1 | https://www.malware-traffic-analysis.net/2021/06/01/index.html | 2021-06-01-Hancitor-with-Cobalt-Stike-and-netping-tool.pcap.zip | 1faedfa1bfe1304f471bd56973f74174cfc3958d05f2ad1a3a86af7e1dc6b7b0 | 10.6.1.101 | 2021-06-01-Hancitor-IOCs.txt.zip 
| Case 2 | https://www.malware-traffic-analysis.net/2021/06/17/index.html | 2021-06-17-Hancitor-infection-with-Cobalt-Strike.pcap.zip | e2447300227afc09561b107861e694d6277bc5c0563735fe59a683b3729c6d22 | 10.17.6.93 | 2021-06-17-Hancitor-IOCs.txt.zip 
| Case 3 | https://www.malware-traffic-analysis.net/2021/09/02/index.html | 2021-09-02-Hancitor-with-Cobalt-Strike.pcap.zip | 31f17459dbebb365975cd5b7bbf850c638dcf4379ee69e646692d35eaf58749d | 10.0.0.113 | 2021-09-02-Hancitor-with-Cobalt-Strike-IOCs.txt.zip

Each MTA post also provides the IOC text file referenced in the `ioc_filename` column of `rules.csv` (e.g., `2021-06-01-Hancitor-IOCs.txt`). MTA distributes pcaps as password-protected archives; see the MTA site for the password convention. SHA-256 values are computed on the extracted pcap files, not on the zip archives downloaded from MTA.

## Labeling procedure

**Flow definition.** A flow is one TCP connection, identified by Wireshark's `tcp.stream` index (equivalently, the 5-tuple and first-packet timestamp). Multiple HTTP requests carried over the same connection (keep-alive) form a single flow.

**Traffic scope.** Only TCP flows are included. All non-TCP traffic (e.g., ICMP, UDP including DNS and QUIC, ARP) is excluded. This includes the netping ICMP activity noted in the Case 1 IOC file.

**Stages.** Stages are defined with reference to MITRE ATT&CK tactics & techniques.

| Label | Technique | ID | Tactic | Communication |
|---|---|---|---|---|
| S1 | Spearphishing Link | T1566.002 | Initial Access | Lure redirection via legitimate service |
| S2 | Malicious Link | T1204.001 | Execution | Malicious document delivery |
| S3 | System Network Configuration Discovery | T1016(.001) | Discovery | External IP check (api.ipify.org) |
| S4 | Application Layer Protocol: Web | T1071.001 | Command and Control | Hancitor C2 check-in |
| S5 | Ingress Tool Transfer | T1105 | Command and Control | Secondary payload (stager) retrieval |
| S6 | Application Layer Protocol: Web | T1071.001 | Command and Control | Persistent beacon communication |
| Background/Other | - | - | – | Flows not matched by any stage rule |

**Assignment rule.** Each stage label is assigned by a rule in `rules.csv`. A rule's `match_expression` is a Wireshark display filter built from IOCs listed in the MTA IOC file for that case. The label is applied to the **entire** `tcp.stream` that contains at least one packet matching the filter.

**Background/Other.** Flows not matched by any stage rule are labeled `Background/Other`. These flows are **not independently verified as benign**; for example, internal Active Directory traffic after infection may include post-compromise activity.

## File formats

### `rules.csv`

| Column | Description |
|---|---|
| `case` | Case date (e.g., `2021-06-01`) |
| `rule_id` | Rule identifier referenced by `flow_labels.csv` (R*, B*, X*) |
| `label` | Assigned label (S1–S6, Background/Other, Excluded) |
| `ioc_filename` | MTA IOC file the rule is based on |
| `ioc_source` | Section heading in the IOC file where the IOC appears |
| `match_expression` | Wireshark display filter used to select flows |
| `observed_request` | Requests recorded in the IOC file / observed in the pcap |

Rule ID ranges: Case 1 `R1–R6`, `B0`, `X0`; Case 2 `R7–R12`, `B1`, `X1`; Case 3 `R13–R18`, `B2`, `X2`.

### `flow_labels.csv`

[TODO: match the column names below to the actual header]

| Column | Description |
|---|---|
| `case` | Case date |
| `stage_id` | Numeric stage index (0 = Background/Other, 1–6 = S1–S6) |
| `label` | Assigned label |
| `pcap_path` | Path of the per-flow pcap produced by our split |
| `sha256` | SHA-256 of the per-flow pcap (for verifying a reconstructed split) |
| `src_ip`, `src_port`, `dst_ip`, `dst_port`, `proto` | Flow 5-tuple |
| `first_ts`, `last_ts` | First and last packet timestamps (UTC) |
| `packets`, `bytes` | Packet and byte counts |
| `http_method`, `http_host`, `tls_sni` | Application-layer identifiers observed in the flow, if any |
| `rule_id` | Rule that produced the label |

### `stage_summary.csv`

| Column | Description |
|---|---|
| `case` | Case date (e.g., `2021-06-01`) |
| `label` | Label (S1–S6, Background/Other) |
| `flows` | Number of flows for the case and label |

Counts are obtained by grouping `flow_labels.csv` by `case` and `label`, and match Table 3 of the paper.

## Locating labeled flows in the original pcap

1. Download the original pcap for each case from the MTA post and verify its SHA-256 against the table above.
2. Each row of `flow_labels.csv` is one TCP connection and can be located in the original pcap by its 5-tuple and `first_ts`. For example:
   ip.src==10.6.1.101 && tcp.srcport==49548 && ip.dst==90.156.143.87 && tcp.dstport==80
3. Look up the row's `rule_id` in `rules.csv` to see the IOC, its source, and the filter that produced the label.

## Case-specific notes

**Case 1 (2021-06-01).**
- The IOC file reports netping ICMP activity. It is excluded because only TCP flows are included.
- S2 (`/swaging.php` ×2, `/favicon.ico`) and S5 (`/6ha8ua.exe`, `/3105.bin`, `/3105s.bin`) each occur within a single TCP connection and are therefore counted as one flow.

**Case 2 (2021-06-17).**
- The IOC file lists two Cobalt Strike servers (139.60.161.74 and 162.244.83.95), and both are observed in the pcap. Flows to either server are assigned to S6.

**Case 3 (2021-09-02).**
- The IOC file does not include a per-infection traffic section for S1 and S2; it lists all feedproxy links and document-delivery URLs from the campaign. S1 and S2 flows were identified because the host and URI observed in the pcap appear in these lists.
- The IOC file lists three Hancitor C2 domains (asinvotheir.com, clatrommon.ru, ditrismale.ru). Only asinvotheir.com was contacted in the pcap; the rule includes all three, and the other two match no streams.
- S5 and S6 appear under the same heading (`HANCITOR C2 TRAFFIC`) in the IOC file. They are separated by content, consistent with Cases 1 and 2: `.bin` payload retrieval is S5, and IP-addressed beacon traffic is S6.


## License

Labels and metadata in this repository: [TODO: e.g., CC BY 4.0].
The original pcaps and IOC files are provided by Malware-Traffic-Analysis.net and are subject to its terms.

## Citation

[TODO: BibTeX entry]
