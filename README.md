# Intrusion Detection System
This Network Intrusion Detection System processes PCAP Files to detect attack using a signature database provided in TOML format. Each signatures in the file are regular expression over byte strings and are matched against IP datagram payloads and TCP streams.

Following is the structure of the TOML Signature Database file:
```
signatures = [
  "foo",
  "bar[0-9]+",
  "pwned_[a-zA-Z_]+_grade"
]
```
The NIDS features:

- IPv4 and TCP checksum verification failing to which packets are dropped silently
- Custom TCP stream reassembly implementing a *first-received* policy for overlapping segments
- Do not track TCP sessions where initial TCP handshake was not observed
- Bounded memory use during execution to prevent DoS attacks using Buffer Trimming
