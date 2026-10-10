# Wireshark Captures Directory

This directory is designated for storing `.pcap` or `.pcapng` packet capture files recorded during CFTP protocol sessions.

## Suggested Capture Naming Convention
- `cftp_handshake_session.pcapng` - Full session showing TCP 3-way handshake, LIST, GET, PUT, and 4-way FIN termination.
- `cftp_stream_segmentation.pcapng` - Capture illustrating TCP segmenting large CFTP payload transfers across multiple MTU segments.
- `cftp_checksum_conflict.pcapng` - Capture demonstrating integrity check failure (409 CONFLICT).

Refer to `docs/wireshark-analysis.md` for complete step-by-step capture instructions and display filter recipes.
