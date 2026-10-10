# Wireshark Packet Capture & Protocol Analysis Guide

**Project:** Innovative Approach to Designing and Analyzing a Custom Application Layer File Transfer Protocol over TCP  
**Document:** TCP Stream Inspection, Packet Analysis, and Wireshark Workflow  

---

## 1. Overview & Objectives

This guide details how to capture, inspect, and analyze CFTP network traffic using **Wireshark**.

The educational goals are to:
1. Observe the **TCP 3-Way Handshake** establishing the transport-layer connection.
2. Observe CFTP **control messages** and delimiter framing (`\r\n`) within TCP data segments.
3. Observe **TCP segmentation** when large file payloads exceed the Maximum Segment Size (MSS).
4. Analyze TCP flags (`SYN`, `ACK`, `PSH`, `FIN`, `RST`).
5. Reconstruct the entire session using Wireshark's **Follow TCP Stream** feature.
6. Observe graceful **TCP 4-Way Connection Termination**.

---

## 2. Step-by-Step Packet Capture Workflow

### Step 1: Select the Capture Interface
- **On Windows:**
  1. Open Wireshark.
  2. Select the **Adapter for loopback traffic capture** (installed via Npcap).
     *(Do not select Ethernet or Wi-Fi when testing on `127.0.0.1`)*.
- **On Linux / macOS:**
  1. Select the **Loopback: lo** interface (`lo0` on macOS).

### Step 2: Apply a Capture Filter (Optional)
To capture only traffic dedicated to CFTP:
```text
tcp port 9000
```

### Step 3: Start the CFTP Server
In your first terminal:
```powershell
# Windows PowerShell
python -m cftp.server --port 9000
```
```bash
# Linux / macOS Bash
python3 -m cftp.server --port 9000
```

### Step 4: Start Packet Capture in Wireshark
Click the blue **Start Capturing Packets** shark fin icon.

### Step 5: Execute the CFTP Automated Demo Scenario
In your second terminal, run the automated traffic generator:
```powershell
python scripts/demo_traffic.py
```
*Alternatively, launch the interactive client (`python -m cftp.client`) and manually run `list`, `put`, `get`, `quit`.*

### Step 6: Stop Capture & Apply Display Filters
In Wireshark, click the red **Stop Capturing Packets** square.

In the top filter bar, type:
```text
tcp.port == 9000
```
and press **Enter**.

---

## 3. Dissecting the Observed TCP Packets

When inspecting the captured packets in Wireshark, you will observe the following lifecycle:

### 3.1 TCP 3-Way Handshake (Establishment)
Before any CFTP application data can flow, TCP establishes reliable communication:

| Packet # | Source -> Destination | TCP Flags | Info / Explanation |
|---|---|---|---|
| **1** | Client -> Server | `[SYN]` | Client sends initial sequence number ($Seq = 0$). |
| **2** | Server -> Client | `[SYN, ACK]` | Server acknowledges client ($Ack = 1$) and sends its own sequence number ($Seq = 0$). |
| **3** | Client -> Server | `[ACK]` | Client acknowledges server ($Ack = 1$). Connection state: `ESTABLISHED`. |

```
Client                                     Server
  |                                          |
  | -------- 1. SYN (Seq=0) ---------------> |
  | <------- 2. SYN, ACK (Seq=0, Ack=1) ---- |
  | -------- 3. ACK (Seq=1, Ack=1) --------> |
  |                                          |
```

---

### 3.2 CFTP Application Exchange (Request & Response)

Following the handshake, packets with the `[PSH, ACK]` flags will appear. The `PSH` (Push) flag indicates to the receiving OS that the buffered segment should be immediately passed to the application layer.

#### LIST Command Packet
- **Frame Detail:** `TCP Payload: 15 bytes`
- **Application Payload:** `CFTP/1.0 LIST\r\n`
- **Wireshark Packet Bytes Pane:**
  ```text
  43 46 54 50 2f 31 2e 30 20 4c 49 53 54 0d 0a     CFTP/1.0 LIST..
  ```

#### LIST Response Packet
- **Application Header:** `CFTP/1.0 200 OK COUNT=1 SIZE=142\r\n`
- **Payload Stream:** JSON array containing file metadata.
- **Framing Observation:** Observe how the header is cleanly separated from the JSON payload by `0d 0a` (`\r\n`).

#### PUT Handshake & File Transfer
1. **PUT Request:** `CFTP/1.0 PUT sample.txt SIZE=200 CHECKSUM=...`
2. **Server Admission:** `CFTP/1.0 200 OK READY_FOR_DATA`
3. **Data Segment(s):** The raw bytes of the file are transmitted.
4. **Completion ACK:** `CFTP/1.0 200 OK TRANSFER_COMPLETE CHECKSUM=...`

---

### 3.3 TCP Stream Segmentation vs. CFTP Framing

#### The Difference:
- **TCP Segment Size:** Over loopback interfaces, the Maximum Transmission Unit (MTU) is typically 65,535 bytes; over Ethernet, MTU is 1,500 bytes (MSS = 1,460 bytes).
- If a file is 5 MB, TCP splits the data into thousands of packets.
- **Academic Insight:** Notice that in Wireshark, the packet header says `TCP segment of a reassembled PDU`. The application never sees these individual packets; Python's `recv()` reads from a continuous byte stream. CFTP's explicit `SIZE=<bytes>` parameter tells the application exactly when the file stream has finished!

---

### 3.4 TCP 4-Way Connection Termination
When `QUIT` is issued, orderly termination is executed:

| Packet # | Source -> Destination | TCP Flags | Explanation |
|---|---|---|---|
| **N** | Client -> Server | `[PSH, ACK]` | Sends `CFTP/1.0 QUIT\r\n`. |
| **N+1**| Server -> Client | `[PSH, ACK]` | Sends `CFTP/1.0 200 OK GOODBYE\r\n`. |
| **N+2**| Client -> Server | `[FIN, ACK]` | Client closes write direction ($Seq = x$, $Ack = y$). |
| **N+3**| Server -> Client | `[ACK]` | Server acknowledges client's FIN. |
| **N+4**| Server -> Client | `[FIN, ACK]` | Server closes its write direction. |
| **N+5**| Client -> Server | `[ACK]` | Client acknowledges server's FIN. Connection `CLOSED`. |

---

## 4. Useful Wireshark Display Filters for CFTP

| Filter Expression | Purpose |
|---|---|
| `tcp.port == 9000` | Filters all packets to or from CFTP server port 9000. |
| `tcp.flags.syn == 1` | Isolates connection establishment handshakes. |
| `tcp.flags.fin == 1` | Isolates connection termination packets. |
| `tcp.flags.reset == 1` | Identifies connection resets (abrupt disconnects). |
| `tcp.len > 0` | Displays only packets that carry actual application payload. |
| `frame contains "CFTP/1.0"` | Shows all CFTP control protocol lines. |
| `frame contains "CHECKSUM"` | Isolates file integrity negotiation headers. |

---

## 5. How to Reconstruct Sessions (Follow TCP Stream)

1. Right-click any packet in the capture list.
2. Select **Follow** -> **TCP Stream**.
3. A dialog will open showing the complete reconstructed conversation:
   - **Client messages** appear in red.
   - **Server responses** appear in blue.
4. Verify that you can view the exact ASCII commands:
   ```text
   CFTP/1.0 LIST
   CFTP/1.0 200 OK COUNT=1 SIZE=115
   [ ... JSON file payload ... ]
   CFTP/1.0 QUIT
   CFTP/1.0 200 OK GOODBYE
   ```

---

## 6. Real-World Capture Storage

When saving captures for project review:
1. In Wireshark, click **File** -> **Save As...**.
2. Save the file in the `captures/` folder as:
   `captures/cftp_demo_session.pcapng`
3. This capture file can be shared with professors or examiners during your viva demonstration.
