# SYN Cookie Implementation for `smoltcp`

## 1. Introduction
This document describes the implementation of SYN cookies in `smoltcp` to mitigate SYN flood attacks. The implementation introduces an opt-in `use_syncookie` option on TCP sockets. When enabled, the socket handles incoming SYN packets statelessly while in the `LISTEN` state, bypassing the transition to `SYN-RECEIVED` and avoiding socket exhaustion.

## 2. Current Architecture & Configuration
A new configuration method and getter are provided on `Socket`:
- **`Socket::set_use_syncookie(&mut self, value: bool)`**: Enables or disables SYN cookie usage for the socket.
- **`Socket::use_syncookie(&self) -> bool`**: Returns the current SYN cookie setting.

By default, `use_syncookie` is set to `false`.

## 3. Stateless SYN Handling (The `LISTEN` State)
When a socket is in `State::Listen` and `use_syncookie` is enabled:
### 3.1 SYN Processing
- Upon receiving a pure `SYN` packet in `process()`, the socket does **NOT** update its `tuple` (source/destination IPs and ports) and does **NOT** transition to `State::SynReceived`.
- It constructs a `SYN|ACK` reply using `Self::reply`.
- The `SYN|ACK` reply is stored temporarily in a new internal socket field: `self.synack_to_reply`.
- The Initial Sequence Number (ISN) for the reply is generated deterministically using the **SipHash-1-3** cryptographic mixer, incorporating:
  - Source IP Address
  - Destination IP Address
  - Source Port
  - Destination Port
  - A 5-bit rotating timestamp counter (derived from `cx.now()`, incrementing every 64 seconds)
  - A 128-bit secret key initialized once on interface creation (`cx.syncookie_secret`)
- **Note**: In the current implementation, `self.synack_to_reply` is consumed and emitted in the subsequent `dispatch()` call.

### 3.2 Option Encoding
Instead of storing connection options (MSS, Window Scale, SACK permissions) in socket memory, they are encoded into a single 8-bit integer and transmitted to the client via the TCP Timestamp option (`tsval`):
- **Bit 0**: `SACK-PERMITTED` (1 bit)
- **Bits 1-4**: `WINDOW-SCALE` (4 bits, values 0-14, where 15 indicates `None`)
- **Bits 5-7**: `MAX-SEGMENT-SIZE` index (3 bits), mapped from a predefined table of common MSS values: `[536, 1300, 1400, 1440, 1460, 1480, 1500, 9000]`.

This 8-bit encoded value is placed in the **lowest 8 bits** of the `tsval` field of the emitted `SYN|ACK` reply, provided TCP Timestamps are supported and present in the client's SYN.

## 4. ACK Validation & Connection Establishment
When the client replies with the final `ACK` of the 3-way handshake:
### 4.1 Acceptance Filter
- The `accepts()` method is modified to allow incoming `ACK` packets to be processed by a socket in `State::Listen` when `use_syncookie` is enabled, rather than rejecting them immediately.

### 4.2 Cookie Validation and Restoration
- In `process()`, the arriving `ACK` is matched in the `(State::Listen, TcpControl::None, Some(ack_number))` branch.
- **ISN Validation**: The `ack_number - 1` (extracted ISN) is validated by recomputing the SipHash-1-3 output using the incoming packet's 4-tuple and the extracted 5-bit timestamp counter encoded in the highest bits of the ISN. Validation checks the counter against a safe time-window relative to the current system time to prevent replay attacks.
- If validation succeeds, the `tuple` is populated with the connection's 4-tuple.
- **Option Decoding**: If the incoming `ACK` contains a TCP Timestamp, the **lowest 8 bits of `tsecr`** are decoded using `decode_syncookie_options` to restore the negotiated MSS, Window Scale, and SACK permissions. If no timestamp is present, default values are used.
- The socket sequence numbers are restored (`local_seq_no` from `ack_number`, `remote_seq_no` from the ACK's sequence number).
- The socket transitions directly to `State::Established`.

## 5. Architectural Impact & Limitations
- **TCP Timestamps Dependency**: The current implementation relies on TCP Timestamps to preserve negotiated options (MSS, WS, SACK) statelessly. Without timestamps, these options revert to safe defaults upon connection establishment.
