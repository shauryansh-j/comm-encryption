# SecureFlex-Inspired Secure MAVLink Communication

## Complete implementation and testing procedure (Windows + Raspberry Pi 5)

**Project stage:** Software prototype before FPGA implementation\
**Current baseline:** Windows laptop sends MAVLink heartbeat messages
over Wi-Fi/UDP; Raspberry Pi 5 running Raspberry Pi OS Lite receives and
decodes them with `pymavlink`.

------------------------------------------------------------------------

## 1. Project objective

Extend the existing working MAVLink link so that messages are encrypted
and authenticated before transmission, verified before decoding,
monitored for faults, and handled by a controlled recovery state
machine.

The implementation is inspired by the SecureFlex-ASCON research paper,
but it is important to distinguish the software prototype from the
paper's FPGA implementation:

-   **Software prototype:** implements ASCON authenticated encryption,
    packet validation, replay protection, fault logging, software fault
    injection, and recovery/lockdown logic.
-   **Later FPGA stage:** implements the 320-bit Ascon permutation,
    parity predictors, linear-layer invariant, combinational output kill
    path, and hardware recovery controller.
-   Software tests do not prove resistance to physical voltage/clock
    glitches. Physical fault-injection testing is a separate future
    activity.

### Primary milestone

The Windows laptop sends an encrypted MAVLink heartbeat. The Raspberry
Pi authenticates and decrypts it, then passes the original MAVLink frame
to `pymavlink`. A modified, forged, replayed, or malformed packet must
never reach the MAVLink decoder.

------------------------------------------------------------------------

## 2. Existing system and target architecture

### Existing working system

``` text
Windows laptop
  Python + pymavlink transmitter
       |
       | MAVLink heartbeat in UDP datagram (currently plaintext)
       | Wi-Fi
       v
Raspberry Pi 5
  Python UDP receiver + pymavlink decoder
```

### Target software architecture

``` text
WINDOWS LAPTOP
  MAVLink message creation
        |
  Serialize complete MAVLink frame
        |
  ASCON-AEAD128 encryption + authentication
        |
  Secure packet framing
        |
  UDP over Wi-Fi
        |
        v
RASPBERRY PI 5
  UDP receive
        |
  Validate packet framing and size
        |
  Replay/session checks
        |
  ASCON-AEAD128 authentication + decryption
        |
  Reject on any authentication failure
        |
  Feed authenticated MAVLink bytes to pymavlink
        |
  Fault monitor + diagnostics + recovery state machine
```

The packet header should be authenticated as associated data (AAD), not
encrypted. The encrypted section contains the serialized MAVLink frame.
The authentication tag protects the ciphertext and AAD.

**Security rule:** Do not call the MAVLink parser with plaintext from a
packet until the ASCON authentication operation has succeeded.

------------------------------------------------------------------------

## 3. What is required?

### 3.1 Hardware

  -----------------------------------------------------------------------
  Item                    Purpose                 Required now?
  ----------------------- ----------------------- -----------------------
  Windows laptop          Runs transmitter and    Yes
                          test tools              

  Raspberry Pi 5          Runs receiver,          Yes
                          decryption and          
                          monitoring              

  Wi-Fi network/access    Carries UDP packets     Yes
  point                                           

  Power supply for Pi 5   Stable operation        Yes

  Ethernet cable          Optional reliable       No
                          setup/debug path        

  Pixhawk/autopilot       Later integration with  No
                          flight controller       

  FPGA development board  Later hardware          No
                          acceleration and        
                          parity-monitor          
                          implementation          
  -----------------------------------------------------------------------

No Pixhawk or FPGA is needed for the first software prototype.

### 3.2 Software

  -----------------------------------------------------------------------
  Software/library        Where                   Purpose
  ----------------------- ----------------------- -----------------------
  Raspberry Pi OS Lite    Raspberry Pi            Operating system

  Python 3                Both systems            Application runtime

  `pymavlink`             Both systems            MAVLink creation and
                                                  parsing

  Git                     Both systems            Source/version control

  ASCON-AEAD128           Both systems            Authenticated
  implementation                                  encryption

  `pytest`                Development systems     Automated tests

  `cryptography` or OS    Both systems            Secure random
  CSPRNG                                          key/session material
                                                  where appropriate

  Wireshark               Laptop (optional)       Verify that UDP
                                                  payloads are not
                                                  readable MAVLink

  `tcpdump`               Pi (optional)           Packet capture and
                                                  debugging
  -----------------------------------------------------------------------

Use the **finalized NIST Ascon-AEAD128 algorithm**, not an older Ascon
v1.2 implementation merely because it has a similar name. Confirm that
the selected implementation explicitly supports the NIST SP 800-232
version and passes its known-answer tests. Do not assume that a Python
package named `ascon` implements the finalized standard.

Suggested authoritative references:

-   NIST SP 800-232: https://csrc.nist.gov/pubs/sp/800/232/final
-   Official Ascon project and implementations: https://github.com/ascon
-   MAVLink 2 message/signing documentation:
    https://mavlink.io/en/guide/message_signing.html
-   `pymavlink`: https://github.com/ArduPilot/pymavlink

Before choosing a library, inspect its documentation, algorithm version,
maintenance status, API, licensing, and test-vector results. Pin the
exact version or commit in the project requirements.

### 3.3 Skills needed

-   Basic Python functions, classes and exception handling
-   UDP sockets and IP/port configuration
-   MAVLink frame serialization and parsing
-   Basic cryptography concepts: key, nonce, ciphertext, tag, AAD
-   Basic state-machine logic
-   Linux SSH and package management
-   Test design and measurement

------------------------------------------------------------------------

## 4. Security design decisions

Decide these before writing the secure transport code.

### 4.1 Algorithm and parameters

Use **Ascon-AEAD128 as specified in NIST SP 800-232**.

Its standard parameters include:

-   Key: 128 bits (16 bytes)
-   Nonce: 128 bits (16 bytes)
-   Authentication tag: 128 bits (16 bytes)

The implementation/library API may represent the tag separately or
append it to the ciphertext. Follow the selected implementation's
documented API exactly.

Do not use a home-grown cipher, custom S-box, or custom cryptographic
mode. Do not modify the Ascon algorithm.

### 4.2 Key management

For the first controlled lab prototype:

1.  Generate a random 16-byte key using a cryptographically secure
    random generator.
2.  Provision the same key to Windows and the Pi through a secure,
    out-of-band method.
3.  Do not send the key in UDP packets.
4.  Do not commit keys to Git.
5.  Restrict the key file's permissions on the Pi (for example, readable
    only by the service account).
6.  Keep a separate test key for automated tests.
7.  Have a documented procedure to replace/revoke a key.

A hard-coded demonstration key is acceptable only for a disposable local
test, never for field deployment. A production design needs
authenticated provisioning, key rotation, secure storage, and a defined
recovery process.

### 4.3 Nonce uniqueness

A nonce must never repeat with the same key. Reuse can severely
undermine AEAD security.

For the prototype, use a documented session-and-counter construction
that guarantees uniqueness across sender restarts and concurrent
senders. One possible design is a unique per-session value combined with
a monotonically increasing counter, with the exact 16-byte encoding
reviewed before implementation.

Requirements:

-   Never reset a counter while reusing the same session/key
    combination.
-   Never wrap the counter.
-   Persist counter/session state safely or establish a fresh unique
    session value before sending.
-   Do not rely on a random 128-bit nonce without assessing collision
    probability and restart behavior.
-   Reject duplicate and stale packet counters at the receiver.
-   If sender state is lost or nonce uniqueness is uncertain, rotate to
    a fresh key/session before resuming.

The packet counter is also useful for replay detection, but nonce
uniqueness and replay policy are related yet distinct requirements.

### 4.4 Replay protection

Authentication alone does not prevent an attacker from recording and
replaying a previously valid packet.

Include a session identifier and sequence counter in the authenticated
header. The receiver should maintain replay state per authenticated
sender/session and reject:

-   Duplicate counters
-   Counters older than the permitted receive window
-   Packets from expired sessions
-   Unexpected session changes

For a simple single-sender heartbeat prototype, strict monotonically
increasing counters may be sufficient. If packets can arrive out of
order, use a bounded sliding replay window instead.

### 4.5 Sender identity

MAVLink system ID and component ID are identifiers, not proof of
identity. Authenticate the secure transport packet with the key and bind
the expected sender/session information into the authenticated header.
After decryption, validate the MAVLink system/component IDs against the
configured policy.

### 4.6 MAVLink 2 signing

MAVLink 2 signing authenticates messages and provides replay-related
protections, but it does **not encrypt** message contents. ASCON-AEAD128
provides confidentiality and authentication at the secure transport
layer.

Do not assume the two mechanisms are interchangeable. Initially,
implement and test ASCON transport security. Later decide whether
MAVLink signing should also be enabled, ensuring timestamp/key handling
and verification are consistent.

------------------------------------------------------------------------

## 5. Define the secure UDP packet format

Use a versioned, explicitly encoded binary format. Do not serialize a
Python dictionary with `repr()` or use unsafe `pickle`.

A proposed logical format:

  Field                 Example size Purpose
  ------------------- -------------- -----------------------------------
  Magic                      2 bytes Identifies this protocol
  Version                     1 byte Protocol version
  Flags                       1 byte Reserved/defined flags
  Sender ID                   1 byte Configured secure sender identity
  Session ID                 8 bytes Distinguishes sender sessions
  Packet counter             8 bytes Sequence and replay tracking
  Nonce                     16 bytes Ascon nonce
  Ciphertext length          2 bytes Length validation
  Ciphertext                Variable Serialized MAVLink frame
  Tag                       16 bytes Authentication tag

This is a **proposed project framing**, not a NIST-defined packet
format. Confirm field widths and byte order in a protocol specification
before coding.

Recommended rules:

-   Encode integers in network byte order (big-endian).
-   Set strict maximum datagram and ciphertext lengths.
-   Authenticate the complete fixed header (excluding fields that cannot
    safely be included, such as the tag itself) as AAD.
-   Verify that the declared ciphertext length exactly matches the
    received packet length.
-   Reject unknown protocol versions and unsupported flags.
-   Never trust a sender ID or length merely because it appears in the
    header.
-   Use the same canonical header bytes for encryption and decryption
    AAD.

A packet counter or session ID may be visible in the header;
confidentiality of those fields is not required, but their integrity is.

------------------------------------------------------------------------

## 6. Recommended project folder structure

Create one shared repository, with separate sender and receiver
programs.

``` text
SecureFlex-MAVLink/
├── README.md
├── requirements-windows.txt
├── requirements-pi.txt
├── .gitignore
├── config/
│   ├── config.example.toml
│   └── README-key-provisioning.md
├── common/
│   ├── packet_format.py
│   ├── protocol_constants.py
│   ├── nonce_manager.py
│   └── replay_window.py
├── crypto/
│   ├── ascon_adapter.py
│   └── known_answer_tests/
├── windows/
│   ├── mavlink_sender.py
│   └── secure_transmitter.py
├── raspberry_pi/
│   ├── secure_receiver.py
│   ├── mavlink_decoder.py
│   ├── fault_monitor.py
│   ├── fault_localizer.py
│   ├── recovery_fsm.py
│   └── service/
├── tests/
│   ├── test_ascon_vectors.py
│   ├── test_packet_format.py
│   ├── test_tampering.py
│   ├── test_replay.py
│   ├── test_fault_monitor.py
│   ├── test_recovery_fsm.py
│   └── test_end_to_end.py
├── experiments/
│   ├── run_performance.py
│   ├── run_fault_campaign.py
│   └── results/
└── logs/
```

Keep secrets, generated keys, private logs, virtual environments, and
packet captures out of Git. Add them to `.gitignore`.

------------------------------------------------------------------------

## 7. Phase 0 --- Preserve and document the working baseline

Before changing the working transmitter or receiver:

1.  Copy the existing Windows transmitter and Pi receiver into a
    `baseline/` backup directory or a separate Git commit.
2.  Record the current IP addresses and UDP port.
3.  Record how the receiver binds its socket and how the sender selects
    the destination.
4.  Record the current heartbeat rate and MAVLink dialect.
5.  Run the current unencrypted link for at least several minutes.
6.  Confirm that the Pi receives and decodes heartbeats consistently.
7.  Save the console output and baseline measurements.

Create a baseline table:

  Metric               Baseline result
  -------------------- -----------------
  Sender IP            To be recorded
  Pi IP                To be recorded
  UDP port             To be recorded
  Heartbeat rate       To be measured
  Packets sent         To be measured
  Packets received     To be measured
  Packet loss          To be measured
  Average latency      To be measured
  Pi CPU utilization   To be measured

Do not proceed until the original link still works from the backup.

------------------------------------------------------------------------

## 8. Phase 1 --- Prepare both systems

### 8.1 Windows laptop

Open PowerShell and check:

``` powershell
python --version
git --version
```

Create and activate a virtual environment in the project directory:

``` powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

Install the project's pinned Python dependencies after selecting and
verifying the NIST-compatible Ascon implementation:

``` powershell
python -m pip install -r requirements-windows.txt
```

Install `pymavlink` and `pytest` through the requirements file. Do not
install an unverified package simply because its name contains "ascon".

### 8.2 Raspberry Pi 5

Connect using SSH and check:

``` bash
python3 --version
git --version
```

Create a project directory and virtual environment:

``` bash
mkdir -p ~/SecureFlex-MAVLink
cd ~/SecureFlex-MAVLink
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

Install pinned dependencies:

``` bash
python -m pip install -r requirements-pi.txt
```

If the chosen Ascon implementation is a C library with Python bindings,
follow its official build instructions on both Windows and Raspberry Pi.
Confirm the same standard algorithm and test vectors on both platforms.

### 8.3 Network checks

On the Pi:

``` bash
hostname -I
```

On Windows:

``` powershell
ipconfig
```

Confirm both systems are on a network that permits the selected UDP
traffic. Configure the firewall to allow only the required UDP port
between the two devices. Do not expose the test receiver to the public
internet.

------------------------------------------------------------------------

## 9. Phase 2 --- Validate the cryptographic implementation independently

Do not integrate encryption into MAVLink immediately.

First build a small independent test program that:

1.  Loads a test key.
2.  Uses a test nonce.
3.  Encrypts a known plaintext with Ascon-AEAD128.
4.  Decrypts it.
5.  Confirms the recovered plaintext is identical.
6.  Changes one ciphertext bit and confirms authentication fails.
7.  Changes one AAD bit and confirms authentication fails.
8.  Changes one tag bit and confirms authentication fails.
9.  Tries the wrong key and confirms authentication fails.

### Mandatory checks

-   Run the official NIST Ascon-AEAD128 known-answer test vectors.
-   Confirm the same test vectors pass on Windows and Raspberry Pi.
-   Confirm the implementation is the finalized SP 800-232 version.
-   Confirm the API rejects an invalid tag and does not return usable
    plaintext.
-   Confirm keys, nonces and tags have the expected lengths.

Never write your own cryptographic primitive for this project. Use a
reviewed implementation.

**Pass condition:** Both systems pass the same known-answer tests and
all negative authentication tests.

------------------------------------------------------------------------

## 10. Phase 3 --- Implement the secure packet transport

Create shared packet-format code and an Ascon adapter.

### Windows sender workflow

1.  Generate a MAVLink heartbeat using `pymavlink`.
2.  Serialize the complete MAVLink message to bytes.
3.  Allocate a unique session/counter and construct the nonce.
4.  Construct the canonical secure header.
5.  Use the header as authenticated associated data.
6.  Encrypt/authenticate the MAVLink frame using Ascon-AEAD128.
7.  Assemble header, nonce, ciphertext and tag.
8.  Send the resulting binary packet over UDP.

### Raspberry Pi receiver workflow

1.  Receive the UDP datagram.
2.  Check minimum and maximum packet size.
3.  Parse the fixed header without trusting its values.
4.  Check protocol magic, version, flags and declared lengths.
5.  Check sender/session policy and replay state.
6.  Reconstruct the exact AAD bytes.
7.  Verify and decrypt using Ascon-AEAD128.
8.  If authentication fails, discard the packet and log a security
    event.
9.  If authentication succeeds, commit the replay counter.
10. Feed the authenticated MAVLink frame bytes to the MAVLink parser.
11. Validate the decoded message type and configured system/component
    IDs.

**Ordering matters:** do not update replay state or forward a message
until the required authentication and policy checks have succeeded.
Handle concurrent packets safely so that two copies of the same counter
cannot both be accepted.

### MAVLink parsing

Use the supported `pymavlink` byte-stream parsing interface. Do not
assume that one UDP datagram always equals one complete MAVLink frame.
Preserve parser buffering semantics and test fragmented, concatenated
and malformed frame cases.

### Phase 3 pass condition

The Pi displays the original heartbeat information only after successful
authentication. A packet with an invalid tag is rejected before MAVLink
decoding.

------------------------------------------------------------------------

## 11. Phase 4 --- Implement fault detection and localization

The software monitor should record events in a structured format.

### Fault categories

  Fault category                   Detection method
  -------------------------------- ------------------------------------
  Invalid packet framing           Header/magic/length validation
  Unsupported version              Version validation
  Authentication failure           Ascon tag verification
  Replay attempt                   Session/counter tracking
  Unexpected sender                Sender/session policy
  Invalid MAVLink frame            MAVLink parser/validation result
  Heartbeat timeout                Monotonic receive-time tracking
  Internal software error          Exception and health monitoring
  Software-model parity mismatch   Ascon model fault-injection checks

### Fault record

Each event should include:

-   Timestamp
-   Event ID
-   Sender/session identifier (if safely available)
-   Packet counter (if safely available)
-   Fault category
-   Verification stage
-   Action taken
-   Recovery state

Do not log encryption keys, plaintext flight commands, or other secrets.
Treat unverified header fields as attacker-controlled data in logs.

### Fault localization

In the software prototype, localization means identifying the stage and
type of failure, for example:

-   Header validation
-   Session validation
-   Replay detection
-   Authentication verification
-   MAVLink parsing
-   Communication timeout
-   Internal software monitor

This is software-level localization. It does not identify an exact FPGA
S-box slice. Exact round/layer/slice localization requires instrumenting
the Ascon permutation implementation and injecting faults into its
internal state or intermediate values.

------------------------------------------------------------------------

## 12. Phase 5 --- Implement a recovery state machine

Implement a documented finite-state machine inspired by the paper.

Suggested software states:

  -----------------------------------------------------------------------
  State                               Meaning
  ----------------------------------- -----------------------------------
  IDLE                                Waiting for an authenticated
                                      session

  RUN                                 Normal packet reception

  SUSPECT                             A fault or policy violation has
                                      occurred

  HALT                                Stop forwarding packets to the
                                      MAVLink application

  RECOVER                             Re-establish or validate the
                                      communication session

  WAIT                                Wait for a valid authenticated
                                      packet/heartbeat

  RECOVERED                           Communication restored

  LOCK                                Communication disabled pending
                                      authorized reset/re-provisioning
  -----------------------------------------------------------------------

### Suggested transition logic

``` text
IDLE -> RUN
RUN -> SUSPECT       on invalid packet or timeout
SUSPECT -> HALT      when policy requires isolation
HALT -> RECOVER      when recovery is permitted
RECOVER -> WAIT      after fresh session establishment
WAIT -> RECOVERED    after successful authenticated validation
RECOVERED -> RUN     after recovery checks pass
Any state -> LOCK    after configured persistent-failure threshold
```

### Safety requirements

-   An invalid tag is always rejected; never retry by accepting
    unauthenticated plaintext.
-   Retransmission must use a fresh nonce and a new packet counter.
-   Never re-encrypt different plaintext with a previously used
    nonce/key pair.
-   Do not automatically replay flight-control commands after a
    communication failure.
-   For the initial heartbeat-only demonstration, recovery can restart
    the secure heartbeat session.
-   Require an authorized operator action or defined secure
    re-provisioning process to leave LOCK.
-   Keep a diagnostic record of the first fault; later faults should not
    silently overwrite it.
-   Use monotonic time for timeout calculations.

The paper's two-cycle hardware state scrub does not directly translate
to a Python process. In software, recovery should clear session/replay
state as appropriate, establish a fresh secure session, and preserve
audit logs. Do not claim that this is equivalent to clearing a 320-bit
hardware register bank.

------------------------------------------------------------------------

## 13. Phase 6 --- Software fault injection

Build a separate test-only fault injector. It should never be enabled in
normal operation.

Inject controlled faults at different points:

### Network/packet tests

1.  Flip a bit in the ciphertext.
2.  Flip a bit in the authentication tag.
3.  Flip a bit in the authenticated header.
4.  Truncate a datagram.
5.  Append extra bytes.
6.  Send a duplicate valid datagram.
7.  Replay an old valid datagram.
8.  Send an unsupported protocol version.
9.  Send random bytes.
10. Send a packet from an unapproved sender/session.

Expected result: reject the packet, record the appropriate fault, and
never pass unauthenticated bytes to `pymavlink`.

### Ascon software-model tests

To reproduce the paper's parity experiments at a software level:

1.  Instrument a reference Ascon permutation implementation in a
    test-only environment.
2.  Identify the relevant S-box input/output slices and linear-layer
    boundaries.
3.  Implement the paper's parity predictor and linear word-parity
    invariant exactly as described.
4.  Inject single-bit and multi-bit XOR masks at the specified
    intermediate points.
5.  Record injected faults, detected faults and missed faults.
6.  Compare measured results against the expected parity properties.

The paper reports 320/320 single-bit S-box output faults detected and
10,314/20,000 random five-bit masks detected (51.57%) in its RTL
simulation. Those are paper-specific results, not guaranteed outcomes
for a separately written software model. Match the fault injection point
and model precisely before comparing results.

Do not use ordinary ciphertext tampering tests as a substitute for S-box
fault-injection experiments: they test different layers and different
properties.

------------------------------------------------------------------------

## 14. Phase 7 --- Performance evaluation

Measure the original unencrypted link first, then the encrypted link,
then the full monitored/recovery version.

### Measurements

  -----------------------------------------------------------------------
  Metric                              Measurement method
  ----------------------------------- -----------------------------------
  Encryption latency                  Time around the AEAD encryption
                                      call

  Decryption/authentication latency   Time around the AEAD open/verify
                                      call

  End-to-end latency                  Sender timestamp and receiver
                                      timestamp, with clock
                                      synchronization or a round-trip
                                      measurement

  Throughput                          Successfully authenticated payload
                                      bytes per second

  Packet delivery ratio               Accepted packets divided by sent
                                      packets

  Authentication failure count        Security monitor counters

  Replay rejection count              Replay monitor counters

  Recovery time                       Time from fault detection to safe
                                      resumed operation

  CPU utilization                     Linux `top`, `htop` or process
                                      metrics

  Memory usage                        Process RSS or system monitoring

  Packet overhead                     Secure packet size minus original
                                      MAVLink frame size
  -----------------------------------------------------------------------

Use monotonic high-resolution timers for local durations. Do not
subtract timestamps from unsynchronized Windows and Pi clocks and call
the result one-way latency. For reliable one-way latency, synchronize
clocks and report the synchronization uncertainty; alternatively measure
round-trip time.

Run repeated trials under the same Wi-Fi conditions and report sample
count, mean, median, percentiles and packet-loss rate.

### Comparison table to complete

  Metric                        Plain MAVLink   ASCON only   ASCON + monitor/FDIR
  --------------------------- --------------- ------------ ----------------------
  Average encryption time                 N/A   To measure             To measure
  Average verification time               N/A   To measure             To measure
  End-to-end latency               To measure   To measure             To measure
  Throughput                       To measure   To measure             To measure
  CPU utilization on Pi            To measure   To measure             To measure
  Memory usage                     To measure   To measure             To measure
  Packet overhead                    Baseline   To measure             To measure
  Recovery time                           N/A          N/A             To measure

Do not fill these cells with estimates. Record actual measured results.

------------------------------------------------------------------------

## 15. Phase 8 --- End-to-end acceptance tests

The software prototype should not be considered complete until it passes
the following tests.

  -----------------------------------------------------------------------
  Test                                Expected result
  ----------------------------------- -----------------------------------
  Valid heartbeat                     Authenticated and decoded

  Wrong key                           Rejected

  Modified ciphertext                 Rejected

  Modified tag                        Rejected

  Modified AAD/header                 Rejected

  Duplicate packet                    Rejected

  Old session packet                  Rejected

  Invalid packet length               Rejected

  Random UDP payload                  Rejected

  Invalid MAVLink frame after valid   Parser rejects/records it
  authentication                      

  Temporary Wi-Fi interruption        Safe timeout and controlled
                                      recovery

  Repeated invalid packets            Configured lockdown

  Valid new session after authorized  Communication resumes
  recovery                            

  Normal traffic during test campaign No unauthenticated data forwarded
  -----------------------------------------------------------------------

Also verify that a packet rejected by authentication never reaches the
MAVLink parser. This is a critical security acceptance test.

------------------------------------------------------------------------

## 16. Suggested development schedule

A reasonable first prototype plan:

  -----------------------------------------------------------------------
  Work package                        Main deliverable
  ----------------------------------- -----------------------------------
  1\. Baseline and setup              Existing link documented and backed
                                      up

  2\. Cryptographic selection         NIST-compatible implementation
                                      selected and test vectors pass

  3\. Secure framing                  Versioned packet format and
                                      nonce/session design

  4\. Encrypted transport             Windows-to-Pi encrypted heartbeat
                                      works

  5\. Security monitor                Authentication, replay and
                                      malformed-packet events

  6\. Recovery FSM                    Controlled recovery and lockdown

  7\. Fault campaign                  Automated tampering/replay/model
                                      fault tests

  8\. Performance evaluation          Baseline-versus-protected
                                      measurements

  9\. Documentation                   Architecture, methods, results,
                                      limitations and logs
  -----------------------------------------------------------------------

The exact duration depends on the chosen Ascon library, the current code
quality, and whether a native C implementation or Python implementation
is used.

------------------------------------------------------------------------

## 17. What should be delivered at the end of the software stage?

### Code deliverables

-   Windows secure MAVLink transmitter
-   Raspberry Pi secure MAVLink receiver
-   Shared packet-format module
-   Ascon adapter
-   Nonce/session manager
-   Replay protection module
-   Fault monitor and localizer
-   Recovery FSM
-   Test-only fault injector
-   Automated test suite
-   Performance measurement scripts

### Research/documentation deliverables

1.  System architecture diagram
2.  Threat model and assumptions
3.  Secure packet format specification
4.  Ascon version and implementation details
5.  Key and nonce management design
6.  Fault taxonomy and detection methods
7.  Recovery state-transition diagram
8.  Test methodology
9.  Fault-injection results
10. Performance comparison
11. Security limitations
12. FPGA migration plan

------------------------------------------------------------------------

## 18. What can be carried forward to FPGA?

Once the software prototype is validated, divide the design into
software and hardware responsibilities.

  -----------------------------------------------------------------------
  Function                Software on Pi          Potential FPGA
                                                  implementation
  ----------------------- ----------------------- -----------------------
  MAVLink                 Yes                     Usually no
  generation/parsing                              

  Wi-Fi/UDP networking    Yes                     No

  Key                     Yes                     Supporting logic
  provisioning/session                            possible
  management                                      

  Ascon-AEAD128           Initially yes           Yes

  S-box parity prediction Software model          Yes

  Linear-layer parity     Software model          Yes
  invariant                                       

  Fault localization      Yes                     Yes

  Immediate combinational Software gate only      Yes
  output clamp            approximates it         

  Recovery controller     Yes                     Yes

  Logs/dashboard          Yes                     Usually no
  -----------------------------------------------------------------------

The FPGA implementation should use a reviewed, standard-compliant
Ascon-AEAD128 datapath. The SecureFlex parity and recovery logic can be
integrated around it.

The Pi can remain responsible for networking, MAVLink handling, system
management and logs.

------------------------------------------------------------------------

## 19. Important project limitations and safety notes

1.  This prototype is a research demonstrator, not a certified
    flight-control security product.
2.  Test initially with heartbeat messages only. Do not connect it to
    active flight-control commands until the complete safety and
    recovery behavior has been reviewed.
3.  Do not allow a security failure to trigger unsafe flight actions.
    Define the autopilot's failsafe behavior separately.
4.  ASCON authentication does not automatically solve key provisioning,
    device identity, replay policy, denial of service, or compromised
    endpoint security.
5.  A compromised Windows laptop or Raspberry Pi can expose keys or
    plaintext.
6.  Wi-Fi jamming and packet dropping cannot be solved by encryption
    alone.
7.  Software parity simulation does not establish physical glitch
    resistance.
8.  SecureFlex's reported results must not be presented as results
    obtained by this project.
9.  Clearly label measured results, simulated results, and proposed
    future work separately.

------------------------------------------------------------------------

## 20. Final implementation checklist

Use this checklist to track completion.

### Setup

-   [ ] Back up the existing working transmitter and receiver.
-   [ ] Record IP addresses, UDP port and heartbeat rate.
-   [ ] Create the shared repository and folder structure.
-   [ ] Create Python virtual environments on Windows and Pi.
-   [ ] Select and pin an NIST SP 800-232-compatible Ascon
    implementation.

### Cryptography

-   [ ] Pass official Ascon-AEAD128 known-answer tests.
-   [ ] Generate and provision a test key securely.
-   [ ] Define a unique nonce/session strategy.
-   [ ] Define the authenticated packet header.
-   [ ] Test valid decryption.
-   [ ] Test wrong-key and tampering rejection.

### Secure MAVLink

-   [ ] Serialize MAVLink frames before encryption.
-   [ ] Encrypt on Windows.
-   [ ] Send binary secure packets over UDP.
-   [ ] Authenticate and decrypt on Pi.
-   [ ] Enforce replay protection.
-   [ ] Pass only authenticated plaintext to `pymavlink`.

### Fault handling

-   [ ] Implement fault categories and structured logs.
-   [ ] Implement fault localization at the software stage.
-   [ ] Implement recovery FSM.
-   [ ] Implement persistent-failure lockdown.
-   [ ] Verify no invalid packet reaches the MAVLink application.

### Testing

-   [ ] Run packet tampering tests.
-   [ ] Run replay and duplicate tests.
-   [ ] Run malformed packet tests.
-   [ ] Run Ascon software-model fault tests.
-   [ ] Run recovery tests.
-   [ ] Measure performance and overhead.
-   [ ] Document limitations and results.

### Before FPGA

-   [ ] Software prototype passes acceptance tests.
-   [ ] Architecture and interfaces are documented.
-   [ ] Standard-compliant Ascon implementation is identified for RTL.
-   [ ] FPGA parity and recovery logic are specified.
-   [ ] Physical fault-injection validation is planned.

------------------------------------------------------------------------

## 21. Immediate next action

Do these things first:

1.  Back up your existing Windows transmitter and Raspberry Pi receiver.
2.  Upload both Python files for review.
3.  Record the UDP port and current IP configuration.
4.  Select the NIST-compatible Ascon implementation and validate it
    independently before modifying MAVLink transport.

**Do not start by adding encryption directly into the existing
scripts.** First validate the cryptographic implementation, nonce
strategy and packet format independently. Then integrate them into the
working communication link.

The first successful milestone is:

**Windows → MAVLink serialization → ASCON-AEAD128 → UDP/Wi-Fi → Pi
authentication/decryption → pymavlink decoding.**
