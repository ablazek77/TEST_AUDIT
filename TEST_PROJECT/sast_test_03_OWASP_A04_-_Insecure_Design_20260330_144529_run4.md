# SAST Test Result: OWASP A04 - Insecure Design ✅

**Run ID:** 4  
**Status:** completed  
**Tokens used:** 9,537  

*Checks for architectural and design weaknesses that lead to security risks.*

---

## Findings

# SAST Analysis: OWASP A04 - Insecure Design

## Summary

This codebase is an **Arduino/embedded firmware project** that acts as an IR (infrared) remote control filter for a Dimplex electric fireplace. It receives IR signals, filters out unwanted commands (e.g., from an LG TV remote that accidentally triggers the fireplace), and retransmits valid commands.

## Findings

### 1. Insufficient IR Command Filtering — Bypass via Raw/Unknown Protocol

- **File:** `IRRemoteFilter.ino`, lines 127–140
- **Severity:** Medium
- **Description:** The filtering logic in `programState == 3` only checks `numberOfBits`, the hex suffix `"ff00"`, `address==4` (LG TV), and `command==70` (power button lock). However, when the protocol is `UNKNOWN`, the `sendCode()` function (line 183) sends the raw IR data without any filtering on the raw content. An attacker with a custom IR transmitter could craft raw signals that pass the bit-length check but carry unintended commands to the fireplace. The filter relies on decoded protocol fields which may not be populated correctly for edge-case or malformed signals.
- **Impact:** An attacker with physical proximity could craft IR signals that bypass the filtering logic and control the electric fireplace (turn it on/off, change heat settings), which poses a **physical safety risk** (fire hazard from unattended activation of a heating device).
- **Remediation:** Implement an allowlist approach — only forward explicitly recognized and permitted commands rather than blocking known-bad ones. Validate raw data payloads as well.

```cpp
// Recommended: allowlist approach instead of blocklist
if (programState == 3) {
    filter = 1; // Default: block everything
    
    // Only allow known Dimplex commands
    if (sStoredIRData.receivedIRData.numberOfBits == 32 &&
        sStoredIRData.receivedIRData.address == 0x00 &&
        rawIRData.substring(4) == "ff00") {
        // Allowlist specific known Dimplex commands
        uint8_t cmd = sStoredIRData.receivedIRData.command;
        if (cmd == 0x46 || cmd == 0x44 || cmd == 0x43 || 
            cmd == 0x07 || cmd == 0x09 || cmd == 0x16 || 
            cmd == 0x0D || cmd == 0x18) {
            filter = 0; // Allow only known Dimplex commands
        }
    }
    // Block unknown protocols entirely
    if (sStoredIRData.receivedIRData.protocol == UNKNOWN) {
        filter = 1;
    }
    // ...
}
```

### 2. Weak Power Button Replay Protection (Race Condition)

- **File:** `IRRemoteFilter.ino`, lines 103–106 and 153–155
- **Severity:** Low
- **Description:** The `POWER_DELAY_LOCK` mechanism is intended to prevent rapid repeated power toggling (command 70). However, the lock countdown (`POWER_DELAY_LOCK--`) only decrements within the timeout window when `timeOut < INIT_REPEAT_DELAY_TIME` (line 103). The lock value is set to `POWER_COMMAND_DELAY` (600) after a power command is sent, but the decrement is tied to a 1ms delay loop that only runs during the receive-wait state. This means the lock can be circumvented by timing attacks — sending a power command immediately after the device returns to `programState == 0`, before the lock has fully counted down in a subsequent cycle.
- **Impact:** Rapid toggling of the fireplace power, which is a safety concern for an electric heating appliance.
- **Remediation:** Use `millis()` for time-based lockout instead of a loop counter, ensuring the lock is independent of program state transitions.

```cpp
static unsigned long lastPowerCommandTime = 0;
const unsigned long POWER_LOCKOUT_MS = 600;

// In programState == 3:
if (sStoredIRData.receivedIRData.command == 70) {
    if (millis() - lastPowerCommandTime < POWER_LOCKOUT_MS) {
        filter = 1;
    }
}

// In programState == 4, after sending:
if (sStoredIRData.receivedIRData.command == 70) {
    lastPowerCommandTime = millis();
}
```

### 3. No Authentication on IR Command Relay

- **File:** `IRRemoteFilter.ino`, entire `loop()` function
- **Severity:** Low
- **Description:** The device acts as a transparent relay for any IR signal that passes the basic filter. There is no cryptographic authentication or challenge-response mechanism to verify that commands originate from the legitimate Dimplex remote. Any device capable of transmitting NEC protocol IR signals with address `0x00` and the `ff00` suffix can control the fireplace through this filter.
- **Impact:** Anyone with physical proximity and a programmable IR transmitter can control the fireplace. This is inherent to the IR protocol but worth noting as a design limitation.
- **Remediation:** This is a limitation of the IR protocol used by Dimplex. Consider adding a physical enable/disable switch on the Arduino device, or implementing time-of-day restrictions for power commands as an additional safety layer.

---

## Not Applicable

The following OWASP A04 checks are **not applicable** to this embedded firmware project:
- **Rate limiting on login/password reset/OTP** — No authentication system present
- **Account lockout** — No user accounts
- **Multi-factor authentication** — Not applicable to IR relay
- **Remember me tokens** — No session management
- **Price manipulation / negative quantities** — No e-commerce logic
- **Client-side validation trust** — No client-server architecture

---

*Report generated by Lithium Argon AI-powered SAST Service*