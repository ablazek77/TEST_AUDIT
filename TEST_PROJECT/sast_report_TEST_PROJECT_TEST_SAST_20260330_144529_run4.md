# SAST Security Report

**Customer:** TEST CUSTOMER  
**Project:** TEST PROJECT  
**Repository:** TEST_SAST  
**Branch:** upload  
**Run ID:** 4  
**Generated:** 2026-03-30 14:42:52 UTC  
**Triggered by:** manual  

---

## Executive Summary

This report contains the results of 3 automated security test(s) performed on the anonymized source code.

| Metric | Value |
|--------|-------|
| Total Tests | 3 |
| Completed | 3 |
| Failed | 0 |
| Total AI Tokens Used | 27,863 |

---

## Test Results

### 1. OWASP A03 - Injection ✅

*Checks for SQL injection, command injection, LDAP injection and other injection attacks.*

**Status:** completed  
**Tokens used:** 8,778  

#### Findings

# SAST Analysis: OWASP A03 - Injection Vulnerabilities

## Result: No Injection Vulnerabilities Found

After thorough analysis of the provided source code, **no injection vulnerabilities were identified**.

### Analysis Summary

This is an Arduino/embedded systems project (IR remote signal filter) written in C/C++ for microcontroller platforms. The codebase consists of:

- **`IRRemoteFilter.ino`** – Main Arduino sketch that receives, filters, and retransmits IR signals
- **`PinDefinitionsAndMore.h`** – Pin configuration header with preprocessor definitions
- **`IRRemoteFilter.code-workspace`** – VS Code workspace configuration (JSON)
- **`read.md`** – Documentation file

### Checks Performed

| Injection Type | Result | Notes |
|---|---|---|
| **SQL Injection** | ✅ Not applicable | No database interactions present |
| **OS Command Injection** | ✅ Not applicable | No shell/system calls; embedded firmware with no OS shell |
| **LDAP Injection** | ✅ Not applicable | No LDAP queries |
| **XML/XPath Injection** | ✅ Not applicable | No XML parsing or XPath queries |
| **Template Injection (SSTI)** | ✅ Not applicable | No template engine usage |
| **NoSQL Injection** | ✅ Not applicable | No NoSQL database interactions |
| **Expression Language Injection** | ✅ Not applicable | No EL expression evaluation |
| **`eval()` / Dynamic Code Execution** | ✅ Not applicable | No dynamic code execution |

### Rationale

This is a **bare-metal embedded application** running on an Arduino microcontroller. It:

1. **Has no external user input channels** susceptible to injection — input comes solely from IR sensor hardware (physical infrared signals), not from text-based interfaces like HTTP, databases, or command-line shells.
2. **Has no network connectivity** — `Serial` is used only for debug logging output, not for receiving user commands.
3. **Performs no string interpolation into query languages or command interpreters** — the `String` operations (e.g., `rawIRData.substring(4)`) are used purely for internal data comparison against hardcoded values.
4. **Uses no `eval()`, `system()`, `exec()`, or equivalent functions.**

### Minor Observation (Info-level, not an injection finding)

- **File: `IRRemoteFilter.ino`, line ~66**: `Serial.println(F("START " __FILE__ " from " __DATE__))` — The `__FILE__` macro embeds the source file path at compile time. This is purely a build-time constant and poses no runtime injection risk, though it could leak filesystem path information if firmware is extracted. **Severity: Info**.

---

### 2. CWE - Memory Safety and Buffer Errors ✅

*Checks for buffer overflows, use-after-free, null pointer dereference and integer overflow issues.*

**Status:** completed  
**Tokens used:** 9,548  

#### Findings

# SAST Analysis Results: Memory Safety and Buffer Errors

## Summary

After careful analysis of the provided source code (an Arduino IR remote filter application), I identified the following potential memory safety issues:

---

### Finding 1: Potential NULL Pointer Dereference from `IrReceiver.read()`

- **File:** `IRRemoteFilter.ino`, line 99
- **Severity:** Medium
- **CWE:** CWE-476 (NULL Pointer Dereference)
- **Description:** The return value of `IrReceiver.read()` is passed directly to `storeCode()` without a NULL check. Depending on the IRremote library version, `IrReceiver.read()` may return a pointer that could be NULL if internal state is inconsistent. The `storeCode` function then dereferences this pointer on line 166 (`aIRReceivedData->flags`).
- **Impact:** If `IrReceiver.read()` returns NULL, the program will attempt to dereference a NULL pointer, causing a crash/reset on the Arduino.
- **Remediation:** Add a NULL check before calling `storeCode`:
  ```cpp
  IRData *data = IrReceiver.read();
  if (data != nullptr) {
      storeCode(data);
      Serial.println(F("e6F675I received"));
      IrReceiver.resume();
      programState = 2;
  }
  ```

---

### Finding 2: Potential Out-of-Bounds Write in `rawCode` Array

- **File:** `IRRemoteFilter.ino`, lines 48–49 and 184–189
- **Severity:** Medium
- **CWE:** CWE-787 (Out-of-bounds Write)
- **Description:** The `rawCode` array is declared as `uint8_t rawCode[RAW_BUFFER_LENGTH]` and `rawCodeLength` is `uint8_t`. On line 184, the raw length is calculated as `IrReceiver.decodedIRData.rawDataPtr->rawlen - 1`. If `rawlen` is 0 (e.g., due to a decoding error or corrupted data), this subtraction wraps around to 255 (since the result is stored in a `uint8_t`). Subsequently, `IrReceiver.compensateAndStoreIRResultInArray(sStoredIRData.rawCode)` (line 189) could write beyond the bounds of `rawCode` if the library doesn't internally validate against `RAW_BUFFER_LENGTH`. Additionally, the `uint8_t rawCodeLength` field can only represent values 0–255, which could truncate `rawlen - 1` if `RAW_BUFFER_LENGTH` exceeds 256.
- **Impact:** Out-of-bounds write could corrupt adjacent memory (the `rawCodeLength` field or other global data), leading to undefined behavior.
- **Remediation:** Add bounds checking before storing raw data:
  ```cpp
  uint16_t rawLen = IrReceiver.decodedIRData.rawDataPtr->rawlen;
  if (rawLen > 1 && (rawLen - 1) <= RAW_BUFFER_LENGTH) {
      sStoredIRData.rawCodeLength = rawLen - 1;
      IrReceiver.compensateAndStoreIRResultInArray(sStoredIRData.rawCode);
  } else {
      Serial.println(F("Raw data too long or invalid, skipping storage"));
      sStoredIRData.rawCodeLength = 0;
  }
  ```

---

### Finding 3: Integer Underflow in Timeout Counter

- **File:** `IRRemoteFilter.ino`, lines 104–117
- **Severity:** Low
- **CWE:** CWE-190 (Integer Overflow or Wraparound)
- **Description:** The `timeOut` variable (type `int`) is decremented every iteration (`timeOut--`) on line 104. The timeout reset check on line 117 uses `timeOut==0`, an exact equality check. If execution of the loop body takes longer than expected or if the decrement is skipped/repeated due to interrupt handling, `timeOut` could go negative, missing the `==0` check entirely. On a 16-bit `int` Arduino (ATmega328), this would eventually wrap around from -32768 to 32767, creating a very long unexpected loop.
- **Impact:** The program could get stuck in an unresponsive state for an extended period rather than properly timing out and resetting.
- **Remediation:** Use `<=` instead of `==` for the timeout check:
  ```cpp
  if (timeOut <= 0) {
      Serial.println(F("Timeout"));
      IrReceiver.stop();
      programState = 0;
      delay(40);
  }
  ```

---

### No Issues Found

The following CWE categories were checked with **no findings**:
- **CWE-416 (Use After Free):** No dynamic memory allocation/deallocation patterns detected.
- **CWE-125 (Out-of-bounds Read):** The `String.substring(4)` call on line 133 is safe as Arduino's `String` class handles out-of-bounds gracefully by returning an empty string.
- **CWE-119 (Unsafe functions like `strcpy`, `sprintf`, `gets`):** No use of unsafe C string functions; the code uses Arduino `String` objects and `Serial.print`.

---

### 3. OWASP A04 - Insecure Design ✅

*Checks for architectural and design weaknesses that lead to security risks.*

**Status:** completed  
**Tokens used:** 9,537  

#### Findings

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

## Anonymization Summary

The following table summarises which files were anonymized before AI analysis. Refer to the accompanying anonymization report for full details including original values and line numbers.

| File | Method | Occurrences |
|------|--------|-------------|
| IRRemoteFilter.ino | Manual Security Strings | 8 |

---

---

*Report generated by Lithium Argon AI-powered SAST Service*  
*This report is confidential and intended solely for the designated recipient.*