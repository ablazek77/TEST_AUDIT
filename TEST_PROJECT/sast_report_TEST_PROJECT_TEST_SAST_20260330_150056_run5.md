# SAST Security Report

**Customer:** TEST CUSTOMER  
**Project:** TEST PROJECT  
**Repository:** TEST_SAST  
**Branch:** upload  
**Run ID:** 5  
**Generated:** 2026-03-30 14:59:17 UTC  
**Triggered by:** manual  

---

## Executive Summary

This report contains the results of 4 automated security test(s) performed on the anonymized source code.

| Metric | Value |
|--------|-------|
| Total Tests | 4 |
| Completed | 4 |
| Failed | 0 |
| Total AI Tokens Used | 37,549 |

---

## Test Results

### 1. OWASP A03 - Injection ✅

*Checks for SQL injection, command injection, LDAP injection and other injection attacks.*

**Status:** completed  
**Tokens used:** 8,762  

#### Findings

# SAST Analysis Results - OWASP A03: Injection

## Summary

After thorough analysis of the provided source code, **no injection vulnerabilities were identified**.

## Detailed Analysis

### Context

This is an **Arduino/embedded systems project** (C++ for microcontrollers) that:
- Receives IR (infrared) remote control signals
- Filters certain IR codes to prevent an LG TV remote from accidentally controlling a Dimplex electric fireplace
- Retransmits allowed IR codes

### Injection Categories Evaluated

| Injection Type | Finding |
|---|---|
| **SQL Injection** | **Not applicable** — No database interactions exist in this codebase. |
| **OS Command Injection** | **Not applicable** — No shell commands, `exec()`, `system()`, `subprocess`, or similar calls. The code runs on bare-metal Arduino hardware with no operating system shell. |
| **LDAP Injection** | **Not applicable** — No LDAP queries. |
| **XML/XPath Injection** | **Not applicable** — No XML parsing or XPath expressions. |
| **Template Injection (SSTI)** | **Not applicable** — No template engine usage. |
| **NoSQL Injection** | **Not applicable** — No database of any kind. |
| **Expression Language Injection** | **Not applicable** — No EL expressions. |
| **`eval()` / Dynamic Code Execution** | **Not applicable** — No dynamic code evaluation. |

### Additional Notes

- **No external/user-controlled input beyond IR signals**: The only "input" to this system is IR data received via a hardware IR receiver. This data is processed as structured binary data (protocol, address, command, flags) by the IRremote library, not as strings interpreted by a query engine, shell, or template system.
- **`Serial.println()` calls**: These output debug information to the serial console and do not constitute an injection risk in this embedded context — there is no reverse channel where serial output could influence program execution.
- **`String` operations** (e.g., `rawIRData.substring(4)` on line ~131): These are used for simple string comparison of hex-encoded IR data and are not passed to any interpreter, query engine, or command processor.
- **`PinDefinitionsAndMore.h`**: Contains only preprocessor `#define` macros for pin assignments — no injection surface.
- **`IRRemoteFilter.code-workspace`**: A VS Code workspace configuration file with static JSON content — no injection surface.

## Conclusion

**No injection vulnerabilities were found.** This is an embedded/firmware application running on Arduino microcontrollers with no network connectivity, no database access, no operating system shell, and no template or expression engines. The attack surface for injection-class vulnerabilities is effectively zero in this codebase.

---

### 2. OWASP A04 - Insecure Design ✅

*Checks for architectural and design weaknesses that lead to security risks.*

**Status:** completed  
**Tokens used:** 9,383  

#### Findings

# SAST Analysis: OWASP A04 - Insecure Design

## Summary

This is an **Arduino/embedded firmware project** that acts as an IR (infrared) remote control filter for a Dimplex electric fireplace. It receives IR signals, filters out unwanted commands (e.g., from an LG TV remote), and retransmits valid commands. The code runs on a microcontroller (Arduino UNO), not a web application or networked service.

## Findings

### 1. Insufficient IR Command Filtering / Bypass Potential

- **File:** `IRRemoteFilter.ino`, lines 124–155
- **Severity:** Medium
- **Description:** The filtering logic relies solely on checking the `address` field, a substring match on the hex representation of raw data (`rawIRData.substring(4)!="ff00"`), and bit length. An attacker with physical proximity and an IR transmitter could craft IR signals that pass these filters but still trigger unintended behavior on the Dimplex fireplace. Specifically:
  - The address check only blocks `address==4` (LG TV). Any other device with a different address but a command that happens to end in `ff00` and is 32 bits would pass through.
  - String-based comparison of hex data (`rawIRData.substring(4)`) is fragile — it depends on the hex representation length being exactly what's expected.
- **Impact:** An attacker in IR line-of-sight could send crafted IR signals that bypass the filter and control the fireplace (turn on/off heating elements), which is a **safety concern** for a device that generates heat.
- **Remediation:** Implement an **allowlist** approach rather than a blocklist. Only permit known valid Dimplex commands (the specific raw data values documented in `read.md`) and reject everything else.

```cpp
// Recommended: allowlist approach
bool isAllowedCommand(uint32_t rawData) {
    const uint32_t allowedCommands[] = {
        0xB946FF00, // Power on/off
        0xBB44FF00, // Fire
        0xBC43FF00, // Heat
        0xF807FF00, // Temp down
        0xF609FF00, // Temp up
        0xE916FF00, // Color
        0xF20DFF00, // Light
        0xE718FF00  // Timer
    };
    for (int i = 0; i < sizeof(allowedCommands)/sizeof(allowedCommands[0]); i++) {
        if (rawData == allowedCommands[i]) return true;
    }
    return false;
}
```

### 2. Weak Rate Limiting on Power Command

- **File:** `IRRemoteFilter.ino`, lines 148–150 and 167
- **Severity:** Medium
- **Description:** The power command (command `70`) has a "lock" mechanism (`POWER_DELAY_LOCK`) intended to prevent rapid toggling of the fireplace power. However, the lock is based on a decrementing counter tied to a `delay(1)` loop, making it time-approximate rather than precise. More importantly, the lock value (`POWER_COMMAND_DELAY = 600`) translates to roughly 600ms, which is very short. An attacker could repeatedly send power commands at intervals just beyond this window to rapidly toggle the fireplace on and off, which is a **fire safety concern**.
- **Impact:** Rapid toggling of the electric fireplace power could cause operational issues or safety hazards.
- **Remediation:** Increase the power command lockout duration significantly (e.g., several seconds) and use `millis()` for accurate time tracking instead of loop-counter-based timing.

```cpp
static unsigned long lastPowerCommandTime = 0;
const unsigned long POWER_LOCKOUT_MS = 5000; // 5 second lockout

if (sStoredIRData.receivedIRData.command == 70) {
    if (millis() - lastPowerCommandTime < POWER_LOCKOUT_MS) {
        filter = 1; // Block
    } else {
        lastPowerCommandTime = millis();
    }
}
```

### 3. No Authentication on IR Commands

- **File:** `IRRemoteFilter.ino`, entire `loop()` function
- **Severity:** Low
- **Description:** The IR protocol (NEC) has no authentication or integrity mechanism. Any IR signal matching the expected format will be retransmitted to the fireplace. This is an inherent limitation of the IR protocol, but the design makes no attempt to add any additional validation (e.g., requiring a sequence of commands, or a physical button confirmation for safety-critical operations like power toggling).
- **Impact:** Anyone within IR line-of-sight can control the fireplace through this filter device.
- **Remediation:** For safety-critical operations (power on/off, heat), consider requiring a physical button press confirmation on the Arduino or implementing a command sequence that would be unlikely from a stray remote.

---

## No Issues Found For

- **Password reset flows, account lockout, MFA, remember-me tokens**: Not applicable — this is embedded firmware with no user accounts, web interfaces, or network connectivity.
- **Business logic flaws (price manipulation, negative quantities)**: Not applicable — no commercial transaction logic exists.
- **Client-side validation trust boundary violations**: Not applicable — no client-server architecture.

---

### 3. Business Logic Flaws ✅

*Checks for workflow bypass, price manipulation, race conditions and other logic-layer vulnerabilities.*

**Status:** completed  
**Tokens used:** 10,626  

#### Findings

# Security Analysis: Business Logic Flaws

## Summary

This is an Arduino-based IR remote filter application designed to block certain IR codes from an LG TV remote that inadvertently trigger a Dimplex electric fireplace. The application receives IR signals, filters them, and retransmits allowed signals.

Given that this is an embedded/IoT firmware project rather than a web application or API service, many of the typical business logic flaw categories (payment bypass, discount manipulation, account state transitions, etc.) are **not applicable**. However, there are several logic-level concerns relevant to the device's intended security purpose.

---

### Finding 1: Incomplete IR Code Filtering – Filter Bypass via Race Condition in State Machine

- **File:** `IRRemoteFilter.ino`, lines 90–110 (programState 1)
- **Severity:** Medium
- **Description:** The `storeCode()` function (called at line 93) silently returns without updating `sStoredIRData` when the received IR data has the `IRDATA_FLAGS_IS_REPEAT`, `IRDATA_FLAGS_IS_AUTO_REPEAT`, or `IRDATA_FLAGS_PARITY_FAILED` flags set. However, the state machine still advances to `programState = 2` (line 95), meaning the **previously stored** IR data in `sStoredIRData` will be re-evaluated and potentially retransmitted. An attacker could exploit this by sending a valid Dimplex command followed by rapid repeat signals, causing the device to retransmit a stale (and potentially already-filtered) command.

- **Impact:** A blocked IR command could be replayed if a subsequent IR signal with repeat/parity flags causes the state machine to advance while the stale data remains in `sStoredIRData`. This effectively bypasses the filter.

- **Remediation:** Check the return value of `storeCode()` or add a validity flag, and only advance the state machine if a new valid code was actually stored.

```cpp
// Modified storeCode to return success/failure
bool storeCode(IRData *aIRReceivedData) {
    if (aIRReceivedData->flags & IRDATA_FLAGS_IS_REPEAT) {
        Serial.println(F("Ignore repeat"));
        return false;
    }
    if (aIRReceivedData->flags & IRDATA_FLAGS_IS_AUTO_REPEAT) {
        Serial.println(F("Ignore autorepeat"));
        return false;
    }
    if (aIRReceivedData->flags & IRDATA_FLAGS_PARITY_FAILED) {
        Serial.println(F("Ignore parity error"));
        return false;
    }
    sStoredIRData.receivedIRData = *aIRReceivedData;
    // ... rest of storage logic ...
    return true;
}

// In loop(), programState == 1:
if (IrReceiver.available()) {
    if (storeCode(IrReceiver.read())) {
        Serial.println(F("e6F675I received"));
        programState = 2;
    }
    IrReceiver.resume();
}
```

---

### Finding 2: Allowlist vs Denylist Approach – Unknown Protocols Bypass Filter

- **File:** `IRRemoteFilter.ino`, lines 118–154 (programState 3)
- **Severity:** High
- **Description:** The filtering logic uses a **denylist** approach: it blocks specific addresses (LG TV address `4`) and non-32-bit commands, but then **allows everything else through**. The `sendCode()` function at line 184 can transmit `UNKNOWN` protocol signals as raw data, which would not have meaningful `address`, `command`, or `numberOfBits` fields. An attacker could craft a raw IR signal that mimics Dimplex commands but uses an unknown protocol encoding that bypasses the address/bit-length checks. The `numberOfBits` check at line 131 would catch some cases, but the interaction with unknown protocol handling is unclear.

    More critically, the intended behavior is to **only** allow Dimplex BLF 5051 commands (address `0x0`, protocol NEC, 32-bit). The current filter does not enforce an allowlist of the known valid Dimplex address (`0x0`).

- **Impact:** Unintended IR commands could be forwarded to the fireplace, potentially triggering power on/off, heating, or other safety-critical functions.

- **Remediation:** Use an **allowlist** approach — only forward signals that match known Dimplex parameters:

```cpp
// programState == 3: Allowlist-based filter
if (programState == 3) {
    filter = 1; // Default: block everything

    // Only allow NEC protocol, address 0x0, 32 bits, with ff00 suffix
    if (sStoredIRData.receivedIRData.protocol == NEC &&
        sStoredIRData.receivedIRData.numberOfBits == 32 &&
        sStoredIRData.receivedIRData.address == 0) {
        
        rawIRData = String(sStoredIRData.receivedIRData.decodedRawData, HEX);
        if (rawIRData.substring(4) == "ff00") {
            filter = 0; // Allow only confirmed Dimplex commands
        }
    }

    // Power button rate limiting
    if (sStoredIRData.receivedIRData.command == 70 && POWER_DELAY_LOCK > 0) {
        filter = 1;
    }

    if (filter == 0) { programState = 4; }
    else { programState = 0; }
}
```

---

### Finding 3: Power Button Rate-Limiting Can Be Bypassed via Timeout Reset

- **File:** `IRRemoteFilter.ino`, lines 103–105 and lines 144–146
- **Severity:** Medium
- **Description:** The `POWER_DELAY_LOCK` counter is decremented in `programState == 1` (line 105) only when `timeOut < INIT_REPEAT_DELAY_TIME`. This counter is meant to prevent rapid toggling of the power command (command `70`). However, each time the state machine resets to `programState == 0` (e.g., on timeout at line 111 or after a blocked signal at line 153), a new cycle starts with `timeOut = READ_TIMEOUT` (30000). The `POWER_DELAY_LOCK` is only decremented when `timeOut < INIT_REPEAT_DELAY_TIME` (29800), meaning only the last 200 iterations of each cycle decrement the lock. An attacker who sends signals at the right timing can reset the cycle and prevent `POWER_DELAY_LOCK` from ever reaching 0, or conversely, by timing signals to arrive after the lock is fully decremented but within a very narrow window, could send multiple power commands in rapid succession.

    Additionally, `POWER_DELAY_LOCK` is set to `600` (line 169) but is decremented by `1` per millisecond only during a narrow window of each read cycle. The actual wall-clock lockout time is unpredictable and much longer than intended, or could be shorter if multiple short cycles occur rapidly.

- **Impact:** The safety mechanism preventing rapid power toggling of the electric fireplace is unreliable and could be bypassed or could fail to protect as intended.

- **Remediation:** Use `millis()` for timing the power lockout instead of a counter tied to the state machine loop:

```cpp
unsigned long powerLockUntil = 0;

// In programState == 3, when checking power lock:
if (sStoredIRData.receivedIRData.command == 70) {
    if (millis() < powerLockUntil) { 
        filter = 1; 
    }
}

// In programState == 4, after sending power command:
if (sStoredIRData.receivedIRData.command == 70) { 
    powerLockUntil = millis() + POWER_COMMAND_DELAY; 
}
```

---

### Finding 4: String-Based Hex Comparison for Address Filtering Is Fragile

- **File:** `IRRemoteFilter.ino`, lines 127–137
- **Severity:** Low
- **Description:** The filter checks `rawIRData.substring(4) != "ff00"` to validate the Dimplex address portion. This string comparison is case-sensitive and depends on the behavior of `String(value, HEX)` on the specific Arduino platform. If the hex representation includes uppercase characters or has a different length (e.g., leading zeros are omitted for smaller values), the comparison would fail in unexpected ways — either allowing malicious signals through or blocking legitimate ones.

- **Impact:** Filter bypass or denial of service for legitimate Dimplex remote commands.

- **Remediation:** Use numeric comparison instead of string comparison:

```cpp
// Use bitmask on the raw data directly
uint32_t rawData = sStoredIRData.receivedIRData.decodedRawData;
uint16_t addressPortion = rawData & 0xFFFF; // Lower 16 bits
if (addressPortion != 0xFF00) {
    filter = 1;
}
```

---

## Not Applicable

The following business logic flaw categories were evaluated and found **not applicable** to this embedded IR filter firmware:

- **Multi-step workflow bypass** (no user-facing multi-step workflow)
- **Negative/zero value manipulation** (no monetary or quantity values)
- **Price/discount manipulation** (not applicable)
- **Inventory/stock manipulation** (not applicable)
- **Privilege/account state transitions** (no user accounts)
- **Referral/reward abuse** (not applicable)
- **Auction/bidding logic** (not applicable)
- **Idempotency on payments** (not applicable)
- **Export/reporting data exposure** (not applicable)

---

### 4. Secrets and Credentials in Code ✅

*Checks for hardcoded secrets, API keys, passwords and credentials committed to the codebase.*

**Status:** completed  
**Tokens used:** 8,778  

#### Findings

# SAST Analysis: Secrets and Credentials in Code

## Summary

After thorough analysis of all provided source files, **no hardcoded secrets, credentials, or sensitive values were identified**.

## Detailed Findings

### Hardcoded Passwords / API Keys / Tokens
**No findings.** The codebase is an Arduino/embedded IR remote control filter application and contains no passwords, API keys, access tokens, or bearer tokens.

### Private Keys / Certificates
**No findings.** No cryptographic key material is present in any of the files.

### Cloud Provider Credentials
**No findings.** No AWS, GCP, Azure, or other cloud credentials are present.

### Database Connection Strings
**No findings.** No database connections exist in this codebase.

### .env Files / Environment Variable Overrides
**No findings.** No environment configuration files with secrets are present.

### Embedded Secrets in Comments or Debug Logging
**No findings.** The comments and `Serial.println()` debug statements contain only IR protocol data (hex codes for IR remote commands like `0xB946FF00` for power on/off), pin numbers, and operational status messages. These are **not secrets** — they are publicly documented IR protocol command codes for a Dimplex BLF 5051 electric fireplace and an LG TV remote.

### Base64-Encoded or Obfuscated Credentials
**No findings.** The hex values present (e.g., `0xBB44FF00`, `0xBB44FB04`) are standard NEC IR protocol command codes, not encoded credentials.

### Other Observations

| Item | Assessment |
|------|-----------|
| `e6F675I` string used throughout `IRRemoteFilter.ino` | This appears to be an obfuscated/placeholder label for "IR signal" used in log messages — **not a credential or secret** |
| `read.md` containing IR hex codes | These are publicly available IR remote protocol codes for consumer electronics — **not sensitive** |
| Email in `PinDefinitionsAndMore.h` (line 9: `armin.joachimsmeyer@gmail.com`) | This is a standard open-source copyright attribution from the IRremote library — **Info severity, no action needed** |

## Conclusion

This codebase is a straightforward Arduino embedded project for filtering IR remote control signals. It contains no secrets, credentials, or sensitive configuration values. The hexadecimal values present are standard infrared protocol command codes, and all configuration consists of hardware pin definitions and timing constants.

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