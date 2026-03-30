# SAST Test Result: Business Logic Flaws ✅

**Run ID:** 5  
**Status:** completed  
**Tokens used:** 10,626  

*Checks for workflow bypass, price manipulation, race conditions and other logic-layer vulnerabilities.*

---

## Findings

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

*Report generated by Lithium Argon AI-powered SAST Service*