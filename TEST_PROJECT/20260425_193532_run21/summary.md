# SAST Technical Report Summary

| | |
|---|---|
| **Run ID** | #21 |
| **Repository** | RemoteFilter |
| **Branch** | upload |
| **Project** | Secret project |
| **Customer** | Best Automotive s.r.o. |
| **Generated** | 2026-04-25T18:48:35Z |
| **Tests** | 3 |
| **Summary Tokens** | 8,421 |

## Overall Status: HIGH

The RemoteFilter repository contains an Arduino-based IR remote filter firmware (IRRemoteFilter.ino) for controlling a Dimplex electric fireplace. Static analysis identified no critical vulnerabilities, but two high-severity memory safety issues were found: a potential buffer overflow in raw IR code storage and a null pointer dereference on the IrReceiver.read() return value. Several medium and low-severity issues were also identified, including integer underflow in raw length calculation, signed integer misuse in timeout counters, and signed/unsigned type mismatches throughout. The codebase has no network attack surface, so exploitability is limited to malformed IR signal inputs, but the issues could cause device crashes or incorrect behavior in embedded operation.

## Severity Counts

| Critical | High | Medium | Low | Info |
|:---:|:---:|:---:|:---:|:---:|
| 0 | 2 | 3 | 4 | 1 |

## Top Findings

### 1. [HIGH] Potential Buffer Overflow in Raw IR Code Storage

In storeCode(), when the protocol is UNKNOWN, rawCodeLength is set to rawlen - 1 and compensateAndStoreIRResultInArray() is called with the rawCode buffer (sized RAW_BUFFER_LENGTH). If rawlen exceeds RAW_BUFFER_LENGTH, the function writes beyond the bounds of the rawCode array, corrupting adjacent global variables or causing undefined behavior.

### 2. [HIGH] NULL Pointer Dereference on IrReceiver.read() Return Value

In loop(), IrReceiver.read() return value is passed directly to storeCode() without a NULL check. If the library returns NULL due to an error or race condition, storeCode() will dereference it at aIRReceivedData->flags, causing a null pointer dereference and likely a microcontroller crash or reset.

### 3. [MEDIUM] Integer Underflow in rawCodeLength Calculation

In storeCode(), rawCodeLength is assigned rawlen - 1 where rawlen is an unsigned type. If rawlen is 0 (malformed or empty IR data), unsigned underflow produces a very large value (e.g., 65535). When truncated to uint8_t, it wraps to 255, potentially causing compensateAndStoreIRResultInArray to overflow the rawCode buffer.

### 4. [MEDIUM] Unchecked Return Value of IrReceiver.read() Before Dereference (Type Safety)

Duplicate finding confirmed by a second test: IrReceiver.read() return value is used without NULL/nullptr check in storeCode(), risking null pointer dereference and undefined behavior or watchdog reset.

### 5. [MEDIUM] Signed Integer Overflow/Underflow Risk in Timeout Counter

The timeout counter and related constants (READ_TIMEOUT=30000, INIT_REPEAT_DELAY_TIME=29800) are declared as signed int. On 16-bit AVR platforms (INT_MAX=32767), these values are valid but leave minimal margin. If the counter skips zero (timeout check uses ==0), it decrements into negative values indefinitely, causing the state machine to hang in programState==1.

### 6. [LOW] Unchecked Null Dereference of rawDataPtr

In storeCode(), IrReceiver.decodedIRData.rawDataPtr is dereferenced to access rawlen without a prior null check. If rawDataPtr is null, this causes undefined behavior and likely a device crash.

### 7. [LOW] Signed/Unsigned Mismatch for Pin Numbers and Delay Parameters

Configuration variables for pins, delays, and timeouts are declared as signed int but passed to Arduino API functions expecting unsigned types. A negative value (due to logic error) passed to delay() would be implicitly converted to a very large unsigned value, potentially freezing the device.

### 8. [LOW] Magic Number Comparisons for IR Protocol Commands Without Range Validation

IR command and address comparisons use magic integer literals (e.g., command==70, address==4) without named constants or range validation. The implicit signed-to-unsigned promotion is benign here but the pattern is fragile and may mask logic errors if underlying types change.

### 9. [INFO] rawCodeLength uint8_t Field May Silently Truncate rawlen

The rawCodeLength field is uint8_t (max 255). If rawlen exceeds 256, the assignment silently truncates the value, causing sendRaw() in sendCode() to transmit an incorrect number of timing entries and produce a malformed IR signal.

## Per-Test Results

| # | Test | Status | Findings | Summary |
|---|------|--------|----------|---------|
| 1 | Insecure Design | no_findings | 0 | No insecure design issues found. The firmware has no network connectivity, authentication flows, API endpoints, or web i |
| 2 | CWE - Memory Safety and Buffer Errors | findings_found | 5 | Found 2 high-severity issues (buffer overflow in raw IR storage, null pointer dereference on IrReceiver.read()), 2 mediu |
| 3 | C/C++ - Type Confusion and Unsafe Casts | findings_found | 5 | No critical type-confusion vulnerabilities found; identified 1 medium-severity null pointer dereference (corroborating t |

---

*Report generated by Lithium Argon AI-powered SAST Service*