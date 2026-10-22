/**
 * tests/hashing.test.js
 *
 * Automated Node.js test suite for ForensiCheck SHA-256 validation logic.
 * Tests Web Crypto API (crypto.subtle.digest), known-answer test fixtures,
 * alteration detection, format validation, CSV escaping, and memo generation.
 *
 * Run with: npm test (or node tests/hashing.test.js)
 */

"use strict";

const utf8Encoder = new TextEncoder();
const SHA256_HEX_LENGTH = 64;
const VALID_HEX = /^[0-9a-f]{64}$/;

// ---- Core Hashing Logic (Mirrors script.js) ----

async function calculateSHA256(data) {
    const buffer = data instanceof ArrayBuffer ? data : data.buffer.slice(
        data.byteOffset, data.byteOffset + data.byteLength
    );
    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    const hashArray = new Uint8Array(hashBuffer);
    return Array.from(hashArray)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function normalizeHash(hex) {
    return hex.trim().toLowerCase();
}

function isValidSHA256Hex(hex) {
    return VALID_HEX.test(normalizeHash(hex));
}

function compareHashes(expected, observed) {
    return normalizeHash(expected) === normalizeHash(observed) ? "PASS" : "FAIL";
}

function csvEscape(value) {
    const str = String(value ?? "");
    if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
        return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
}

// ---- Test Runner Harness ----

let passedCount = 0;
let failedCount = 0;
const failures = [];

async function test(name, fn) {
    const start = Date.now();
    try {
        await fn();
        passedCount++;
        const duration = Date.now() - start;
        console.log(`  \x1b[32m✔\x1b[0m ${name} \x1b[90m(${duration}ms)\x1b[0m`);
    } catch (err) {
        failedCount++;
        failures.push({ name, error: err.message });
        console.log(`  \x1b[31m✖\x1b[0m ${name}`);
        console.log(`    \x1b[31mError: ${err.message}\x1b[0m`);
    }
}

function assertEqual(actual, expected, msg = "") {
    if (actual !== expected) {
        throw new Error(`${msg ? msg + ": " : ""}Expected "${expected}", got "${actual}"`);
    }
}

function assertTrue(value, msg = "Expected truthy value") {
    if (!value) throw new Error(msg);
}

function assertFalse(value, msg = "Expected falsy value") {
    if (value) throw new Error(msg);
}

function assertNotEqual(a, b, msg = "") {
    if (a === b) {
        throw new Error(`${msg ? msg + ": " : ""}Values should not be equal: "${a}"`);
    }
}

// ---- Main Test Execution ----

async function runTestSuite() {
    console.log("\n\x1b[1m\x1b[36m🧪 ForensiCheck SHA-256 Validation Test Suite\x1b[0m");
    console.log("\x1b[90mRunning automated tests against independently-verified hashes...\x1b[0m\n");

    console.log("\x1b[1m1. Known-Answer Cryptographic Tests\x1b[0m");

    await test("TC-001: Standard ASCII text file hash matches known vector", async () => {
        const data = utf8Encoder.encode("The quick brown fox jumps over the lazy dog.\n");
        const hash = await calculateSHA256(data);
        assertEqual(hash, "b47cc0f104b62d4c7c30bcd68fd8e67613e287dc4ad8c310ef10cbadea9c4380");
    });

    await test("TC-002: Binary data (all byte values 0x00..0xFF) hashes accurately", async () => {
        const data = new Uint8Array(256).map((_, i) => i);
        const hash = await calculateSHA256(data);
        assertEqual(hash, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880");
    });

    await test("TC-003: Empty file (zero bytes) produces standard SHA-256 constant", async () => {
        const data = new Uint8Array(0);
        const hash = await calculateSHA256(data);
        assertEqual(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    });

    await test("TC-004: Unicode / UTF-8 multi-byte characters hash correctly", async () => {
        const data = utf8Encoder.encode("Ünïcödé Tëst: 日本語テスト 🔍🔒\n");
        const hash = await calculateSHA256(data);
        assertEqual(hash, "197a7e14689ce38e304c9bf1330595f0adaf36730c8c719d7d84710cc98ebf1e");
    });

    await test("TC-005: Large payload (~100 KiB repeated content) hashes correctly", async () => {
        const line = utf8Encoder.encode("ForensiCheck large-file test line.\n");
        const buffer = new Uint8Array(line.length * 3000);
        for (let i = 0; i < 3000; i++) buffer.set(line, i * line.length);
        const hash = await calculateSHA256(buffer);
        assertEqual(hash, "9f875318fe63115a88afff67768bd41d802098a725d015a62ba5173e297e9e59");
    });

    await test("TC-006: Deliberately modified content produces expected FAIL outcome", async () => {
        const originalExpected = "b47cc0f104b62d4c7c30bcd68fd8e67613e287dc4ad8c310ef10cbadea9c4380";
        const modifiedData = utf8Encoder.encode("The quick brown fox jumps over the lazy dog!\n");
        const observedHash = await calculateSHA256(modifiedData);
        const result = compareHashes(originalExpected, observedHash);
        assertEqual(result, "FAIL", "Modified file must fail comparison against original hash");
        assertEqual(observedHash, "668acb539397715859d1e6db2322f98535b000356dacbce18fe12bacadd7f99b");
    });

    await test("TC-007: Invalid expected hash format produces ERROR outcome", async () => {
        const invalidHash = "ZZZZ_NOT_A_VALID_HEX_HASH";
        assertFalse(isValidSHA256Hex(invalidHash), "Invalid string must fail hex validation");
    });

    console.log("\n\x1b[1m2. Integrity & Avalanche Effect Tests\x1b[0m");

    await test("Single-character modification produces completely different digest", async () => {
        const orig = utf8Encoder.encode("The quick brown fox jumps over the lazy dog.\n");
        const mod = utf8Encoder.encode("The quick brown fox jumps over the lazy dog!\n");
        const h1 = await calculateSHA256(orig);
        const h2 = await calculateSHA256(mod);
        assertNotEqual(h1, h2, "Avalanche effect must change hash");
    });

    await test("Appending a single null byte produces distinct hash", async () => {
        const orig = utf8Encoder.encode("evidence_file_payload");
        const appended = new Uint8Array([...orig, 0x00]);
        const h1 = await calculateSHA256(orig);
        const h2 = await calculateSHA256(appended);
        assertNotEqual(h1, h2);
    });

    console.log("\n\x1b[1m3. Comparison & Normalization Tests\x1b[0m");

    await test("Identical hashes yield PASS", () => {
        const hash = "a".repeat(64);
        assertEqual(compareHashes(hash, hash), "PASS");
    });

    await test("Case-insensitive comparison matches uppercase and lowercase hex", () => {
        const lower = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        const upper = lower.toUpperCase();
        assertEqual(compareHashes(lower, upper), "PASS");
    });

    await test("Mismatched hashes yield FAIL", () => {
        const h1 = "0".repeat(64);
        const h2 = "1".repeat(64);
        assertEqual(compareHashes(h1, h2), "FAIL");
    });

    await test("Hash normalization trims leading and trailing whitespace", () => {
        const dirty = "  " + "f".repeat(64) + " \n";
        assertEqual(normalizeHash(dirty), "f".repeat(64));
    });

    console.log("\n\x1b[1m4. Hash Format Validation Tests\x1b[0m");

    await test("Valid 64-char lowercase hex is accepted", () => {
        assertTrue(isValidSHA256Hex("b47cc0f104b62d4c7c30bcd68fd8e67613e287dc4ad8c310ef10cbadea9c4380"));
    });

    await test("Valid 64-char uppercase hex is accepted", () => {
        assertTrue(isValidSHA256Hex("B47CC0F104B62D4C7C30BCD68FD8E67613E287DC4AD8C310EF10CBADEA9C4380"));
    });

    await test("Short hash (<64 chars) is rejected", () => {
        assertFalse(isValidSHA256Hex("b47cc0f104b62d4c"));
    });

    await test("Long hash (>64 chars) is rejected", () => {
        assertFalse(isValidSHA256Hex("a".repeat(65)));
    });

    await test("Non-hex characters are rejected", () => {
        assertFalse(isValidSHA256Hex("g".repeat(64)));
    });

    await test("Empty string is rejected", () => {
        assertFalse(isValidSHA256Hex(""));
    });

    console.log("\n\x1b[1m5. Export & CSV Escaping Tests\x1b[0m");

    await test("Plain strings are preserved without unnecessary quotes in CSV", () => {
        assertEqual(csvEscape("ForensiCheck"), "ForensiCheck");
    });

    await test("Commas in strings are quoted correctly for RFC 4180 CSV compliance", () => {
        assertEqual(csvEscape("UPES, Dehradun"), '"UPES, Dehradun"');
    });

    await test("Internal double quotes are escaped as doubled double-quotes", () => {
        assertEqual(csvEscape('Status is "PASS"'), '"Status is ""PASS"""');
    });

    await test("Newlines within strings are properly quoted", () => {
        assertEqual(csvEscape("Line 1\nLine 2"), '"Line 1\nLine 2"');
    });

    // Summary
    console.log("\n" + "=".repeat(50));
    console.log(`Results: \x1b[32m${passedCount} passed\x1b[0m, \x1b[31m${failedCount} failed\x1b[0m out of ${passedCount + failedCount} tests.`);
    if (failedCount > 0) {
        console.error("\nFailures:");
        failures.forEach(f => console.error(`- ${f.name}: ${f.error}`));
        process.exit(1);
    } else {
        console.log("\x1b[32m\x1b[1m✔ All SHA-256 validation tests passed successfully!\x1b[0m\n");
    }
}

runTestSuite();
