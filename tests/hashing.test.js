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

async function calculateDigest(algorithm, data) {
    const buffer = data instanceof ArrayBuffer ? data : data.buffer.slice(
        data.byteOffset, data.byteOffset + data.byteLength
    );
    const hashBuffer = await crypto.subtle.digest(algorithm, buffer);
    const hashArray = new Uint8Array(hashBuffer);
    return Array.from(hashArray)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function calculateMD5(input) {
    let bytes;
    if (typeof input === "string") {
        bytes = utf8Encoder.encode(input);
    } else if (input instanceof ArrayBuffer) {
        bytes = new Uint8Array(input);
    } else if (input instanceof Uint8Array) {
        bytes = input;
    } else {
        bytes = new Uint8Array(0);
    }

    function safeAdd(x, y) {
        const lsw = (x & 0xffff) + (y & 0xffff);
        const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xffff);
    }

    function bitRotateLeft(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }

    function md5cmn(q, a, b, x, s, t) {
        return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
    }
    function md5ff(a, b, c, d, x, s, t) {
        return md5cmn((b & c) | (~b & d), a, b, x, s, t);
    }
    function md5gg(a, b, c, d, x, s, t) {
        return md5cmn((b & d) | (c & ~d), a, b, x, s, t);
    }
    function md5hh(a, b, c, d, x, s, t) {
        return md5cmn(b ^ c ^ d, a, b, x, s, t);
    }
    function md5ii(a, b, c, d, x, s, t) {
        return md5cmn(c ^ (b | ~d), a, b, x, s, t);
    }

    const nblk = ((bytes.length + 8) >> 6) + 1;
    const blks = new Array(nblk * 16).fill(0);
    for (let i = 0; i < bytes.length; i++) {
        blks[i >> 2] |= bytes[i] << ((i % 4) * 8);
    }
    blks[bytes.length >> 2] |= 0x80 << ((bytes.length % 4) * 8);
    blks[nblk * 16 - 2] = (bytes.length * 8) & 0xffffffff;
    blks[nblk * 16 - 1] = Math.floor((bytes.length * 8) / 0x100000000);

    let a = 1732584193;
    let b = -271733879;
    let c = -1732584194;
    let d = 271733878;

    for (let i = 0; i < blks.length; i += 16) {
        const olda = a, oldb = b, oldc = c, oldd = d;

        a = md5ff(a, b, c, d, blks[i + 0], 7, -680876936);
        d = md5ff(d, a, b, c, blks[i + 1], 12, -389564586);
        c = md5ff(c, d, a, b, blks[i + 2], 17, 606105819);
        b = md5ff(b, c, d, a, blks[i + 3], 22, -1044525330);
        a = md5ff(a, b, c, d, blks[i + 4], 7, -176418897);
        d = md5ff(d, a, b, c, blks[i + 5], 12, 1200080426);
        c = md5ff(c, d, a, b, blks[i + 6], 17, -1473231341);
        b = md5ff(b, c, d, a, blks[i + 7], 22, -45705983);
        a = md5ff(a, b, c, d, blks[i + 8], 7, 1770035416);
        d = md5ff(d, a, b, c, blks[i + 9], 12, -1958414417);
        c = md5ff(c, d, a, b, blks[i + 10], 17, -42063);
        b = md5ff(b, c, d, a, blks[i + 11], 22, -1990404162);
        a = md5ff(a, b, c, d, blks[i + 12], 7, 1804603682);
        d = md5ff(d, a, b, c, blks[i + 13], 12, -40341101);
        c = md5ff(c, d, a, b, blks[i + 14], 17, -1502002290);
        b = md5ff(b, c, d, a, blks[i + 15], 22, 1236535329);

        a = md5gg(a, b, c, d, blks[i + 1], 5, -165796510);
        d = md5gg(d, a, b, c, blks[i + 6], 9, -1069501632);
        c = md5gg(c, d, a, b, blks[i + 11], 14, 643717713);
        b = md5gg(b, c, d, a, blks[i + 0], 20, -373897302);
        a = md5gg(a, b, c, d, blks[i + 5], 5, -701558691);
        d = md5gg(d, a, b, c, blks[i + 10], 9, 38016083);
        c = md5gg(c, d, a, b, blks[i + 15], 14, -660478335);
        b = md5gg(b, c, d, a, blks[i + 4], 20, -405537848);
        a = md5gg(a, b, c, d, blks[i + 9], 5, 568446438);
        d = md5gg(d, a, b, c, blks[i + 14], 9, -1019803690);
        c = md5gg(c, d, a, b, blks[i + 3], 14, -187363961);
        b = md5gg(b, c, d, a, blks[i + 8], 20, 1163531501);
        a = md5gg(a, b, c, d, blks[i + 13], 5, -1444681467);
        d = md5gg(d, a, b, c, blks[i + 2], 9, -51403784);
        c = md5gg(c, d, a, b, blks[i + 7], 14, 1735328473);
        b = md5gg(b, c, d, a, blks[i + 12], 20, -1926607734);

        a = md5hh(a, b, c, d, blks[i + 5], 4, -378558);
        d = md5hh(d, a, b, c, blks[i + 8], 11, -2022574463);
        c = md5hh(c, d, a, b, blks[i + 11], 16, 1839030562);
        b = md5hh(b, c, d, a, blks[i + 14], 23, -35309556);
        a = md5hh(a, b, c, d, blks[i + 1], 4, -1530992060);
        d = md5hh(d, a, b, c, blks[i + 4], 11, 1272893353);
        c = md5hh(c, d, a, b, blks[i + 7], 16, -155497632);
        b = md5hh(b, c, d, a, blks[i + 10], 23, -1094730640);
        a = md5hh(a, b, c, d, blks[i + 13], 4, 681279174);
        d = md5hh(d, a, b, c, blks[i + 0], 11, -358537222);
        c = md5hh(c, d, a, b, blks[i + 3], 16, -722521979);
        b = md5hh(b, c, d, a, blks[i + 6], 23, 76029189);
        a = md5hh(a, b, c, d, blks[i + 9], 4, -640364487);
        d = md5hh(d, a, b, c, blks[i + 12], 11, -421815835);
        c = md5hh(c, d, a, b, blks[i + 15], 16, 530742520);
        b = md5hh(b, c, d, a, blks[i + 2], 23, -995338651);

        a = md5ii(a, b, c, d, blks[i + 0], 6, -198630844);
        d = md5ii(d, a, b, c, blks[i + 7], 10, 1126891415);
        c = md5ii(c, d, a, b, blks[i + 14], 15, -1416354905);
        b = md5ii(b, c, d, a, blks[i + 5], 21, -57434055);
        a = md5ii(a, b, c, d, blks[i + 12], 6, 1700485571);
        d = md5ii(d, a, b, c, blks[i + 3], 10, -1894986606);
        c = md5ii(c, d, a, b, blks[i + 10], 15, -1051523);
        b = md5ii(b, c, d, a, blks[i + 1], 21, -2054922799);
        a = md5ii(a, b, c, d, blks[i + 8], 6, 1873313359);
        d = md5ii(d, a, b, c, blks[i + 15], 10, -30611744);
        c = md5ii(c, d, a, b, blks[i + 6], 15, -1560198380);
        b = md5ii(b, c, d, a, blks[i + 13], 21, 1309151649);
        a = md5ii(a, b, c, d, blks[i + 4], 6, -145523070);
        d = md5ii(d, a, b, c, blks[i + 11], 10, -1120210379);
        c = md5ii(c, d, a, b, blks[i + 2], 15, 718787259);
        b = md5ii(b, c, d, a, blks[i + 9], 21, -343485551);

        a = safeAdd(a, olda);
        b = safeAdd(b, oldb);
        c = safeAdd(c, oldc);
        d = safeAdd(d, oldd);
    }

    function wordToHex(val) {
        let hex = "";
        for (let j = 0; j <= 3; j++) {
            const byte = (val >>> (j * 8)) & 255;
            hex += byte.toString(16).padStart(2, "0");
        }
        return hex;
    }

    return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

function calculateCRC32(input) {
    let bytes;
    if (typeof input === "string") {
        bytes = utf8Encoder.encode(input);
    } else if (input instanceof ArrayBuffer) {
        bytes = new Uint8Array(input);
    } else if (input instanceof Uint8Array) {
        bytes = input;
    } else {
        bytes = new Uint8Array(0);
    }

    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let c = i;
        for (let j = 0; j < 8; j++) {
            c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        }
        table[i] = c;
    }

    let crc = 0 ^ (-1);
    for (let i = 0; i < bytes.length; i++) {
        crc = (crc >>> 8) ^ table[(crc ^ bytes[i]) & 0xff];
    }
    crc = (crc ^ (-1)) >>> 0;
    return crc.toString(16).padStart(8, "0").toLowerCase();
}

function hexToBytes(hex) {
    const clean = hex.replace(/[^0-9a-fA-F]/g, "");
    if (clean.length % 2 !== 0) {
        throw new Error("Hex input must contain an even number of hex characters (byte pairs).");
    }
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
        bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
    }
    return bytes;
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

    console.log("\n\x1b[1m6. Multi-Algorithm Hash Calculator Tests\x1b[0m");

    await test("MD5: Empty input produces standard RFC 1321 constant", () => {
        assertEqual(calculateMD5(""), "d41d8cd98f00b204e9800998ecf8427e");
    });

    await test("MD5: Fox vector matches known hash", () => {
        assertEqual(calculateMD5("The quick brown fox jumps over the lazy dog"), "9e107d9d372bb6826bd81d3542a419d6");
    });

    await test("SHA-1: Empty input produces standard FIPS 180-1 constant", async () => {
        const hash = await calculateDigest("SHA-1", new Uint8Array(0));
        assertEqual(hash, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    });

    await test("SHA-512: Empty input produces standard FIPS 180-4 constant", async () => {
        const hash = await calculateDigest("SHA-512", new Uint8Array(0));
        assertEqual(hash, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    });

    await test("SHA-384: Empty input produces standard FIPS 180-4 constant", async () => {
        const hash = await calculateDigest("SHA-384", new Uint8Array(0));
        assertEqual(hash, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    });

    await test("CRC-32: Empty input produces 00000000 and 123456789 produces cbf43926", () => {
        assertEqual(calculateCRC32(""), "00000000");
        assertEqual(calculateCRC32("123456789"), "cbf43926");
    });

    await test("Hex string decoder parses byte pairs and throws on invalid length", () => {
        const bytes = hexToBytes("48656c6c6f");
        assertEqual(Array.from(bytes).map(b => String.fromCharCode(b)).join(""), "Hello");
        let threw = false;
        try {
            hexToBytes("abc");
        } catch {
            threw = true;
        }
        assertTrue(threw, "Odd-length hex string must throw an error");
    });

    // Summary
    console.log("\n" + "=".repeat(50));
    console.log(`Results: \x1b[32m${passedCount} passed\x1b[0m, \x1b[31m${failedCount} failed\x1b[0m out of ${passedCount + failedCount} tests.`);
    if (failedCount > 0) {
        console.error("\nFailures:");
        failures.forEach(f => console.error(`- ${f.name}: ${f.error}`));
        process.exit(1);
    } else {
        console.log("\x1b[32m\x1b[1m✔ All validation and hash calculator tests passed successfully!\x1b[0m\n");
    }
}

runTestSuite();
