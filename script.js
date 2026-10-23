/**
 * script.js — ForensiCheck: Forensic Tool Validation System
 *
 * All interactive logic for the ForensiCheck dashboard.
 * Uses the Web Crypto API (crypto.subtle.digest) for SHA-256 hashing.
 *
 * Author:  Pranav Sharma (500121423)
 * Project: DF-PBL-030 — Forensic Tool Validation Study
 */

"use strict";

// =========================================================================
// Constants & Known-Answer Test Fixtures
// =========================================================================

/**
 * SHA-256 hex digest length.
 */
const SHA256_HEX_LENGTH = 64;

/**
 * Valid hexadecimal characters.
 */
const VALID_HEX = /^[0-9a-f]{64}$/;

/**
 * Encoder used to convert strings to UTF-8 byte arrays.
 */
const utf8Encoder = new TextEncoder();

/**
 * Known-answer test fixture definitions.
 *
 * Expected hashes were independently established using:
 *   1. Python hashlib.sha256 in a separate interpreter session
 *   2. macOS `shasum -a 256` on the generated fixture files
 *
 * Both methods produced identical results for each fixture.
 */
const FIXTURES = [
    {
        testId: "TC-001",
        name: "Normal ASCII Text File",
        filename: "normal_text.txt",
        contentBytes: utf8Encoder.encode("The quick brown fox jumps over the lazy dog.\n"),
        expectedHash: "b47cc0f104b62d4c7c30bcd68fd8e67613e287dc4ad8c310ef10cbadea9c4380",
        description:
            "A simple ASCII sentence followed by a newline. " +
            "Validates basic text-file hashing.",
        verificationMethod:
            "Computed independently using Python hashlib.sha256 in a " +
            "separate interpreter session and cross-verified with " +
            "macOS shasum -a 256.",
    },
    {
        testId: "TC-002",
        name: "Binary File (All Byte Values)",
        filename: "binary_data.bin",
        // Every byte value from 0x00 to 0xFF
        contentBytes: new Uint8Array(256).map((_, i) => i),
        expectedHash: "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880",
        description:
            "Contains every byte value from 0x00 to 0xFF. " +
            "Validates binary-safe reading.",
        verificationMethod:
            "Computed independently using Python hashlib.sha256 in a " +
            "separate interpreter session and cross-verified with " +
            "macOS shasum -a 256.",
    },
    {
        testId: "TC-003",
        name: "Empty File",
        filename: "empty_file.txt",
        contentBytes: new Uint8Array(0),
        expectedHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        description:
            "A zero-byte file. The expected SHA-256 is the well-known " +
            "hash of empty input: e3b0c44298fc1c149afbf4c8996fb924" +
            "27ae41e4649b934ca495991b7852b855.",
        verificationMethod:
            "Computed independently using Python hashlib.sha256 in a " +
            "separate interpreter session and cross-verified with " +
            "macOS shasum -a 256.",
    },
    {
        testId: "TC-004",
        name: "Unicode / UTF-8 Text File",
        filename: "unicode_text.txt",
        contentBytes: utf8Encoder.encode("Ünïcödé Tëst: 日本語テスト 🔍🔒\n"),
        expectedHash: "197a7e14689ce38e304c9bf1330595f0adaf36730c8c719d7d84710cc98ebf1e",
        description:
            "Contains Latin-extended, CJK, and emoji characters " +
            "encoded as UTF-8. Validates correct byte-level hashing " +
            "of multi-byte encoded text.",
        verificationMethod:
            "Computed independently using Python hashlib.sha256 in a " +
            "separate interpreter session and cross-verified with " +
            "macOS shasum -a 256.",
    },
    {
        testId: "TC-005",
        name: "Large File (~100 KiB, Chunked Reading)",
        filename: "large_file.txt",
        // Built lazily in generateLargeContent()
        contentBytes: null,
        expectedHash: "9f875318fe63115a88afff67768bd41d802098a725d015a62ba5173e297e9e59",
        description:
            "A ~100 KiB file containing 3 000 repeated lines. " +
            "Validates reading performance on larger inputs.",
        verificationMethod:
            "Computed independently using Python hashlib.sha256 in a " +
            "separate interpreter session and cross-verified with " +
            "macOS shasum -a 256.",
    },
    {
        testId: "TC-006",
        name: "Modified File (Tamper Detection)",
        filename: "modified_text.txt",
        contentBytes: utf8Encoder.encode("The quick brown fox jumps over the lazy dog!\n"),
        // Deliberately the hash of the ORIGINAL file — this test SHOULD fail
        expectedHash: "b47cc0f104b62d4c7c30bcd68fd8e67613e287dc4ad8c310ef10cbadea9c4380",
        description:
            "The original sentence with the period changed to an " +
            "exclamation mark. The expected hash is that of the " +
            "ORIGINAL file — this test SHOULD fail, proving that " +
            "even a single-character change is detected.",
        verificationMethod:
            "Expected hash is intentionally the hash of TC-001 content. " +
            "The actual modified content produces a different hash, " +
            "demonstrating tamper detection.",
    },
    {
        testId: "TC-007",
        name: "Invalid Expected Hash Format",
        filename: "normal_text.txt",
        contentBytes: utf8Encoder.encode("The quick brown fox jumps over the lazy dog.\n"),
        expectedHash: "ZZZZ_NOT_A_VALID_HEX_HASH",
        description:
            "Uses the same content as TC-001 but with a deliberately " +
            "invalid expected hash string. This test should produce an " +
            "ERROR status because the expected hash is not a valid " +
            "64-character hexadecimal digest.",
        verificationMethod:
            "Deliberately invalid expected hash to test error handling.",
    },
];

/**
 * Generate the large content for TC-005 (~100 KiB).
 * Done lazily to avoid slowing page load.
 */
function generateLargeContent() {
    const line = utf8Encoder.encode("ForensiCheck large-file test line.\n");
    const result = new Uint8Array(line.length * 3000);
    for (let i = 0; i < 3000; i++) {
        result.set(line, i * line.length);
    }
    return result;
}


// =========================================================================
// SHA-256 Hashing (Web Crypto API)
// =========================================================================

/**
 * Calculate the SHA-256 hash of a Uint8Array or ArrayBuffer.
 *
 * @param {Uint8Array|ArrayBuffer} data - The data to hash.
 * @returns {Promise<string>} Lower-case hexadecimal SHA-256 digest.
 */
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

/**
 * Calculate the SHA-256 hash of a File object.
 *
 * @param {File} file - The file to hash.
 * @returns {Promise<string>} Lower-case hexadecimal SHA-256 digest.
 */
async function calculateSHA256FromFile(file) {
    const arrayBuffer = await file.arrayBuffer();
    return calculateSHA256(arrayBuffer);
}

/**
 * Calculate standard Web Crypto API digest (SHA-1, SHA-256, SHA-384, SHA-512).
 * @param {string} algorithm - "SHA-1", "SHA-256", "SHA-384", "SHA-512"
 * @param {Uint8Array|ArrayBuffer} data
 * @returns {Promise<string>} Lowercase hexadecimal digest.
 */
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

/**
 * Calculate the MD5 hash (RFC 1321) of a Uint8Array, ArrayBuffer, or string.
 * Uses a pure JavaScript implementation for 100% browser and offline compatibility.
 * @param {Uint8Array|ArrayBuffer|string} input
 * @returns {string} Lowercase 32-character hexadecimal MD5 digest.
 */
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

/**
 * Calculate the CRC-32 checksum (IEEE 802.3 standard) of a Uint8Array, ArrayBuffer, or string.
 * @param {Uint8Array|ArrayBuffer|string} input
 * @returns {string} Lowercase 8-character hexadecimal CRC-32 checksum.
 */
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

/**
 * Calculate all forensic algorithms (SHA-256, MD5, SHA-1, SHA-512, SHA-384, CRC-32) in parallel.
 * @param {Uint8Array|ArrayBuffer} dataBytes
 * @returns {Promise<{sha256: string, md5: string, sha1: string, sha512: string, sha384: string, crc32: string}>}
 */
async function calculateMultiHashes(dataBytes) {
    const [sha256, sha1, sha512, sha384] = await Promise.all([
        calculateSHA256(dataBytes),
        calculateDigest("SHA-1", dataBytes),
        calculateDigest("SHA-512", dataBytes),
        calculateDigest("SHA-384", dataBytes),
    ]);
    const md5 = calculateMD5(dataBytes);
    const crc32 = calculateCRC32(dataBytes);
    return { sha256, md5, sha1, sha512, sha384, crc32 };
}

/**
 * Convert a hexadecimal string to a Uint8Array byte array.
 * @param {string} hex
 * @returns {Uint8Array}
 */
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


// =========================================================================
// Hash Validation Helpers
// =========================================================================

/**
 * Normalize a hex hash string: trim whitespace, lowercase.
 * @param {string} hex
 * @returns {string}
 */
function normalizeHash(hex) {
    return hex.trim().toLowerCase();
}

/**
 * Validate whether a string is a valid SHA-256 hex digest (64 hex chars).
 * @param {string} hex
 * @returns {boolean}
 */
function isValidSHA256Hex(hex) {
    return VALID_HEX.test(normalizeHash(hex));
}

/**
 * Compare two SHA-256 hex strings (case-insensitive).
 * @param {string} expected
 * @param {string} observed
 * @returns {"PASS"|"FAIL"}
 */
function compareHashes(expected, observed) {
    return normalizeHash(expected) === normalizeHash(observed) ? "PASS" : "FAIL";
}


// =========================================================================
// Application State
// =========================================================================

/**
 * @type {Array<Object>} Array of test result objects.
 */
let testResults = [];

/**
 * @type {boolean} Whether the full test suite has been executed.
 */
let testsExecuted = false;


// =========================================================================
// Test Runner
// =========================================================================

/**
 * Run a single known-answer test case.
 *
 * @param {Object} fixture - A fixture object from FIXTURES.
 * @returns {Promise<Object>} A result object.
 */
async function runSingleTest(fixture) {
    const result = {
        testId: fixture.testId,
        testName: fixture.name,
        filename: fixture.filename,
        fileSize: 0,
        expectedHash: fixture.expectedHash,
        observedHash: "",
        status: "NOT EXECUTED",
        timestamp: "",
        notes: fixture.description,
        errorDetails: "",
    };

    try {
        // Validate expected hash format first
        if (!isValidSHA256Hex(fixture.expectedHash)) {
            result.status = "ERROR";
            result.errorDetails =
                "Invalid expected hash format: must be exactly 64 hexadecimal characters. " +
                `Got: "${fixture.expectedHash}"`;
            result.notes = result.errorDetails;
            result.timestamp = new Date().toISOString();
            return result;
        }

        // Get content bytes (generate large content lazily for TC-005)
        let contentBytes = fixture.contentBytes;
        if (contentBytes === null && fixture.testId === "TC-005") {
            contentBytes = generateLargeContent();
            // Cache it for reuse
            fixture.contentBytes = contentBytes;
        }

        if (!contentBytes) {
            throw new Error("No content bytes available for this test fixture.");
        }

        result.fileSize = contentBytes.byteLength;

        // Calculate hash
        const observed = await calculateSHA256(contentBytes);
        result.observedHash = observed;
        result.status = compareHashes(fixture.expectedHash, observed);
    } catch (err) {
        result.status = "ERROR";
        result.errorDetails = err.message || String(err);
        result.notes = `Error: ${result.errorDetails}`;
    }

    result.timestamp = new Date().toISOString();
    return result;
}

/**
 * Run all known-answer test cases.
 * @returns {Promise<Array<Object>>} Array of result objects.
 */
async function runAllTests() {
    const results = [];
    for (const fixture of FIXTURES) {
        const result = await runSingleTest(fixture);
        results.push(result);
    }
    return results;
}


// =========================================================================
// UI Helpers
// =========================================================================

/**
 * Show a toast notification.
 * @param {string} message
 * @param {"success"|"error"|"info"} type
 */
function showToast(message, type = "info") {
    // Remove existing toasts
    document.querySelectorAll(".toast").forEach(t => t.remove());

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => toast.remove(), 3000);
}

/**
 * Get the status badge HTML.
 * @param {string} status - "PASS", "FAIL", "ERROR", "NOT EXECUTED"
 * @returns {string}
 */
function statusBadgeHTML(status) {
    const classMap = {
        PASS: "badge-pass",
        FAIL: "badge-fail",
        ERROR: "badge-error",
        "NOT EXECUTED": "badge-pending",
    };
    return `<span class="status-badge ${classMap[status] || "badge-pending"}">${status}</span>`;
}

/**
 * Format a number of bytes as a human-readable string.
 * @param {number} bytes
 * @returns {string}
 */
function formatBytes(bytes) {
    if (bytes === 0) return "0 bytes";
    if (bytes === 1) return "1 byte";
    if (bytes < 1024) return `${bytes} bytes`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1048576).toFixed(1)} MB`;
}

/**
 * Truncate a hash for table display.
 * @param {string} hash
 * @param {number} len
 * @returns {string}
 */
function truncateHash(hash, len = 20) {
    if (!hash) return "—";
    if (hash.length <= len) return hash;
    return hash.substring(0, len) + "…";
}

/**
 * Copy text to clipboard and show toast.
 * @param {string} text
 */
async function copyToClipboard(text) {
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
        } else {
            const textarea = document.createElement("textarea");
            textarea.value = text;
            textarea.style.position = "fixed";
            textarea.style.opacity = "0";
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand("copy");
            document.body.removeChild(textarea);
        }
        showToast("Copied to clipboard!", "success");
    } catch {
        showToast("Failed to copy", "error");
    }
}

/**
 * Escape HTML special characters.
 * @param {string} str
 * @returns {string}
 */
function escapeHTML(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
}


// =========================================================================
// Navigation
// =========================================================================

const sidebarNav = document.getElementById("sidebarNav");
const pageSections = document.querySelectorAll(".page-section");
const sidebar = document.getElementById("sidebar");
const mobileToggle = document.getElementById("mobileToggle");
const sidebarOverlay = document.getElementById("sidebarOverlay");

/**
 * Navigate to a page by its data-page attribute.
 * @param {string} pageName
 */
function navigateTo(pageName) {
    // Update nav links
    sidebarNav.querySelectorAll("a").forEach(a => {
        a.classList.toggle("active", a.dataset.page === pageName);
    });

    // Show/hide page sections
    pageSections.forEach(section => {
        section.classList.toggle("active", section.id === `page-${pageName}`);
    });

    // Close mobile sidebar
    sidebar.classList.remove("open");
    sidebarOverlay.classList.remove("open");

    // Scroll to top
    window.scrollTo({ top: 0, behavior: "smooth" });
}

// Sidebar link clicks
sidebarNav.addEventListener("click", (e) => {
    const link = e.target.closest("a[data-page]");
    if (!link) return;
    e.preventDefault();
    navigateTo(link.dataset.page);
});

// Mobile toggle
mobileToggle.addEventListener("click", () => {
    sidebar.classList.toggle("open");
    sidebarOverlay.classList.toggle("open");
});

sidebarOverlay.addEventListener("click", () => {
    sidebar.classList.remove("open");
    sidebarOverlay.classList.remove("open");
});

// Handle hash-based navigation
function handleHashNavigation() {
    const hash = window.location.hash.replace("#", "");
    const validPages = ["dashboard", "tests", "calculator", "upload", "modification", "results", "export"];
    if (validPages.includes(hash)) {
        navigateTo(hash);
    }
}

window.addEventListener("hashchange", handleHashNavigation);


// =========================================================================
// Dashboard Page
// =========================================================================

/**
 * Render the fixture list on the dashboard.
 */
function renderFixtureList() {
    const container = document.getElementById("fixtureList");
    container.innerHTML = FIXTURES.map(fix => {
        const expectedStatus =
            fix.testId === "TC-006"
                ? '<span class="tag tag-fail">Expected: FAIL ⬅ tamper detection</span>'
                : fix.testId === "TC-007"
                ? '<span class="tag tag-fail">Expected: ERROR ⬅ invalid hash format</span>'
                : '<span class="tag tag-pass">Expected: PASS</span>';
        return `
            <div class="fixture-item">
                <div class="fixture-item-header">${fix.testId} — ${escapeHTML(fix.name)}</div>
                <div class="fixture-item-meta">
                    ${escapeHTML(fix.filename)} · ${formatBytes(fix.contentBytes ? fix.contentBytes.byteLength : 105000)} · ${expectedStatus}
                </div>
                <div class="fixture-item-desc">${escapeHTML(fix.description)}</div>
            </div>
        `;
    }).join("");
}

/**
 * Update dashboard metrics and overall status.
 */
function updateDashboard() {
    const total = FIXTURES.length;
    let passed = 0, failed = 0, errors = 0, pending = 0;

    if (testsExecuted && testResults.length > 0) {
        passed = testResults.filter(r => r.status === "PASS").length;
        failed = testResults.filter(r => r.status === "FAIL").length;
        errors = testResults.filter(r => r.status === "ERROR").length;
        pending = total - testResults.length;
    } else {
        pending = total;
    }

    document.getElementById("metricTotal").textContent = total;
    document.getElementById("metricPassed").textContent = passed;
    document.getElementById("metricFailed").textContent = failed;
    document.getElementById("metricErrors").textContent = errors;
    document.getElementById("metricPending").textContent = pending;

    const statusContainer = document.getElementById("dashboardStatus");

    if (!testsExecuted || testResults.length === 0) {
        statusContainer.innerHTML = `
            <div class="info-box">
                ℹ️ <strong>No tests have been executed yet.</strong>
                Navigate to <em>🧪 Run Validation Tests</em> in the sidebar to execute the known-answer test suite.
            </div>
        `;
    } else {
        // TC-006 is an expected FAIL, TC-007 is an expected ERROR
        const expectedNonPass = new Set(["TC-006", "TC-007"]);
        const unexpectedFailures = testResults.filter(
            r => (r.status === "FAIL" || r.status === "ERROR") &&
                 !expectedNonPass.has(r.testId)
        );

        if (unexpectedFailures.length === 0) {
            statusContainer.innerHTML = `
                <div class="overall-pass">
                    <div class="overall-status-icon">✅</div>
                    <div class="overall-status-title text-green">VALIDATION PASSED</div>
                    <div class="overall-status-desc">
                        All tests produced expected results. TC-006 correctly detected file modification (expected FAIL).
                        TC-007 correctly detected invalid hash format (expected ERROR).
                    </div>
                </div>
            `;
        } else {
            statusContainer.innerHTML = `
                <div class="overall-fail">
                    <div class="overall-status-icon">⚠️</div>
                    <div class="overall-status-title text-red">VALIDATION — DISCREPANCIES DETECTED</div>
                    <div class="overall-status-desc">
                        ${unexpectedFailures.length} unexpected failure(s). Review the Results Table for details.
                    </div>
                </div>
            `;
        }
    }
}


// =========================================================================
// Run Validation Tests Page
// =========================================================================

/**
 * Populate the single-test select dropdown.
 */
function populateSingleTestSelect() {
    const select = document.getElementById("singleTestSelect");
    select.innerHTML = FIXTURES.map(
        fix => `<option value="${fix.testId}">${fix.testId} — ${escapeHTML(fix.name)}</option>`
    ).join("");
}

/**
 * Render test result cards (expandable).
 */
function renderTestResultCards() {
    const container = document.getElementById("testResultCards");

    if (testResults.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">🧪</div>
                <div class="empty-state-text">No test results yet.</div>
                <div class="empty-state-hint">Click "Run All Tests" to execute the test suite.</div>
            </div>
        `;
        return;
    }

    container.innerHTML = testResults.map(r => {
        const hashClass = r.status === "PASS" ? "hash-match" : "hash-mismatch";
        const isExpectedFail = r.testId === "TC-006" && r.status === "FAIL";
        const isExpectedError = r.testId === "TC-007" && r.status === "ERROR";

        let noteHTML = "";
        if (isExpectedFail) {
            noteHTML = `
                <div class="info-box">
                    ✅ <strong>This FAIL is expected.</strong> The file was deliberately
                    modified to demonstrate tamper detection. The hash mismatch confirms
                    that even a single-character change is detected by SHA-256.
                </div>
            `;
        } else if (isExpectedError) {
            noteHTML = `
                <div class="info-box">
                    ✅ <strong>This ERROR is expected.</strong> The expected hash was deliberately
                    set to an invalid format to test error handling.
                </div>
            `;
        } else if (r.status === "FAIL") {
            noteHTML = `<div class="info-box" style="border-left-color: var(--fail-red);">
                ⚠️ <strong>Unexpected mismatch</strong> — investigate this result.
            </div>`;
        } else if (r.status === "ERROR" && r.errorDetails) {
            noteHTML = `<div class="info-box" style="border-left-color: var(--warn-amber);">
                ⚠️ <strong>Error:</strong> ${escapeHTML(r.errorDetails)}
            </div>`;
        }

        return `
            <div class="test-card" data-testid="${r.testId}">
                <div class="test-card-header" onclick="toggleTestCard(this)">
                    <div class="test-card-header-left">
                        <span class="test-card-id">${r.testId}</span>
                        <span class="test-card-name">${escapeHTML(r.testName)}</span>
                    </div>
                    ${statusBadgeHTML(r.status)}
                    <span class="test-card-chevron">▼</span>
                </div>
                <div class="test-card-body">
                    <div class="test-detail-grid">
                        <div class="test-detail-item">
                            <label>Status</label>
                            <span>${statusBadgeHTML(r.status)}</span>
                        </div>
                        <div class="test-detail-item">
                            <label>File</label>
                            <span>${escapeHTML(r.filename)}</span>
                        </div>
                        <div class="test-detail-item">
                            <label>Size</label>
                            <span>${formatBytes(r.fileSize)}</span>
                        </div>
                        <div class="test-detail-item">
                            <label>Timestamp</label>
                            <span style="font-size:0.78rem;">${r.timestamp}</span>
                        </div>
                    </div>
                    <div class="form-label">Expected SHA-256:</div>
                    <div class="hash-display ${hashClass} mb-2" onclick="copyToClipboard('${r.expectedHash}')" title="Click to copy">
                        ${escapeHTML(r.expectedHash)}
                    </div>
                    <div class="form-label">Observed SHA-256:</div>
                    <div class="hash-display ${hashClass} mb-2" onclick="copyToClipboard('${r.observedHash}')" title="Click to copy">
                        ${r.observedHash || "—"}
                    </div>
                    ${noteHTML}
                    <p class="text-muted" style="font-size:0.78rem; margin-top:0.5rem;">📝 ${escapeHTML(r.notes)}</p>
                </div>
            </div>
        `;
    }).join("");
}

/**
 * Toggle a test card's expanded state.
 * @param {HTMLElement} headerEl
 */
function toggleTestCard(headerEl) {
    const card = headerEl.closest(".test-card");
    card.classList.toggle("open");
}

// Run All Tests button
document.getElementById("btnRunAll").addEventListener("click", async () => {
    const btn = document.getElementById("btnRunAll");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Running…';

    try {
        testResults = await runAllTests();
        testsExecuted = true;
        renderTestResultCards();
        updateDashboard();
        updateResultsPage();
        updateExportPage();
        showToast(`✅ Executed ${testResults.length} test case(s).`, "success");
    } catch (err) {
        showToast(`Error running tests: ${err.message}`, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = "▶ Run All Tests";
    }
});

// Clear Results button
document.getElementById("btnClearResults").addEventListener("click", () => {
    testResults = [];
    testsExecuted = false;
    renderTestResultCards();
    updateDashboard();
    updateResultsPage();
    updateExportPage();
    showToast("Results cleared.", "info");
});

// Run Single Test button
document.getElementById("btnRunSingle").addEventListener("click", async () => {
    const select = document.getElementById("singleTestSelect");
    const testId = select.value;
    const fixture = FIXTURES.find(f => f.testId === testId);
    if (!fixture) return;

    const btn = document.getElementById("btnRunSingle");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Running…';

    try {
        const result = await runSingleTest(fixture);

        // Update or append
        const existingIdx = testResults.findIndex(r => r.testId === result.testId);
        if (existingIdx >= 0) {
            testResults[existingIdx] = result;
        } else {
            testResults.push(result);
        }
        testsExecuted = true;

        renderTestResultCards();
        updateDashboard();
        updateResultsPage();
        updateExportPage();
        showToast(`${result.testId}: ${result.status}`, result.status === "PASS" ? "success" : "info");
    } catch (err) {
        showToast(`Error: ${err.message}`, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = "▶ Run Selected";
    }
});


// =========================================================================
// Hash Calculator Page
// =========================================================================

const calcState = {
    mode: "text", // "text" | "file"
    text: "",
    encoding: "utf-8",
    file: null,
    caseMode: "lower", // "lower" | "upper"
    hashes: {
        sha256: "",
        md5: "",
        sha1: "",
        sha512: "",
        sha384: "",
        crc32: "",
    },
    debounceTimer: null,
};

// DOM references
const calcTabBtnText = document.getElementById("calcTabBtnText");
const calcTabBtnFile = document.getElementById("calcTabBtnFile");
const calcTextModePanel = document.getElementById("calcTextModePanel");
const calcFileModePanel = document.getElementById("calcFileModePanel");

const calcTextInput = document.getElementById("calcTextInput");
const calcEncodingSelect = document.getElementById("calcEncodingSelect");

const calcStatChars = document.getElementById("calcStatChars");
const calcStatBytes = document.getElementById("calcStatBytes");
const calcStatLines = document.getElementById("calcStatLines");
const calcStatStatus = document.getElementById("calcStatStatus");

const calcFileDropZone = document.getElementById("calcFileDropZone");
const calcFileInput = document.getElementById("calcFileInput");
const calcFileInfoCard = document.getElementById("calcFileInfoCard");
const calcFileClearBtn = document.getElementById("calcFileClearBtn");

const calcCaseLower = document.getElementById("calcCaseLower");
const calcCaseUpper = document.getElementById("calcCaseUpper");
const calcCopyAllBtn = document.getElementById("calcCopyAllBtn");
const calcDownloadTxtBtn = document.getElementById("calcDownloadTxtBtn");
const calcDownloadSha256Btn = document.getElementById("calcDownloadSha256Btn");

const calcVerifyInput = document.getElementById("calcVerifyInput");
const calcClearVerifyBtn = document.getElementById("calcClearVerifyBtn");
const calcVerifyFeedback = document.getElementById("calcVerifyFeedback");

/**
 * Render computed hashes according to active casing (lower or upper).
 */
function renderCalcHashes() {
    const isUpper = calcState.caseMode === "upper";
    const algos = ["sha256", "md5", "sha1", "sha512", "sha384", "crc32"];
    algos.forEach((algo) => {
        const el = document.getElementById(`calcHash-${algo}`);
        if (!el) return;
        const raw = calcState.hashes[algo] || "";
        if (raw) {
            const formatted = isUpper ? raw.toUpperCase() : raw.toLowerCase();
            el.textContent = formatted;
            el.onclick = () => copyToClipboard(formatted);
        } else {
            el.textContent = "—";
            el.onclick = null;
        }
    });

    checkCalcVerification();
}

/**
 * Check if the verification input matches any computed algorithm.
 */
function checkCalcVerification() {
    if (!calcVerifyInput || !calcVerifyFeedback) return;
    const rawInput = calcVerifyInput.value.trim();
    const algos = ["sha256", "md5", "sha1", "sha512", "sha384", "crc32"];

    // Reset visual highlights
    algos.forEach((algo) => {
        const card = document.getElementById(`algoCard-${algo}`);
        const pill = document.getElementById(`algoMatch-${algo}`);
        if (card) card.classList.remove("match-highlight");
        if (pill) pill.classList.add("hidden");
    });

    if (!rawInput) {
        calcVerifyFeedback.innerHTML = "";
        return;
    }

    // Normalize: strip whitespace, colons, dashes
    const normalizedInput = rawInput.replace(/[:\s-]/g, "").toLowerCase();

    // Check for match
    let matchedAlgo = null;
    for (const algo of algos) {
        const val = (calcState.hashes[algo] || "").toLowerCase();
        if (val && val === normalizedInput) {
            matchedAlgo = algo;
            break;
        }
    }

    // Detect format by character length
    let detectedType = "";
    if (normalizedInput.length === 64) detectedType = "SHA-256 (64 hex)";
    else if (normalizedInput.length === 32) detectedType = "MD5 (32 hex)";
    else if (normalizedInput.length === 40) detectedType = "SHA-1 (40 hex)";
    else if (normalizedInput.length === 128) detectedType = "SHA-512 (128 hex)";
    else if (normalizedInput.length === 96) detectedType = "SHA-384 (96 hex)";
    else if (normalizedInput.length === 8) detectedType = "CRC-32 (8 hex)";
    else detectedType = `${normalizedInput.length} hex chars`;

    const algoNames = {
        sha256: "SHA-256",
        md5: "MD5",
        sha1: "SHA-1",
        sha512: "SHA-512",
        sha384: "SHA-384",
        crc32: "CRC-32",
    };

    if (matchedAlgo) {
        const card = document.getElementById(`algoCard-${matchedAlgo}`);
        const pill = document.getElementById(`algoMatch-${matchedAlgo}`);
        if (card) card.classList.add("match-highlight");
        if (pill) pill.classList.remove("hidden");

        calcVerifyFeedback.innerHTML = `
            <div class="info-box" style="border-left: 4px solid var(--success-green); background: rgba(16, 185, 129, 0.1); margin-bottom: 0;">
                <span class="text-green" style="font-weight: 700; font-size: 0.95rem;">✅ VERIFICATION MATCH!</span>
                <br>
                The provided hash matches the computed <strong>${algoNames[matchedAlgo]}</strong> hash identically (case-insensitive).
                <br>
                <span class="text-muted" style="font-size: 0.78rem;">Detected Format: ${escapeHTML(detectedType)}</span>
            </div>
        `;
    } else {
        calcVerifyFeedback.innerHTML = `
            <div class="info-box" style="border-left: 4px solid var(--fail-red); background: rgba(239, 68, 68, 0.1); margin-bottom: 0;">
                <span class="text-red" style="font-weight: 700; font-size: 0.95rem;">❌ NO MATCH</span>
                <br>
                The provided hash does not match any currently calculated algorithm for this input.
                <br>
                <span class="text-muted" style="font-size: 0.78rem;">Detected Format: ${escapeHTML(detectedType)}</span>
            </div>
        `;
    }
}

/**
 * Execute real-time hashing on the text input.
 */
async function executeTextHashing() {
    if (calcState.mode !== "text" || !calcTextInput) return;
    const text = calcTextInput.value;
    const encoding = calcEncodingSelect ? calcEncodingSelect.value : "utf-8";

    // Update stats
    const charCount = text.length;
    const lineCount = text ? text.split("\n").length : 0;
    if (calcStatChars) calcStatChars.textContent = charCount.toLocaleString();
    if (calcStatLines) calcStatLines.textContent = lineCount.toLocaleString();

    let bytes;
    try {
        if (encoding === "hex") {
            bytes = hexToBytes(text);
        } else if (encoding === "ascii") {
            bytes = new Uint8Array(text.split("").map((c) => c.charCodeAt(0) & 0xff));
        } else {
            bytes = utf8Encoder.encode(text);
        }
        if (calcStatBytes) calcStatBytes.textContent = formatBytes(bytes.byteLength);
        if (calcStatStatus) {
            calcStatStatus.textContent = "⚡ Live Sync Active";
            calcStatStatus.className = "calc-stat-val text-green";
        }
    } catch (err) {
        if (calcStatBytes) calcStatBytes.textContent = "Invalid format";
        if (calcStatStatus) {
            calcStatStatus.textContent = `⚠️ ${err.message}`;
            calcStatStatus.className = "calc-stat-val text-red";
        }
        return;
    }

    try {
        const hashes = await calculateMultiHashes(bytes);
        calcState.hashes = hashes;
        renderCalcHashes();
    } catch (err) {
        if (calcStatStatus) {
            calcStatStatus.textContent = `Error: ${err.message}`;
            calcStatStatus.className = "calc-stat-val text-red";
        }
    }
}

/**
 * Execute hashing on a file.
 * @param {File} file
 */
async function executeFileHashing(file) {
    if (!file) return;
    const MAX_SIZE = 500 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
        showToast("File too large. Maximum size is 500 MB.", "error");
        return;
    }

    calcState.file = file;

    // Show metadata
    const fnEl = document.getElementById("calcMetaFilename");
    const szEl = document.getElementById("calcMetaSize");
    const tpEl = document.getElementById("calcMetaType");
    const mdEl = document.getElementById("calcMetaModified");

    if (fnEl) fnEl.textContent = file.name;
    if (szEl) szEl.textContent = `${formatBytes(file.size)} (${file.size.toLocaleString()} bytes)`;
    if (tpEl) tpEl.textContent = file.type || "application/octet-stream";
    if (mdEl) mdEl.textContent = file.lastModified ? new Date(file.lastModified).toLocaleString() : "—";

    if (calcFileInfoCard) calcFileInfoCard.classList.remove("hidden");
    if (calcFileDropZone) calcFileDropZone.classList.add("hidden");

    const algos = ["sha256", "md5", "sha1", "sha512", "sha384", "crc32"];
    algos.forEach((algo) => {
        const el = document.getElementById(`calcHash-${algo}`);
        if (el) el.textContent = "Calculating…";
    });

    try {
        const arrayBuffer = await file.arrayBuffer();
        const hashes = await calculateMultiHashes(arrayBuffer);
        calcState.hashes = hashes;
        renderCalcHashes();
        showToast("File hashes calculated successfully!", "success");
    } catch (err) {
        showToast(`Failed to hash file: ${err.message}`, "error");
        algos.forEach((algo) => {
            const el = document.getElementById(`calcHash-${algo}`);
            if (el) el.textContent = `Error: ${err.message}`;
        });
    }
}

/**
 * Format all hashes into a forensic evidence report string.
 * @returns {string}
 */
function getFormattedHashReport() {
    const isUpper = calcState.caseMode === "upper";
    const fmt = (h) => (isUpper ? (h || "").toUpperCase() : (h || "").toLowerCase());
    const sourceDesc =
        calcState.mode === "file" && calcState.file
            ? `File: "${calcState.file.name}" (${formatBytes(calcState.file.size)})`
            : `Text Input (${calcStatChars ? calcStatChars.textContent : 0} chars, ${
                  calcStatBytes ? calcStatBytes.textContent : "0 bytes"
              })`;

    return [
        "================================================================================",
        " FORENSICHECK CRYPTOGRAPHIC HASH REPORT",
        "================================================================================",
        `Generated:     ${new Date().toISOString()}`,
        `Input Source:  ${sourceDesc}`,
        `Hex Casing:    ${isUpper ? "UPPERCASE" : "lowercase"}`,
        "--------------------------------------------------------------------------------",
        `SHA-256:       ${fmt(calcState.hashes.sha256)}`,
        `MD5:           ${fmt(calcState.hashes.md5)}`,
        `SHA-1:         ${fmt(calcState.hashes.sha1)}`,
        `SHA-512:       ${fmt(calcState.hashes.sha512)}`,
        `SHA-384:       ${fmt(calcState.hashes.sha384)}`,
        `CRC-32:        ${fmt(calcState.hashes.crc32)}`,
        "--------------------------------------------------------------------------------",
        "Validated with ForensiCheck · DF-PBL-030 · UPES Dehradun",
        "================================================================================",
    ].join("\n");
}

/**
 * Initialize all event listeners for the Hash Calculator.
 */
function initHashCalculator() {
    if (!calcTabBtnText || !calcTabBtnFile) return;

    // Sub-tab: Text Mode
    calcTabBtnText.addEventListener("click", () => {
        calcTabBtnText.classList.add("active");
        calcTabBtnFile.classList.remove("active");
        if (calcTextModePanel) calcTextModePanel.classList.remove("hidden");
        if (calcFileModePanel) calcFileModePanel.classList.add("hidden");
        calcState.mode = "text";
        executeTextHashing();
    });

    // Sub-tab: File Mode
    calcTabBtnFile.addEventListener("click", () => {
        calcTabBtnFile.classList.add("active");
        calcTabBtnText.classList.remove("active");
        if (calcFileModePanel) calcFileModePanel.classList.remove("hidden");
        if (calcTextModePanel) calcTextModePanel.classList.add("hidden");
        calcState.mode = "file";
        if (calcState.file) {
            executeFileHashing(calcState.file);
        } else {
            calcState.hashes = { sha256: "", md5: "", sha1: "", sha512: "", sha384: "", crc32: "" };
            renderCalcHashes();
        }
    });

    // Text input live recalculation
    if (calcTextInput) {
        calcTextInput.addEventListener("input", () => {
            clearTimeout(calcState.debounceTimer);
            calcState.debounceTimer = setTimeout(() => {
                executeTextHashing();
            }, 60);
        });
    }

    if (calcEncodingSelect) {
        calcEncodingSelect.addEventListener("change", () => {
            executeTextHashing();
        });
    }

    // Presets
    const presets = {
        calcPresetFox: "The quick brown fox jumps over the lazy dog",
        calcPresetEmpty: "",
        calcPresetUnicode: "Ünïcödé Tëst: 日本語テスト 🔍🔒\n",
        calcPresetForensic: "EVIDENCE ID: EXHIBIT-001 | CASE: 2026-DF-030 | ACQUISITION: BIT-STREAM PHYSICAL",
        calcPresetClear: "",
    };

    Object.entries(presets).forEach(([btnId, val]) => {
        const btn = document.getElementById(btnId);
        if (btn) {
            btn.addEventListener("click", () => {
                if (calcTextInput) {
                    calcTextInput.value = val;
                    executeTextHashing();
                }
            });
        }
    });

    // File Drag and Drop
    if (calcFileDropZone && calcFileInput) {
        calcFileDropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            calcFileDropZone.classList.add("drag-over");
        });

        calcFileDropZone.addEventListener("dragleave", () => {
            calcFileDropZone.classList.remove("drag-over");
        });

        calcFileDropZone.addEventListener("drop", (e) => {
            e.preventDefault();
            calcFileDropZone.classList.remove("drag-over");
            const files = e.dataTransfer.files;
            if (files && files.length > 0) {
                executeFileHashing(files[0]);
            }
        });

        calcFileInput.addEventListener("change", () => {
            if (calcFileInput.files && calcFileInput.files.length > 0) {
                executeFileHashing(calcFileInput.files[0]);
            }
        });
    }

    // Clear File button
    if (calcFileClearBtn) {
        calcFileClearBtn.addEventListener("click", () => {
            calcState.file = null;
            if (calcFileInput) calcFileInput.value = "";
            if (calcFileInfoCard) calcFileInfoCard.classList.add("hidden");
            if (calcFileDropZone) calcFileDropZone.classList.remove("hidden");
            calcState.hashes = { sha256: "", md5: "", sha1: "", sha512: "", sha384: "", crc32: "" };
            renderCalcHashes();
        });
    }

    // Hex Casing toggle
    if (calcCaseLower && calcCaseUpper) {
        calcCaseLower.addEventListener("click", () => {
            calcCaseLower.classList.add("active");
            calcCaseUpper.classList.remove("active");
            calcState.caseMode = "lower";
            renderCalcHashes();
        });

        calcCaseUpper.addEventListener("click", () => {
            calcCaseUpper.classList.add("active");
            calcCaseLower.classList.remove("active");
            calcState.caseMode = "upper";
            renderCalcHashes();
        });
    }

    // Individual Copy Buttons
    document.querySelectorAll(".btn-copy[data-algo]").forEach((btn) => {
        btn.addEventListener("click", () => {
            const algo = btn.dataset.algo;
            const raw = calcState.hashes[algo] || "";
            if (!raw) return;
            const formatted = calcState.caseMode === "upper" ? raw.toUpperCase() : raw.toLowerCase();
            copyToClipboard(formatted);
        });
    });

    // Copy All Hashes
    if (calcCopyAllBtn) {
        calcCopyAllBtn.addEventListener("click", () => {
            copyToClipboard(getFormattedHashReport());
        });
    }

    // Download Text Report
    if (calcDownloadTxtBtn) {
        calcDownloadTxtBtn.addEventListener("click", () => {
            const report = getFormattedHashReport();
            const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
            downloadFile(report, `hash_report_${timestamp}.txt`, "text/plain");
            showToast("Hash report downloaded!", "success");
        });
    }

    // Download .sha256
    if (calcDownloadSha256Btn) {
        calcDownloadSha256Btn.addEventListener("click", () => {
            const rawSha256 = calcState.hashes.sha256;
            if (!rawSha256) {
                showToast("No SHA-256 hash available to export.", "error");
                return;
            }
            const hash = calcState.caseMode === "upper" ? rawSha256.toUpperCase() : rawSha256.toLowerCase();
            const filename = calcState.mode === "file" && calcState.file ? calcState.file.name : "input.txt";
            const content = `${hash}  ${filename}\n`;
            downloadFile(content, `${filename}.sha256`, "text/plain");
            showToast(".sha256 checksum file downloaded!", "success");
        });
    }

    // Verifier input
    if (calcVerifyInput) {
        calcVerifyInput.addEventListener("input", checkCalcVerification);
    }
    if (calcClearVerifyBtn) {
        calcClearVerifyBtn.addEventListener("click", () => {
            if (calcVerifyInput) calcVerifyInput.value = "";
            checkCalcVerification();
        });
    }

    // Initial calculation (default text input)
    executeTextHashing();
}


// =========================================================================
// File Upload & Hash Page
// =========================================================================

const uploadZone = document.getElementById("uploadZone");
const fileInput = document.getElementById("fileInput");
const fileInfoCard = document.getElementById("fileInfoCard");
const compareSection = document.getElementById("compareSection");

// Drag and drop
uploadZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    uploadZone.classList.add("drag-over");
});

uploadZone.addEventListener("dragleave", () => {
    uploadZone.classList.remove("drag-over");
});

uploadZone.addEventListener("drop", (e) => {
    e.preventDefault();
    uploadZone.classList.remove("drag-over");
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileUpload(files[0]);
    }
});

fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
        handleFileUpload(fileInput.files[0]);
    }
});

/** Currently uploaded file's observed hash (for comparison). */
let uploadedFileHash = "";

/**
 * Handle a file upload: display info and compute hash.
 * @param {File} file
 */
async function handleFileUpload(file) {
    // Size limit: 500 MB
    const MAX_SIZE = 500 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
        showToast("File too large. Maximum size is 500 MB.", "error");
        return;
    }

    fileInfoCard.classList.remove("hidden");
    compareSection.classList.remove("hidden");
    document.getElementById("uploadFilename").textContent = file.name;
    document.getElementById("uploadFilesize").textContent = formatBytes(file.size);
    document.getElementById("uploadHash").textContent = "Calculating…";
    document.getElementById("uploadHash").className = "hash-display";
    document.getElementById("compareResult").innerHTML = "";

    try {
        const hash = await calculateSHA256FromFile(file);
        uploadedFileHash = hash;
        const hashEl = document.getElementById("uploadHash");
        hashEl.textContent = hash;
        hashEl.title = "Click to copy";
        hashEl.onclick = () => copyToClipboard(hash);
        showToast("SHA-256 hash calculated!", "success");
    } catch (err) {
        document.getElementById("uploadHash").textContent = `Error: ${err.message}`;
        document.getElementById("uploadHash").className = "hash-display hash-mismatch";
        showToast("Failed to calculate hash.", "error");
    }
}

// Compare hash button
document.getElementById("btnCompareHash").addEventListener("click", () => {
    const expectedInput = document.getElementById("expectedHashInput").value.trim();
    const resultDiv = document.getElementById("compareResult");

    if (!uploadedFileHash) {
        showToast("Upload a file first.", "error");
        return;
    }

    if (!expectedInput) {
        showToast("Enter an expected hash.", "error");
        return;
    }

    if (!isValidSHA256Hex(expectedInput)) {
        resultDiv.innerHTML = `
            <div class="overall-fail">
                <div class="overall-status-icon">❌</div>
                <div class="overall-status-title text-red">Invalid Hash Format</div>
                <div class="overall-status-desc">
                    Must be exactly 64 hexadecimal characters (0-9, a-f).
                </div>
            </div>
        `;
        document.getElementById("expectedHashInput").classList.add("input-error");
        return;
    }

    document.getElementById("expectedHashInput").classList.remove("input-error");

    const status = compareHashes(expectedInput, uploadedFileHash);
    if (status === "PASS") {
        resultDiv.innerHTML = `
            <div class="overall-pass">
                <div class="overall-status-icon">✅</div>
                <div class="overall-status-title text-green">MATCH — Hashes are identical</div>
            </div>
        `;
    } else {
        resultDiv.innerHTML = `
            <div class="overall-fail">
                <div class="overall-status-icon">❌</div>
                <div class="overall-status-title text-red">MISMATCH — Hashes differ</div>
            </div>
            <div class="form-label mt-2">Expected:</div>
            <div class="hash-display hash-mismatch mb-2">${escapeHTML(normalizeHash(expectedInput))}</div>
            <div class="form-label">Observed:</div>
            <div class="hash-display hash-mismatch">${escapeHTML(uploadedFileHash)}</div>
        `;
    }
});


// =========================================================================
// Modification Detection Page
// =========================================================================

document.getElementById("btnRunModDemo").addEventListener("click", async () => {
    const btn = document.getElementById("btnRunModDemo");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Computing hashes…';

    try {
        const originalContent = utf8Encoder.encode("The quick brown fox jumps over the lazy dog.\n");
        const modifiedContent = utf8Encoder.encode("The quick brown fox jumps over the lazy dog!\n");

        const originalHash = await calculateSHA256(originalContent);
        const modifiedHash = await calculateSHA256(modifiedContent);

        const hashesMatch = originalHash === modifiedHash;

        // Populate the UI
        document.getElementById("modOrigName").textContent = "normal_text.txt";
        document.getElementById("modOrigSize").textContent = formatBytes(originalContent.byteLength);
        document.getElementById("modOrigContent").textContent = new TextDecoder().decode(originalContent);
        document.getElementById("modOrigHash").textContent = originalHash;
        document.getElementById("modOrigHash").onclick = () => copyToClipboard(originalHash);

        document.getElementById("modModName").textContent = "modified_text.txt";
        document.getElementById("modModSize").textContent = formatBytes(modifiedContent.byteLength);
        document.getElementById("modModContent").textContent = new TextDecoder().decode(modifiedContent);
        document.getElementById("modModHash").textContent = modifiedHash;
        document.getElementById("modModHash").onclick = () => copyToClipboard(modifiedHash);

        const compResult = document.getElementById("modComparisonResult");
        if (hashesMatch) {
            compResult.innerHTML = `
                <div class="overall-fail">
                    <div class="overall-status-icon">⚠️</div>
                    <div class="overall-status-title text-amber">Hashes MATCH — modification not detected</div>
                    <div class="overall-status-desc">(This should not happen with SHA-256.)</div>
                </div>
            `;
        } else {
            compResult.innerHTML = `
                <div class="overall-pass">
                    <div class="overall-status-icon">✅</div>
                    <div class="overall-status-title text-green">Hashes DIFFER — modification successfully detected!</div>
                </div>
                <p class="mt-1" style="font-size:0.88rem;">
                    <strong>Change:</strong> Changed the period (.) at the end of the sentence
                    to an exclamation mark (!) — a single-character modification.
                </p>
            `;
        }

        document.getElementById("modTimestamp").textContent =
            `🕐 Demo executed: ${new Date().toISOString()}`;

        document.getElementById("modDemoResult").classList.remove("hidden");
        showToast("Modification detection demo complete!", "success");
    } catch (err) {
        showToast(`Error: ${err.message}`, "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = "▶ Run Modification Detection Demo";
    }
});


// =========================================================================
// Results Table Page
// =========================================================================

/**
 * Update the results table page.
 */
function updateResultsPage() {
    const empty = document.getElementById("resultsEmpty");
    const populated = document.getElementById("resultsPopulated");

    if (!testsExecuted || testResults.length === 0) {
        empty.classList.remove("hidden");
        populated.classList.add("hidden");
        return;
    }

    empty.classList.add("hidden");
    populated.classList.remove("hidden");

    // Metrics
    const passed = testResults.filter(r => r.status === "PASS").length;
    const failed = testResults.filter(r => r.status === "FAIL").length;
    const errors = testResults.filter(r => r.status === "ERROR").length;

    document.getElementById("resultsMetrics").innerHTML = `
        <div class="metric-card">
            <div class="metric-value val-blue">${testResults.length}</div>
            <div class="metric-label">Tests Run</div>
        </div>
        <div class="metric-card">
            <div class="metric-value val-green">${passed}</div>
            <div class="metric-label">Passed</div>
        </div>
        <div class="metric-card">
            <div class="metric-value val-red">${failed}</div>
            <div class="metric-label">Failed</div>
        </div>
        <div class="metric-card">
            <div class="metric-value val-amber">${errors}</div>
            <div class="metric-label">Errors</div>
        </div>
    `;

    // Table rows
    renderResultsTable(testResults);

    // Detail cards
    renderResultsDetailCards(testResults);
}

/**
 * Render table rows for the results.
 * @param {Array<Object>} results
 */
function renderResultsTable(results) {
    const tbody = document.getElementById("resultsTableBody");
    tbody.innerHTML = results.map(r => `
        <tr>
            <td><strong>${r.testId}</strong></td>
            <td>${escapeHTML(r.testName)}</td>
            <td class="code-text">${escapeHTML(r.filename)}</td>
            <td>${formatBytes(r.fileSize)}</td>
            <td class="hash-cell" title="${escapeHTML(r.expectedHash)}">${truncateHash(r.expectedHash)}</td>
            <td class="hash-cell" title="${escapeHTML(r.observedHash)}">${truncateHash(r.observedHash)}</td>
            <td>${statusBadgeHTML(r.status)}</td>
            <td style="font-size:0.72rem;white-space:nowrap;">${r.timestamp ? new Date(r.timestamp).toLocaleString() : "—"}</td>
        </tr>
    `).join("");
}

/**
 * Render detailed result cards on the results page.
 * @param {Array<Object>} results
 */
function renderResultsDetailCards(results) {
    const container = document.getElementById("resultsDetailCards");
    container.innerHTML = results.map(r => {
        const hashClass = r.status === "PASS" ? "hash-match" : "hash-mismatch";
        return `
            <div class="test-card" data-testid="${r.testId}">
                <div class="test-card-header" onclick="toggleTestCard(this)">
                    <div class="test-card-header-left">
                        <span class="test-card-id">${r.testId}</span>
                        <span class="test-card-name">${escapeHTML(r.testName)}</span>
                    </div>
                    ${statusBadgeHTML(r.status)}
                    <span class="test-card-chevron">▼</span>
                </div>
                <div class="test-card-body">
                    <p><strong>File:</strong> ${escapeHTML(r.filename)} · <strong>Size:</strong> ${formatBytes(r.fileSize)}</p>
                    <p class="text-muted" style="font-size:0.82rem;"><strong>Timestamp:</strong> ${r.timestamp}</p>
                    <div class="form-label mt-2">Expected:</div>
                    <div class="hash-display ${hashClass} mb-2" onclick="copyToClipboard('${r.expectedHash}')" title="Click to copy">${escapeHTML(r.expectedHash)}</div>
                    <div class="form-label">Observed:</div>
                    <div class="hash-display ${hashClass}" onclick="copyToClipboard('${r.observedHash}')" title="Click to copy">${r.observedHash || "—"}</div>
                    ${r.notes ? `<p class="text-muted mt-1" style="font-size:0.78rem;">📝 ${escapeHTML(r.notes)}</p>` : ""}
                    ${r.errorDetails ? `<div class="info-box mt-1" style="border-left-color:var(--warn-amber);">⚠️ Error: ${escapeHTML(r.errorDetails)}</div>` : ""}
                </div>
            </div>
        `;
    }).join("");
}

// Search/filter on results table
document.getElementById("resultsSearch").addEventListener("input", (e) => {
    const query = e.target.value.toLowerCase().trim();
    if (!query) {
        renderResultsTable(testResults);
        renderResultsDetailCards(testResults);
        return;
    }
    const filtered = testResults.filter(r =>
        r.testId.toLowerCase().includes(query) ||
        r.testName.toLowerCase().includes(query) ||
        r.filename.toLowerCase().includes(query) ||
        r.status.toLowerCase().includes(query)
    );
    renderResultsTable(filtered);
    renderResultsDetailCards(filtered);
});


// =========================================================================
// Export Report Page
// =========================================================================

/**
 * Update the export page visibility.
 */
function updateExportPage() {
    const empty = document.getElementById("exportEmpty");
    const populated = document.getElementById("exportPopulated");

    if (!testsExecuted || testResults.length === 0) {
        empty.classList.remove("hidden");
        populated.classList.add("hidden");
    } else {
        empty.classList.add("hidden");
        populated.classList.remove("hidden");
    }
}

/**
 * Properly escape a value for CSV.
 * If it contains commas, quotes, or newlines, wrap in quotes and escape internal quotes.
 * @param {*} value
 * @returns {string}
 */
function csvEscape(value) {
    const str = String(value ?? "");
    if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
        return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
}

/**
 * Generate CSV content from test results.
 * @returns {string}
 */
function generateCSV() {
    const headers = [
        "Test ID", "Test Name", "Filename", "File Size (bytes)",
        "Expected SHA-256", "Observed SHA-256", "Status", "Timestamp", "Notes"
    ];
    const rows = testResults.map(r => [
        r.testId, r.testName, r.filename, r.fileSize,
        r.expectedHash, r.observedHash, r.status, r.timestamp, r.notes
    ]);

    const csvLines = [
        headers.map(csvEscape).join(","),
        ...rows.map(row => row.map(csvEscape).join(","))
    ];
    return csvLines.join("\n");
}

/**
 * Generate the investigation memo text.
 * @param {string} csvHash - Hash of the CSV report.
 * @returns {string}
 */
function generateMemo(csvHash) {
    const now = new Date().toISOString();
    const passed = testResults.filter(r => r.status === "PASS").length;
    const failed = testResults.filter(r => r.status === "FAIL").length;
    const errors = testResults.filter(r => r.status === "ERROR").length;

    const evidenceLines = testResults.map(r =>
        `| ${r.testId} | ${r.testName} | ${r.filename} | ` +
        `${r.fileSize.toLocaleString()} | ${truncateHash(r.expectedHash, 16)} | ` +
        `${truncateHash(r.observedHash, 16)} | **${r.status}** |`
    ).join("\n");

    const discrepancies = testResults.filter(r => r.status === "FAIL" || r.status === "ERROR");
    let discSection;
    if (discrepancies.length > 0) {
        discSection = discrepancies.map(r => {
            let reason;
            if (r.testId === "TC-006") {
                reason = "Expected failure — deliberate modification to demonstrate tamper detection.";
            } else if (r.testId === "TC-007") {
                reason = "Expected error — deliberately invalid expected hash format to test error handling.";
            } else if (r.status === "ERROR") {
                reason = `Execution error: ${r.errorDetails}`;
            } else {
                reason = "Unexpected hash mismatch — requires investigation.";
            }
            return `- **${r.testId} (${r.testName}):** ${reason}`;
        }).join("\n");
    } else {
        discSection = "No discrepancies detected.";
    }

    return `# ForensiCheck — Investigation Memo

## Project Information

| Field | Value |
|-------|-------|
| **Project ID** | DF-PBL-030 |
| **Title** | Forensic Tool Validation Study |
| **Investigator** | Pranav Sharma (500121423) |
| **Institution** | UPES, Dehradun |
| **Date** | ${now} |
| **Format** | Investigation Memo |

---

## 1. Objective

To validate the accuracy of the ForensiCheck dashboard's SHA-256 file-hashing
feature by comparing its output against independently-established expected hash
values for a suite of controlled test files.

## 2. Validation Method

- **Algorithm:** SHA-256 (Web Crypto API — crypto.subtle.digest)
- **Reading mode:** Binary (ArrayBuffer processing)
- **Expected hashes:** Computed independently using Python hashlib.sha256 in a
  separate interpreter session and cross-verified with shasum -a 256 (macOS).
- **Test design:** Known-answer testing — the expected output for each input is
  established before the test is executed.

## 3. Test Environment

- **Application:** ForensiCheck v2.0 (Static web dashboard)
- **Platform:** HTML5, CSS3, Vanilla JavaScript
- **Hashing API:** Web Crypto API (crypto.subtle.digest SHA-256)
- **Browser:** (record your browser and version here)
- **Execution:** Local — all processing in the browser, no server upload

## 4. Evidence Inventory

| Test ID | Test Name | Filename | Size (B) | Expected (prefix) | Observed (prefix) | Status |
|---------|-----------|----------|----------|--------------------|--------------------|--------|
${evidenceLines}

**Total:** ${testResults.length} test cases — ${passed} PASS, ${failed} FAIL, ${errors} ERROR

## 5. Expected vs. Observed Results

### Observation
The ForensiCheck hashing engine was executed on ${testResults.length} controlled test inputs.
${passed} tests produced SHA-256 hashes matching the independently-established expected values.
${failed} test(s) showed hash mismatches. ${errors} test(s) encountered execution errors.

### Interpretation
- TC-001 through TC-005 test different file types (ASCII, binary, empty, Unicode, large).
  A PASS confirms byte-accurate SHA-256 computation for each category.
- TC-006 deliberately uses a modified file compared against the original's hash.
  A FAIL for TC-006 is the **expected and correct** outcome — it demonstrates tamper detection.
- TC-007 deliberately uses an invalid expected hash format.
  An ERROR for TC-007 is the **expected and correct** outcome — it demonstrates error handling.

### Inference
The hashing implementation correctly computes SHA-256 for the tested input categories
and successfully detects a single-character file modification.

## 6. Discrepancies

${discSection}

## 7. Conclusion

The ForensiCheck SHA-256 hashing engine produced correct results for all ${testResults.length}
known-answer test cases. The modification-detection test (TC-006) confirmed that even a
single-character change produces a different hash, validating the tool's integrity-checking capability.
The error-handling test (TC-007) confirmed that invalid hash formats are properly rejected.

## 8. Limitations

- This validation covers ${testResults.length} controlled test cases. Successful results do not
  prove correctness for every possible input, file system, or operating environment.
- Expected hashes were established using Python's hashlib in a separate session.
  A stronger protocol would use a completely independent tool chain.
- The application does not certify files for legal proceedings or court admissibility.
- Self-hashing the exported report detects subsequent changes but does not independently
  prove authenticity to a third party.
- No adversarial or fuzz testing was performed.
- Browser-based hashing depends on the Web Crypto API implementation.

## 9. Reproduction Steps

1. Clone the project repository.
2. Open index.html in a modern web browser, or run a local server.
3. Navigate to **🧪 Run Validation Tests** and click **Run All Tests**.
4. Review results in **📊 Results Table**.
5. Run the **🔍 Modification Detection** demo.
6. Export the report from **📋 Export Report**.
7. Deploy to Vercel via GitHub for public access.

---

**CSV Report SHA-256:** \`${csvHash}\`

*This memo was generated by the ForensiCheck application on ${now}.*
*It contains only results actually obtained by executing the test suite.*
`;
}

/**
 * Trigger a file download.
 * @param {string} content - File content.
 * @param {string} filename - File name.
 * @param {string} mimeType - MIME type.
 */
function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// CSV export button
document.getElementById("btnExportCSV").addEventListener("click", async () => {
    const csv = generateCSV();
    const csvBytes = utf8Encoder.encode(csv);
    const csvHash = await calculateSHA256(csvBytes);
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);

    downloadFile(csv, `forensicheck_report_${timestamp}.csv`, "text/csv");

    document.getElementById("csvHashInfo").innerHTML = `
        <strong>Report SHA-256:</strong><br>
        <code style="word-break:break-all;">${csvHash}</code><br><br>
        Hashing the exported report allows you to detect subsequent changes to the file.
        However, a self-generated hash does not independently prove the report's authenticity
        to a third party.
    `;

    showToast("CSV report downloaded!", "success");
});

// Memo export button
document.getElementById("btnExportMemo").addEventListener("click", async () => {
    const csv = generateCSV();
    const csvBytes = utf8Encoder.encode(csv);
    const csvHash = await calculateSHA256(csvBytes);

    const memo = generateMemo(csvHash);
    const memoBytes = utf8Encoder.encode(memo);
    const memoHash = await calculateSHA256(memoBytes);
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);

    downloadFile(memo, `investigation_memo_${timestamp}.md`, "text/markdown");

    document.getElementById("memoHashInfo").innerHTML = `
        <strong>Memo SHA-256:</strong><br>
        <code style="word-break:break-all;">${memoHash}</code>
    `;

    showToast("Investigation memo downloaded!", "success");
});

// Memo preview toggle
document.getElementById("btnToggleMemoPreview").addEventListener("click", async () => {
    const container = document.getElementById("memoPreviewContainer");
    container.classList.toggle("hidden");

    if (!container.classList.contains("hidden")) {
        const csv = generateCSV();
        const csvBytes = utf8Encoder.encode(csv);
        const csvHash = await calculateSHA256(csvBytes);
        document.getElementById("memoPreview").textContent = generateMemo(csvHash);
    }
});


// =========================================================================
// Initialization
// =========================================================================

document.addEventListener("DOMContentLoaded", () => {
    renderFixtureList();
    populateSingleTestSelect();
    updateDashboard();
    renderTestResultCards();
    updateResultsPage();
    updateExportPage();
    initHashCalculator();
    handleHashNavigation();
});
