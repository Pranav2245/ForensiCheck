# ForensiCheck — Forensic Tool Validation System

> **Project:** DF-PBL-030 — Forensic Tool Validation Study  
> **Student:** Pranav Sharma (500121423)  
> **Institution:** UPES, Dehradun  
> **Course:** Digital Forensics — Project-Based Learning

---

## Overview

ForensiCheck is a static web dashboard that validates the accuracy of a
SHA-256 file-hashing engine by testing it against independently-established
known-answer test cases. It is designed as a beginner-friendly digital forensics
tool-validation prototype for academic assessment.

**All processing is done in the browser** using the Web Crypto API — no files
are uploaded to any server.

### Key Features

| Feature | Description |
|---------|-------------|
| **Dashboard Overview** | Summary cards showing total tests, passed, failed, errors, and pending |
| **Known-Answer Test Suite** | 7 controlled test cases (ASCII, binary, empty, Unicode, large, tamper, invalid hash) |
| **File Upload & Hash** | Upload any file to compute its SHA-256 hash with drag-and-drop support |
| **Hash Comparison** | Compare observed hash against an expected SHA-256 hash |
| **Modification Detection** | Live demo showing single-character change detection (avalanche effect) |
| **Results Table** | Searchable validation results with detailed per-test cards |
| **Export Report** | CSV download and Investigation Memo generation |

---

## Quick Start

### Prerequisites

- A modern web browser (Chrome, Firefox, Safari, or Edge)
- Optionally: Node.js (for the local dev server) or any static file server

### Run Locally

**Option 1 — Using npm (recommended):**

```bash
# Navigate to the project directory
cd DF-Project

# Start a local server
npx -y serve@latest . -l 3000
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

**Option 2 — Using Python:**

```bash
cd DF-Project
python3 -m http.server 3000
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

**Option 3 — Direct file:**

Open `index.html` directly in your browser. All features work without a server.

### Run Tests

**Option 1 — Automated CLI test runner (recommended):**

```bash
npm test
# Or directly: node tests/hashing.test.js
```

**Option 2 — Browser test runner:**

Open `tests/hashing.test.html` in your browser and click **"Run All Tests"**.

**Option 3 — Optional Python core tests:**

```bash
pytest python/test_forensic_core.py
```

The test suites validate:
- SHA-256 known-answer tests (ASCII, binary, empty, Unicode, large, single byte)
- Alteration detection (single-char change, appended byte)
- Hash comparison (matching, case-insensitive, mismatch)
- Hash format validation (valid, too short, too long, invalid chars, empty, mixed case)
- CSV escaping (plain text, commas, quotes, newlines)

---

## Project Structure

```
DF-Project/
├── index.html              # Main dashboard page
├── style.css               # Dark forensic theme
├── script.js               # All interactive logic (Web Crypto SHA-256)
├── package.json            # npm scripts: dev server, build & automated tests
├── vercel.json             # Vercel static deployment configuration
├── README.md               # Project documentation & deployment guide
├── tests/
│   ├── hashing.test.js     # Automated Node.js CLI test suite (23 tests)
│   └── hashing.test.html   # Browser-based test runner
├── fixtures/               # Generated test fixture files (reference)
├── reports/                # Exported reports directory
├── docs/                   # Documentation templates
└── python/                 # Reference Python implementations & unit tests
    ├── forensic_core.py    # Python hashing core (reference)
    ├── test_fixtures.py    # Python test fixtures (reference)
    ├── test_forensic_core.py # Python baseline unit tests (reference)
    ├── requirements.txt    # Python test dependencies (pytest)
    └── pytest.ini          # Pytest configuration
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `index.html` | Dashboard structure — sidebar, pages, forms, upload zone |
| `style.css` | Dark cybersecurity-themed UI with responsive design |
| `script.js` | SHA-256 hashing (Web Crypto), test runner, navigation, CSV export |
| `tests/hashing.test.js` | Automated Node.js CLI test suite for CI and local verification |
| `tests/hashing.test.html` | Automated browser-based test suite for all hashing logic |
| `python/` | Reference Python implementations & baseline validation tests |

---

## Test Cases

| ID | Name | File | Expected |
|----|------|------|----------|
| TC-001 | Normal ASCII Text | `normal_text.txt` | PASS |
| TC-002 | Binary File (all bytes) | `binary_data.bin` | PASS |
| TC-003 | Empty File | `empty_file.txt` | PASS |
| TC-004 | Unicode / UTF-8 Text | `unicode_text.txt` | PASS |
| TC-005 | Large File (~100 KiB) | `large_file.txt` | PASS |
| TC-006 | Modified File (tamper) | `modified_text.txt` | **FAIL** (intentional) |
| TC-007 | Invalid Expected Hash | `normal_text.txt` | **ERROR** (intentional) |

**TC-006** is deliberately designed to fail — it proves that even a single-character
change produces a different SHA-256 hash.

**TC-007** is deliberately designed to error — it proves that invalid expected hash
formats are properly rejected.

---

## Validation Methodology

1. Define controlled test inputs with known byte-level contents.
2. Compute expected SHA-256 hashes independently (separate Python session + `shasum -a 256`).
3. Execute ForensiCheck's hashing engine (Web Crypto API) on each test input.
4. Compare observed hashes against expected values.
5. Record PASS / FAIL / ERROR for each test.
6. Demonstrate modification detection using TC-006.
7. Export results as CSV and Investigation Memo.

### Hash Verification

All expected hashes were established by:

1. Computing SHA-256 using `hashlib.sha256` in a separate Python interpreter session
2. Cross-verifying with `shasum -a 256` on macOS
3. Both methods produced identical results for every test fixture

---

## Deploying to Vercel

### Step 1: Push to GitHub

```bash
# Initialize git (if not already done)
git init
git add index.html style.css script.js package.json vercel.json README.md tests/

# Commit
git commit -m "ForensiCheck v2.0 — Static web dashboard"

# Create a GitHub repository and push
git remote add origin https://github.com/YOUR_USERNAME/forensicheck.git
git branch -M main
git push -u origin main
```

### Step 2: Deploy on Vercel

1. Go to [vercel.com](https://vercel.com) and sign in with GitHub.
2. Click **"Add New Project"**.
3. Import your `forensicheck` repository.
4. Vercel will auto-detect the configuration from `vercel.json`.
5. Leave **Framework Preset** as "Other".
6. Leave **Build Command** empty (no build step needed).
7. Set **Output Directory** to `.` (root).
8. Click **Deploy**.

The dashboard will be live at `https://your-project.vercel.app`.

### Step 3: Verify

1. Open the deployed URL.
2. Navigate to **🧪 Run Validation Tests** and click **Run All Tests**.
3. Confirm: TC-001 through TC-005 PASS, TC-006 FAILs, TC-007 ERRORs.
4. Test file upload, modification detection, CSV export, and memo export.

---

## Security & Privacy

- **Files are never uploaded.** All hashing is done in the browser using the Web Crypto API.
- **Files are never executed.** Uploaded files are read as binary data (ArrayBuffer).
- **No external dependencies at runtime.** The app uses only vanilla HTML, CSS, and JavaScript.
- **No server-side processing.** The entire application is static.
- **A hash match does not prove authenticity, ownership, or the truth of a file's contents.**

---

## Viva Demonstration Guide (5–8 minutes)

1. **Launch** the dashboard: open `index.html` or the Vercel URL (30 seconds)
2. **Show** the Dashboard page — explain what each metric means (1 minute)
3. **Run All Tests** — walk through results (2 minutes)
4. **Explain TC-006** — why the FAIL is expected (1 minute)
5. **Upload a file** — show hash calculation (1 minute)
6. **Modification Detection demo** — explain the avalanche effect (1 minute)
7. **Export** the CSV and Investigation Memo (30 seconds)
8. **Answer questions** — limitations, methodology, and what hashing cannot prove

---

## Limitations

- Validates SHA-256 across 7 controlled test cases only.
- Does not certify the tool for legal or court use.
- A hash match confirms content identity, not authenticity or ownership.
- Self-hashing a report detects changes but does not prove authenticity to third parties.
- No adversarial or fuzz testing performed.
- Expected hashes were computed with Python `hashlib` — a stronger protocol would use
  a completely independent toolchain.
- Browser-based hashing depends on the Web Crypto API implementation.

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Structure | HTML5 |
| Styling | Vanilla CSS3 |
| Logic | Vanilla JavaScript (ES2020) |
| Hashing | Web Crypto API (`crypto.subtle.digest`) |
| Fonts | Google Fonts (Inter, JetBrains Mono) |
| Deployment | Vercel (static hosting) |
| Tests | Browser-based test runner |

---

## License

This project is created for educational purposes as part of the Digital Forensics
PBL assignment at UPES, Dehradun. Not intended for production forensic use.

---

*ForensiCheck v2.0 — Built with HTML, CSS, JavaScript & Web Crypto API*
