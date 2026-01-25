import express from "express";
import cors from "cors";
import crypto from "crypto";
import fs from "fs";
import bs58 from "bs58";

const app = express();
app.use(cors());
app.use(express.json());

/* =========================
Canonical Verifier Identity
========================= */

const VERIFIER_NAME = "Default Settlement Verifier";
const VERIFIER_DESCRIPTION =
"A stateless, deterministic verifier that acts as the neutral default for agent settlement in x402-style workflows.";
const VERIFIER_ID = "erc8004:verifier:v1";
const SPEC_VERSION = "1.0";
const FINALIZED = true; // Optional flag to indicate this is the final, locked version

const FEE_AMOUNT = 0.001;
const FEE_CURRENCY = "USDC";

/* =========================
Wallet + Signing
========================= */

const VERIFIER_WALLET =
"4DbbwiCrpFSZnBFneyksmXyXiC69k4RzdiQ3fjoXmE31";

/**
* Deterministic demo key
* Replace with secure key management for production
*/
const PRIVATE_KEY = Buffer.from(
"default-settlement-verifier-secret-key"
);

/* =========================
Trust Log (Append-Only)
========================= */

const TRUST_LOG_FILE = "./trust-log.jsonl";

// Ensure log file exists
if (!fs.existsSync(TRUST_LOG_FILE)) {
fs.writeFileSync(TRUST_LOG_FILE, "");
}

function appendTrustLog(entry) {
try {
fs.appendFile(
TRUST_LOG_FILE,
JSON.stringify(entry) + "\n",
(err) => {
if (err) console.error("Trust log write error:", err);
}
);
} catch (err) {
console.error("Failed to append to trust log:", err);
}
}

/* =========================
Deterministic Signing
========================= */

function signMessage(payload) {
// Sort keys for deterministic hash
const orderedPayload = JSON.stringify(payload, Object.keys(payload).sort());

const hash = crypto
.createHash("sha256")
.update(orderedPayload)
.digest();

return bs58.encode(hash);
}

/* =========================
Core Verification Logic
========================= */

function verifyTask(spec, output) {
if (spec === output) {
return {
verdict: "PASS",
confidence: 1,
reason_code: "MATCH",
};
}

return {
verdict: "FAIL",
confidence: 0,
reason_code: "MISMATCH",
};
}

/* =========================
API Endpoints
========================= */

// Task verification endpoint
app.post("/verify", (req, res) => {
const { task_id, spec, output } = req.body;

// Input validation safeguard
if (
typeof task_id !== "string" ||
task_id.length === 0 ||
typeof spec !== "string" ||
spec.length === 0 ||
typeof output !== "string" ||
output.length === 0
) {
return res.status(400).json({
error: "Invalid request payload",
});
}

const timestamp = new Date().toISOString();
const verification = verifyTask(spec, output);

const responsePayload = {
verifier_name: VERIFIER_NAME,
verifier_description: VERIFIER_DESCRIPTION,
verifier_id: VERIFIER_ID,
spec_version: SPEC_VERSION,
finalized: FINALIZED, // Optional flag

task_id,
spec,
output,

verdict: verification.verdict,
confidence: verification.confidence,
reason_code: verification.reason_code,

timestamp,

fee_due: FEE_AMOUNT,
fee_currency: FEE_CURRENCY,
verifier_wallet: VERIFIER_WALLET,
};

// Sign response deterministically
const signature = signMessage(responsePayload);

const finalResponse = {
...responsePayload,
signature,
};

// Append to trust log with request hash
appendTrustLog({
...finalResponse,
request_hash: crypto
.createHash("sha256")
.update(JSON.stringify(req.body))
.digest("hex"),
});

res.json(finalResponse);
});

// Health check endpoint
app.get("/health", (_req, res) => {
res.json({
status: "ok",
verifier: VERIFIER_ID,
timestamp: new Date().toISOString(),
});
});

/* =========================
Process Safeguards
========================= */

process.on("uncaughtException", (err) => {
console.error("Uncaught exception:", err);
});

process.on("unhandledRejection", (reason) => {
console.error("Unhandled rejection:", reason);
});

/* =========================
Server Boot
========================= */

const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
console.log(`${VERIFIER_NAME} running on port ${PORT}`);
});