/**
 * Richmous GhSL -- MoMo payment backend, hosted on Render instead of
 * Firebase Cloud Functions (which require the paid Blaze plan).
 *
 * This does exactly what the Firebase version did:
 * 1. POST /initiateMomoPayment  -- starts a Paystack MoMo charge
 * 2. POST /submitMomoOtp        -- submits an OTP if the network needs one
 * 3. POST /paystackWebhook      -- Paystack calls this directly once a
 *    charge actually succeeds; we verify its signature and only THEN
 *    write "paid" to Firestore.
 *
 * Firestore and Firebase Auth themselves are untouched and still live on
 * Firebase's free Spark plan -- only the compute (this server) moved.
 *
 * Auth: the Flutter app signs in anonymously via Firebase Auth (as
 * before) and sends its Firebase ID token in an `Authorization: Bearer
 * <token>` header. This server verifies that token with the Admin SDK,
 * which is the manual equivalent of what Cloud Functions did
 * automatically via `context.auth`.
 *
 * Required environment variables (set these in Render's dashboard,
 * under your service's "Environment" tab):
 *   PAYSTACK_SECRET            -- your sk_test_... or sk_live_... key
 *   FIREBASE_SERVICE_ACCOUNT   -- the full JSON contents of a Firebase
 *                                 service account key, as one string
 *                                 (Firebase Console > Project Settings >
 *                                 Service Accounts > Generate new
 *                                 private key)
 */

const express = require("express");
const admin = require("firebase-admin");
const fetch = require("node-fetch");
const crypto = require("crypto");
const cors = require("cors");

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

const app = express();
app.use(cors());

const PAYSTACK_BASE_URL = "https://api.paystack.co";
const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET;

// Price for premium access, in pesewas (GHS 20.00 = 2000).
const INTERMEDIATE_PRICE_PESEWAS = 2000;
const CURRENCY = "GHS";

const NETWORK_MAP = {
  mtn: "mtn",
  vodafone: "vod",
  airteltigo: "atl",
};

/**
 * Verifies the Firebase ID token sent by the app and attaches the
 * verified uid to the request. Rejects the request if it's missing or
 * invalid -- this is what stops someone from faking another user's uid.
 */
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Missing Authorization token." });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.uid = decoded.uid;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token." });
  }
}

app.post("/initiateMomoPayment", express.json(), requireAuth, async (req, res) => {
  const { phone, network } = req.body;

  if (!phone || !network || !NETWORK_MAP[network]) {
    return res.status(400).json({
      error: "A valid phone number and network (mtn, vodafone, airteltigo) are required.",
    });
  }

  const uid = req.uid;
  const reference = `premium_${uid}_${Date.now()}`;

  try {
    const response = await fetch(`${PAYSTACK_BASE_URL}/charge`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: `${uid}@richmousghsl.app`,
        amount: INTERMEDIATE_PRICE_PESEWAS,
        currency: CURRENCY,
        reference,
        mobile_money: { phone, provider: NETWORK_MAP[network] },
        metadata: { uid, product: "premium_access" },
      }),
    });

    const result = await response.json();

    if (!result.status) {
      return res.status(400).json({ error: result.message || "Paystack rejected the charge request." });
    }

    await db.collection("payments").doc(reference).set({
      uid,
      reference,
      amount: INTERMEDIATE_PRICE_PESEWAS,
      currency: CURRENCY,
      status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({
      reference,
      status: result.data.status,
      displayText: result.data.display_text || "Check your phone to approve the payment.",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong starting the payment." });
  }
});

app.post("/submitMomoOtp", express.json(), requireAuth, async (req, res) => {
  const { reference, otp } = req.body;

  if (!reference || !otp) {
    return res.status(400).json({ error: "reference and otp are both required." });
  }

  try {
    const response = await fetch(`${PAYSTACK_BASE_URL}/charge/submit_otp`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ otp, reference }),
    });

    const result = await response.json();

    if (!result.status) {
      return res.status(400).json({ error: result.message || "OTP submission failed." });
    }

    res.json({
      status: result.data.status,
      displayText: result.data.display_text || "Processing payment...",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong submitting the code." });
  }
});

/**
 * Paystack calls this directly (never the app). We need the RAW request
 * body -- not the JSON-parsed version -- because the signature is
 * computed over the exact bytes Paystack sent. That's why this route
 * uses express.raw() instead of express.json(), unlike the other two.
 */
app.post("/paystackWebhook", express.raw({ type: "application/json" }), async (req, res) => {
  const signature = req.headers["x-paystack-signature"];
  const expectedSignature = crypto
    .createHmac("sha512", PAYSTACK_SECRET)
    .update(req.body)
    .digest("hex");

  if (signature !== expectedSignature) {
    console.warn("Webhook signature mismatch -- rejecting.");
    return res.status(401).send("Invalid signature");
  }

  const event = JSON.parse(req.body.toString("utf8"));

  if (event.event === "charge.success") {
    const { reference, metadata } = event.data;
    const uid = metadata && metadata.uid;

    if (uid) {
      await db.collection("payments").doc(reference).set(
        { status: "success", confirmedAt: admin.firestore.FieldValue.serverTimestamp() },
        { merge: true }
      );

      await db.collection("users").doc(uid).collection("entitlements").doc("premium").set({
        active: true,
        reference,
        grantedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }
  }

  res.status(200).send("ok");
});

app.get("/", (req, res) => {
  res.send("Richmous GhSL MoMo backend is running.");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});