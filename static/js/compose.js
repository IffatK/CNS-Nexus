(() => {
  const form = document.getElementById("compose-form");
  if (!form) return;
  const recipient = document.getElementById("recipient");
  const body = document.getElementById("body");
  const button = document.getElementById("send-button");
  const status = document.getElementById("send-status");
  const sendLabel = button.textContent;
  const announce = (message, state = "info") => { status.textContent = message; status.dataset.state = state; };
  const encoder = new TextEncoder();
  const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const hex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
  function modPow(base, exp, mod) {
    let result = 1n; base %= mod;
    while (exp > 0n) { if (exp & 1n) result = (result * base) % mod; exp >>= 1n; base = (base * base) % mod; }
    return result;
  }
  function randomBigInt(bytes = 32) {
    const a = crypto.getRandomValues(new Uint8Array(bytes));
    return BigInt("0x" + hex(a));
  }
  async function protectedPayload(text) {
    const response = await fetch("/api/transport/public-key", {credentials:"same-origin", cache:"no-store"});
    if (!response.ok) throw new Error("Could not load transport public key.");
    const pk = await response.json();
    const p = BigInt("0x" + pk.p), g = BigInt("0x" + pk.g), y = BigInt("0x" + pk.y);
    const rawKey = crypto.getRandomValues(new Uint8Array(32));
    const aesKey = await crypto.subtle.importKey("raw", rawKey, {name:"AES-GCM"}, false, ["encrypt"]);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({name:"AES-GCM", iv:nonce, additionalData:encoder.encode(pk.aad + "|" + recipient.value.trim().toLowerCase())}, aesKey, encoder.encode(text));
    const m = BigInt("0x" + hex(rawKey));
    const k = randomBigInt(192) % (p - 2n) + 2n;
    const c1 = modPow(g, k, p);
    const c2 = (m * modPow(y, k, p)) % p;
    rawKey.fill(0);
    return {elgamal_c1:c1.toString(16), elgamal_c2:c2.toString(16), nonce:b64(nonce), ciphertext:b64(cipher)};
  }
  form.addEventListener("submit", async ev => {
    ev.preventDefault();
    if (!recipient?.value.trim() || !body?.value.trim()) { form.reportValidity(); return; }
    button.disabled = true; button.textContent = "Sending…"; button.setAttribute("aria-busy", "true"); announce("Preparing message…", "pending");
    try {
      const modeResponse = await fetch("/api/transport/settings?recipient=" + encodeURIComponent(recipient.value.trim()), {credentials:"same-origin", cache:"no-store"});
      if (modeResponse.status === 401) throw new Error("Your session is not available to this page. Sign in again using the same server URL and protocol (HTTP or HTTPS) as this page.");
      if (!modeResponse.ok) throw new Error("Could not check the sender's transport protection setting (HTTP " + modeResponse.status + ").");
      const mode = await modeResponse.json();
      // The authenticated sender controls transport protection. A protected
      // sender bypasses the attacker relay; an unprotected sender enters it,
      // even when the recipient has opted into protection.
      const protection = Boolean(mode.protection_enabled);
      let payload = {recipient:recipient.value.trim(), body:body.value};
      let endpoint = "/api/lab/send-plain";
      if (protection) {
        if (!window.isSecureContext || !window.crypto?.subtle) {
          throw new Error("Sender-side protection is enabled, so protected messaging needs a trusted HTTPS connection. Open the Ubuntu HTTPS URL and trust the lab certificate in the browser you are using.");
        }
        announce("Encrypting in your browser with AES-GCM and wrapping the key with ElGamal…", "pending");
        const encrypted = await protectedPayload(body.value);
        payload = {recipient:recipient.value.trim(), ...encrypted};
        endpoint = "/api/lab/send-protected";
      } else {
        announce(mode.recipient_enabled
          ? "Your protection is off but the recipient has protection on. This message will be visible in the attacker relay; the recipient will receive a tamper warning if it is changed."
          : "Both accounts are unprotected. This message will be readable and held in the attacker relay for forwarding.", "pending");
      }
      const response = await window.cnsPostJSON(endpoint, payload);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Message send failed.");
      if (data.intercepted) {
        announce("QUEUED · relay item #" + data.id + ". The recipient has not received this message yet; an authorized lab operator must forward it.", "queued");
        body.value = "";
        recipient.value = "";
        document.getElementById("body-count").textContent = "0";
        button.disabled = false;
        button.textContent = sendLabel; button.removeAttribute("aria-busy");
        return;
      }
      if (protection) {
        announce("DELIVERED · Protected send accepted through " + window.location.origin + ". Opening message…", "delivered");
      } else {
        announce("DELIVERED · Message accepted. Opening message…", "delivered");
      }
      body.value = "";
      recipient.value = "";
      document.getElementById("body-count").textContent = "0";
      window.setTimeout(() => window.location.assign("/messages/" + data.id), protection ? 2200 : 900);
    } catch (err) {
      const message = err.message || "Message send failed.";
      announce(message, /settings differ|mismatch|must enable|must disable/i.test(message) ? "rejected" : "failed");
      button.disabled = false;
      button.textContent = sendLabel; button.removeAttribute("aria-busy");
    }
  });
})();
