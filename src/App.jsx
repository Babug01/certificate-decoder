import { useRef, useState } from "react";
import forge from "node-forge";
import Header from "./components/Header";

const REPO_URL = "https://github.com/Babug01/certificate-decoder";

// node-forge verified live (generated a real self-signed cert, parsed it
// back) before writing this: subject/issuer fields, validity dates, serial,
// signature algorithm OID, SANs, RSA modulus/exponent, and malformed-PEM
// error handling all came back correct.

const SIG_ALGO_NAMES = {
  "1.2.840.113549.1.1.5": "SHA-1 with RSA",
  "1.2.840.113549.1.1.11": "SHA-256 with RSA",
  "1.2.840.113549.1.1.12": "SHA-384 with RSA",
  "1.2.840.113549.1.1.13": "SHA-512 with RSA",
  "1.2.840.10045.4.3.2": "SHA-256 with ECDSA",
  "1.2.840.10045.4.3.3": "SHA-384 with ECDSA",
};

const SAN_TYPE_NAMES = { 1: "email", 2: "DNS", 6: "URI", 7: "IP" };

function fingerprint(cert, md) {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const digest = md.create().update(der).digest().toHex();
  return digest.match(/.{2}/g).join(":").toUpperCase();
}

function attrList(entity) {
  return entity.attributes.map((a) => `${a.shortName || a.name}=${a.value}`).join(", ");
}

function decodeCertificate(pem) {
  const cert = forge.pki.certificateFromPem(pem);
  const now = new Date();
  const daysLeft = Math.round((cert.validity.notAfter - now) / (1000 * 60 * 60 * 24));

  const pubKeyInfo = cert.publicKey.n
    ? { algorithm: "RSA", size: `${cert.publicKey.n.bitLength()} bits`, exponent: cert.publicKey.e.toString() }
    : { algorithm: "Unknown / non-RSA (EC keys aren't decoded in detail here)", size: "-", exponent: "-" };

  let sans = [];
  const sanExt = cert.getExtension("subjectAltName");
  if (sanExt) sans = sanExt.altNames.map((a) => `${SAN_TYPE_NAMES[a.type] || `type ${a.type}`}: ${a.value || a.ip || ""}`);

  const basicConstraints = cert.getExtension("basicConstraints");
  const keyUsage = cert.getExtension("keyUsage");
  const extKeyUsage = cert.getExtension("extKeyUsage");

  return {
    subject: attrList(cert.subject),
    issuer: attrList(cert.issuer),
    version: cert.version + 1, // forge stores 0-indexed (v1=0, v3=2)
    serialNumber: cert.serialNumber,
    signatureAlgorithm: SIG_ALGO_NAMES[cert.siginfo.algorithmOid] || cert.siginfo.algorithmOid,
    notBefore: cert.validity.notBefore,
    notAfter: cert.validity.notAfter,
    isCurrentlyValid: now >= cert.validity.notBefore && now <= cert.validity.notAfter,
    daysLeft,
    publicKey: pubKeyInfo,
    sans,
    isCA: basicConstraints ? Boolean(basicConstraints.cA) : false,
    // Exclude the extension's own bookkeeping fields (id/critical/value/name)
    // explicitly — found live: a keyUsage extension marked critical:true (the
    // RFC 5280-recommended setting) otherwise slips through a bare "=== true"
    // filter and shows up as if it were a usage flag itself.
    keyUsage: keyUsage ? Object.keys(keyUsage).filter((k) => !["id", "critical", "value", "name"].includes(k) && keyUsage[k] === true) : [],
    extKeyUsage: extKeyUsage ? Object.keys(extKeyUsage).filter((k) => !["id", "critical", "value", "name"].includes(k) && extKeyUsage[k] === true) : [],
    sha256Fingerprint: fingerprint(cert, forge.md.sha256),
    sha1Fingerprint: fingerprint(cert, forge.md.sha1),
  };
}

const styles = {
  root: { minHeight: "100dvh", display: "flex", flexDirection: "column" },
  content: { fontFamily: "system-ui, sans-serif", padding: "24px 32px", maxWidth: 900, margin: "0 auto", color: "var(--text, #1a1a1a)", width: "100%", boxSizing: "border-box", background: "var(--bg-subtle, #f0efed)", flex: 1 },
  legendTable: { width: "100%", borderCollapse: "collapse", fontSize: 12, marginTop: 8 },
  legendTh: { textAlign: "left", padding: "4px 8px 4px 0", opacity: 0.5, fontWeight: 600, textTransform: "uppercase", fontSize: 10 },
  legendTd: { padding: "6px 8px 6px 0", fontFamily: "'SFMono-Regular', Consolas, monospace", verticalAlign: "top" },
  title: { fontSize: 22, fontWeight: 700, margin: 0 },
  subtitle: { fontSize: 13, opacity: 0.6, margin: "4px 0 20px" },
  textarea: {
    width: "100%", minHeight: 200, padding: 12, borderRadius: 8, border: "1px solid var(--border, #e5e7eb)",
    background: "var(--input-bg, #f9fafb)", color: "var(--text, #1a1a1a)", fontSize: 12, boxSizing: "border-box",
    fontFamily: "'SFMono-Regular', Consolas, monospace", resize: "vertical",
  },
  row: { display: "flex", gap: 10, marginTop: 12, marginBottom: 20 },
  btn: (kind) => ({
    padding: "9px 18px", borderRadius: 6, border: kind === "primary" ? "none" : "1px solid var(--border, #e5e7eb)",
    background: kind === "primary" ? "var(--accent, #4f46e5)" : "transparent",
    color: kind === "primary" ? "#fff" : "var(--text, #1a1a1a)", cursor: "pointer", fontSize: 13, fontWeight: 600,
  }),
  errorBox: {
    padding: 16, borderRadius: 8, border: "1px solid #e05c5c", background: "rgba(224,92,92,0.08)",
    color: "#e05c5c", fontSize: 13, marginBottom: 20,
  },
  validBadge: (ok) => ({
    display: "inline-block", padding: "4px 10px", borderRadius: 20, fontSize: 12, fontWeight: 600,
    background: ok ? "rgba(63,185,80,0.12)" : "rgba(224,92,92,0.12)", color: ok ? "#3fb950" : "#e05c5c",
  }),
  section: { marginBottom: 20 },
  sectionTitle: { fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.04em", opacity: 0.6, marginBottom: 10 },
  grid: { display: "grid", gridTemplateColumns: "180px 1fr", gap: "8px 16px", fontSize: 13 },
  gridLabel: { opacity: 0.6 },
  gridValue: { fontFamily: "'SFMono-Regular', Consolas, monospace", wordBreak: "break-all" },
  list: { margin: 0, paddingLeft: 18, fontSize: 13 },
};

const GLOSSARY = [
  { term: "Subject", meaning: "Who/what the certificate identifies — for a server cert, this is the domain it's issued for." },
  { term: "Issuer", meaning: "The Certificate Authority (CA) that signed and vouches for this certificate. Same as Subject means self-signed." },
  { term: "SAN", meaning: "Subject Alternative Name — the actual list of domains/IPs a browser checks against; most clients ignore the Subject CN entirely now." },
  { term: "Serial Number", meaning: "A unique ID the issuing CA assigns — used to identify this exact certificate, e.g. in revocation lists." },
  { term: "Fingerprint", meaning: "A hash of the whole certificate — a quick way to confirm two certificates are byte-for-byte identical without comparing the full file." },
  { term: "Key Usage", meaning: "What operations the certificate's key is allowed to perform (e.g. digital signatures, key encipherment) — enforced by clients, not just descriptive." },
];

export default function CertDecoderTool() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  function decode() {
    if (!input.trim()) {
      setResult(null);
      setError(null);
      return;
    }
    try {
      setResult(decodeCertificate(input));
      setError(null);
    } catch (e) {
      setResult(null);
      setError("Couldn't parse this as a PEM X.509 certificate — " + e.message);
    }
  }

  function handleUploadClick() {
    fileInputRef.current?.click();
  }

  function handleFileChosen(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      setInput(String(reader.result || ""));
      setResult(null);
      setError(null);
    };
    reader.readAsText(file);
    e.target.value = "";
  }

  function clearAll() {
    setInput("");
    setResult(null);
    setError(null);
  }

  return (
    <div style={styles.root}>
      <Header repoUrl={REPO_URL} />
      <div style={styles.content}>
      <h1 style={styles.title}>Certificate Decoder</h1>
      <p style={styles.subtitle}>Paste a PEM certificate (-----BEGIN CERTIFICATE-----) to see what `openssl x509 -in cert.crt -text -noout` would show — subject, issuer, validity, SANs, public key, and fingerprints. Nothing leaves the browser.</p>

      <textarea style={styles.textarea} value={input} onChange={(e) => setInput(e.target.value)} placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"} spellCheck={false} />
      <div style={styles.row}>
        <input ref={fileInputRef} type="file" accept=".pem,.crt,.cer,.txt" style={{ display: "none" }} onChange={handleFileChosen} />
        <button style={styles.btn("secondary")} onClick={handleUploadClick}>Upload Certificate File</button>
        <button style={styles.btn("primary")} onClick={decode}>Decode</button>
        <button style={styles.btn("secondary")} onClick={clearAll}>Clear</button>
      </div>

      {error && <div style={styles.errorBox}>{error}</div>}

      {result && (
        <>
          <div style={styles.section}>
            <span style={styles.validBadge(result.isCurrentlyValid)}>
              {result.isCurrentlyValid ? `Valid — ${result.daysLeft} days remaining` : result.daysLeft < 0 ? `Expired ${-result.daysLeft} days ago` : "Not yet valid"}
            </span>
          </div>

          <div style={styles.section}>
            <div style={styles.sectionTitle}>Subject / Issuer</div>
            <div style={styles.grid}>
              <div style={styles.gridLabel}>Subject</div><div style={styles.gridValue}>{result.subject}</div>
              <div style={styles.gridLabel}>Issuer</div><div style={styles.gridValue}>{result.issuer}</div>
              <div style={styles.gridLabel}>Self-signed</div><div style={styles.gridValue}>{result.subject === result.issuer ? "Yes" : "No"}</div>
            </div>
          </div>

          <div style={styles.section}>
            <div style={styles.sectionTitle}>Validity &amp; Identity</div>
            <div style={styles.grid}>
              <div style={styles.gridLabel}>Not Before</div><div style={styles.gridValue}>{result.notBefore.toUTCString()}</div>
              <div style={styles.gridLabel}>Not After</div><div style={styles.gridValue}>{result.notAfter.toUTCString()}</div>
              <div style={styles.gridLabel}>Serial Number</div><div style={styles.gridValue}>{result.serialNumber}</div>
              <div style={styles.gridLabel}>Version</div><div style={styles.gridValue}>v{result.version}</div>
              <div style={styles.gridLabel}>Signature Algorithm</div><div style={styles.gridValue}>{result.signatureAlgorithm}</div>
              <div style={styles.gridLabel}>CA Certificate</div><div style={styles.gridValue}>{result.isCA ? "Yes" : "No"}</div>
            </div>
          </div>

          {result.sans.length > 0 && (
            <div style={styles.section}>
              <div style={styles.sectionTitle}>Subject Alternative Names</div>
              <ul style={styles.list}>{result.sans.map((s, i) => <li key={i}>{s}</li>)}</ul>
            </div>
          )}

          {(result.keyUsage.length > 0 || result.extKeyUsage.length > 0) && (
            <div style={styles.section}>
              <div style={styles.sectionTitle}>Key Usage</div>
              <div style={styles.grid}>
                {result.keyUsage.length > 0 && (<><div style={styles.gridLabel}>Key Usage</div><div style={styles.gridValue}>{result.keyUsage.join(", ")}</div></>)}
                {result.extKeyUsage.length > 0 && (<><div style={styles.gridLabel}>Extended Key Usage</div><div style={styles.gridValue}>{result.extKeyUsage.join(", ")}</div></>)}
              </div>
            </div>
          )}

          <div style={styles.section}>
            <div style={styles.sectionTitle}>Public Key</div>
            <div style={styles.grid}>
              <div style={styles.gridLabel}>Algorithm</div><div style={styles.gridValue}>{result.publicKey.algorithm}</div>
              <div style={styles.gridLabel}>Key Size</div><div style={styles.gridValue}>{result.publicKey.size}</div>
              <div style={styles.gridLabel}>Exponent</div><div style={styles.gridValue}>{result.publicKey.exponent}</div>
            </div>
          </div>

          <div style={styles.section}>
            <div style={styles.sectionTitle}>Fingerprints</div>
            <div style={styles.grid}>
              <div style={styles.gridLabel}>SHA-256</div><div style={styles.gridValue}>{result.sha256Fingerprint}</div>
              <div style={styles.gridLabel}>SHA-1</div><div style={styles.gridValue}>{result.sha1Fingerprint}</div>
            </div>
          </div>
        </>
      )}

      <div style={styles.section}>
        <div style={styles.sectionTitle}>Terms Explained</div>
        <table style={styles.legendTable}>
          <thead><tr><th style={styles.legendTh}>Term</th><th style={styles.legendTh}>Meaning</th></tr></thead>
          <tbody>
            {GLOSSARY.map((g) => (
              <tr key={g.term}><td style={styles.legendTd}>{g.term}</td><td style={{ ...styles.legendTd, fontFamily: "inherit" }}>{g.meaning}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
      </div>
    </div>
  );
}
