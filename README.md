# Certificate Decoder

**Live demo:** https://certificate-decoder.vercel.app (Vercel) · [GitHub Pages mirror](https://babug01.github.io/certificate-decoder/)

Paste a PEM X.509 certificate to see what `openssl x509 -in cert.crt -text -noout` would show —
subject, issuer, validity window (with days-remaining or days-expired called out explicitly), SANs,
public key details, key usage, and both SHA-256 and SHA-1 fingerprints. Runs entirely in the
browser; nothing you paste ever leaves your machine.

## Features

- **Validity status** — a clear "Valid — N days remaining" / "Expired N days ago" / "Not yet valid"
  badge, not just raw dates
- **Subject / Issuer**, with a self-signed check
- **Subject Alternative Names** — the list clients actually check, not just the Subject CN
- **Key Usage / Extended Key Usage** flags, correctly excluding the extension's own `critical`
  bookkeeping field from the usage list (a real gotcha — a critical `keyUsage` extension otherwise
  slips through a naive `=== true` filter and shows up as if it were a usage flag itself)
- **Public key** algorithm, size, and exponent (RSA)
- **SHA-256 / SHA-1 fingerprints**
- A short glossary of what each term actually means

## Why I built this

sslshopper.com's decoder is fine but ad-heavy, and I wanted the key-usage extraction to actually be
correct (see the note above). This is also one piece of a larger internal DevOps tool I built at
work consolidating the utility pages a platform engineer reaches for daily into one place — this
repo is the certificate decoder piece, cleaned up and open-sourced on its own.

## Tech Stack

- [React](https://react.dev/) + [Vite](https://vitejs.dev/)
- [node-forge](https://github.com/digitalbazaar/forge) for real X.509 parsing

## Running locally

```bash
git clone https://github.com/Babug01/certificate-decoder.git
cd certificate-decoder
npm install
npm run dev
```

## License

MIT — see [LICENSE](LICENSE).
