// PKCS#10 certificate signing request decoder (RFC 2986), plus real
// self-signature verification via WebCrypto. Reuses the DER parser and the
// Name/SPKI/extension decoders from the cert tool.
//
// A CSR is: CertificationRequest ::= SEQUENCE {
//   certificationRequestInfo  SEQUENCE { version INTEGER(0), subject Name,
//                                        subjectPKInfo, [0] attributes },
//   signatureAlgorithm        AlgorithmIdentifier,
//   signature                 BIT STRING }
// The signature is made with the requester's own private key over the DER of
// certificationRequestInfo — so it can be checked with the public key inside.
import {
  parseElement, content, toHex, readOid, readInteger, readBitString,
  readString, pemBlocks, CLASS_CONTEXT,
} from "../cert/der.js";
import {
  parseName, parseSpki, decodeExtension, algorithmIdentifier, expectSeq,
  SIG_ALGS, EXT_NAMES,
} from "../cert/cert.js";

export const ATTR_NAMES = {
  "1.2.840.113549.1.9.14": "extensionRequest",
  "1.2.840.113549.1.9.7": "challengePassword",
  "1.2.840.113549.1.9.2": "unstructuredName",
  "1.2.840.113549.1.9.8": "unstructuredAddress",
  "1.3.6.1.4.1.311.13.2.3": "msOSVersion",
  "1.3.6.1.4.1.311.21.20": "msRequestClientInfo",
  "1.2.840.113549.1.9.15": "smimeCapabilities",
};

// ---- the main decoder --------------------------------------------------

export function decodeCsr(der) {
  let root;
  try { root = parseElement(der, 0); }
  catch (e) { throw new Error(`Not valid DER: ${e.message}`); }
  expectSeq(root, "CertificationRequest");
  if (root.end !== der.length) {
    throw new Error(`Trailing bytes after the request (${der.length - root.end} extra).`);
  }
  const [criNode, sigAlgNode, sigValNode] = root.children;
  if (!criNode || !sigAlgNode || !sigValNode) {
    throw new Error("Malformed CSR: expected certificationRequestInfo, signatureAlgorithm, signature. Is this a CSR (not a certificate or key)?");
  }
  expectSeq(criNode, "CertificationRequestInfo");
  const cri = criNode.children;
  if (cri.length < 3) throw new Error("Malformed CSR: certificationRequestInfo is too short.");

  const version = Number(readInteger(der, cri[0]).bigint);
  const subject = parseName(der, cri[1]);
  const spkiNode = cri[2];
  const publicKey = parseSpki(der, spkiNode);

  // [0] IMPLICIT SET OF Attribute — required by RFC 2986, may be empty.
  const attrNode = cri.find((c) => c.cls === CLASS_CONTEXT && c.tag === 0);
  const attributes = [];
  let extensions = null; // requested extensions, decoded like a certificate's
  for (const attr of (attrNode && attrNode.children) || []) {
    let oid;
    try { oid = readOid(der, attr.children[0]); }
    catch { continue; }
    const valuesNode = attr.children[1]; // SET OF AttributeValue
    const values = (valuesNode && valuesNode.children) || [];
    if (oid === "1.2.840.113549.1.9.14" && values[0]) {
      // extensionRequest: the value is an Extensions SEQUENCE, same shape as
      // a certificate's — { extnID, critical DEFAULT FALSE, extnValue OCTET STRING }
      extensions = [];
      for (const ext of values[0].children || []) {
        const extOid = readOid(der, ext.children[0]);
        let critical = false, valIdx = 1;
        if (ext.children[1] && ext.children[1].tag === 1 && ext.children[1].cls === 0) {
          critical = der[ext.children[1].contentStart] !== 0;
          valIdx = 2;
        }
        const valueBytes = content(der, ext.children[valIdx]);
        extensions.push({
          oid: extOid, critical,
          name: EXT_NAMES[extOid] || extOid,
          ...decodeExtension(der, extOid, valueBytes),
        });
      }
      attributes.push({ oid, name: "extensionRequest", value: `${extensions.length} extension${extensions.length === 1 ? "" : "s"} (below)` });
    } else {
      const strings = values.map((v) => {
        const s = readString(der, v);
        return s !== null ? s : "#" + toHex(content(der, v));
      });
      attributes.push({ oid, name: ATTR_NAMES[oid] || oid, value: strings.join(", ") });
    }
  }

  const sigAlg = algorithmIdentifier(der, sigAlgNode);
  const sigAlgInfo = SIG_ALGS[sigAlg.oid] || null;
  const sigBits = readBitString(der, sigValNode);
  const signature = {
    oid: sigAlg.oid,
    name: sigAlgInfo ? sigAlgInfo.name : sigAlg.oid,
    weakHash: sigAlgInfo && sigAlgInfo.weak ? sigAlgInfo.weak : null,
    bytes: sigBits.bytes,
  };

  const san = (extensions || []).find((e) => e.oid === "2.5.29.17");
  const bc = (extensions || []).find((e) => e.oid === "2.5.29.19");
  const challenge = attributes.find((a) => a.oid === "1.2.840.113549.1.9.7");

  const warnings = [];
  if (version !== 0) warnings.push(`Version field is ${version}; PKCS#10 requires 0. Many CAs will reject this request.`);
  if (signature.weakHash) warnings.push(`Signed with ${signature.weakHash}, which is broken for signatures. Public CAs will refuse it; regenerate with SHA-256 or better.`);
  if (publicKey.type === "RSA" && publicKey.bits < 2048) warnings.push(`RSA key is only ${publicKey.bits} bits; below the 2048-bit minimum CAs accept.`);
  if (!san) warnings.push("No subjectAltName requested. Modern TLS matches hostnames against the SAN, not the CN — add one unless your CA fills it in from elsewhere.");
  if (challenge) warnings.push("Contains a challengePassword attribute, stored in plaintext (shown above). Anyone who sees this CSR can read it — never reuse a real password here.");
  if (bc && bc.ca) warnings.push("Requests basicConstraints CA:TRUE — this asks the CA to issue a CA certificate, which is almost never what a server needs.");

  const notes = [];
  if (subject.rfc2253 === "") notes.push("Empty subject DN (legal; some ACME clients do this and put everything in the SAN).");
  if (!extensions) notes.push("No extensionRequest attribute — the request asks for no extensions.");

  return {
    version, subject, publicKey, attributes, extensions, signature,
    warnings, notes,
    // byte ranges needed for signature verification
    criStart: criNode.start, criEnd: criNode.end,
    spkiStart: spkiNode.start, spkiEnd: spkiNode.end,
  };
}

// ---- self-signature verification (WebCrypto) ---------------------------

// Map a signature OID to WebCrypto parameters. Returns null if the
// algorithm can't be verified with WebCrypto (MD5, PSS, Ed448, secp256k1…).
const RSA_HASHES = {
  "1.2.840.113549.1.1.5": "SHA-1", "1.2.840.113549.1.1.11": "SHA-256",
  "1.2.840.113549.1.1.12": "SHA-384", "1.2.840.113549.1.1.13": "SHA-512",
};
const ECDSA_HASHES = {
  "1.2.840.10045.4.1": "SHA-1", "1.2.840.10045.4.3.2": "SHA-256",
  "1.2.840.10045.4.3.3": "SHA-384", "1.2.840.10045.4.3.4": "SHA-512",
};
const WEBCRYPTO_CURVES = {
  "1.2.840.10045.3.1.7": { name: "P-256", bytes: 32 },
  "1.3.132.0.34": { name: "P-384", bytes: 48 },
  "1.3.132.0.35": { name: "P-521", bytes: 66 },
};

// ECDSA signatures in a CSR are DER SEQUENCE { r INTEGER, s INTEGER };
// WebCrypto wants raw fixed-width r||s. Strip sign pads, left-pad to width.
export function ecdsaDerToRaw(sigBytes, widthBytes) {
  const seq = parseElement(sigBytes, 0);
  if (seq.tag !== 16 || !seq.children || seq.children.length !== 2) {
    throw new Error("ECDSA signature is not a SEQUENCE of two INTEGERs.");
  }
  const out = new Uint8Array(widthBytes * 2);
  seq.children.forEach((intNode, i) => {
    let c = content(sigBytes, intNode);
    while (c.length > 0 && c[0] === 0) c = c.subarray(1); // sign pad
    if (c.length > widthBytes) throw new Error("ECDSA integer wider than the curve.");
    out.set(c, widthBytes * (i + 1) - c.length);
  });
  return out;
}

// Verify the CSR's self-signature. Returns
//   { state: "valid" | "invalid" | "unsupported" | "unavailable", detail }.
// "unsupported" = algorithm exists but WebCrypto here can't check it;
// "unavailable" = no WebCrypto at all.
export async function verifyCsrSignature(der, decoded) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) return { state: "unavailable", detail: "WebCrypto is not available in this environment." };

  const signed = der.subarray(decoded.criStart, decoded.criEnd);
  const spki = der.subarray(decoded.spkiStart, decoded.spkiEnd);
  const oid = decoded.signature.oid;
  let importAlg, verifyAlg, sig = decoded.signature.bytes;

  if (RSA_HASHES[oid]) {
    importAlg = { name: "RSASSA-PKCS1-v1_5", hash: RSA_HASHES[oid] };
    verifyAlg = importAlg;
  } else if (ECDSA_HASHES[oid]) {
    const curve = WEBCRYPTO_CURVES[decoded.publicKey.curveOid];
    if (!curve) return { state: "unsupported", detail: `Cannot verify: curve ${decoded.publicKey.curve || decoded.publicKey.curveOid || "(unknown)"} is not supported by WebCrypto.` };
    importAlg = { name: "ECDSA", namedCurve: curve.name };
    verifyAlg = { name: "ECDSA", hash: ECDSA_HASHES[oid] };
    try { sig = ecdsaDerToRaw(sig, curve.bytes); }
    catch (e) { return { state: "invalid", detail: `Malformed ECDSA signature: ${e.message}` }; }
  } else if (oid === "1.3.101.112") {
    importAlg = "Ed25519";
    verifyAlg = "Ed25519";
  } else {
    return { state: "unsupported", detail: `Cannot verify a ${decoded.signature.name} signature with WebCrypto.` };
  }

  let key;
  try { key = await subtle.importKey("spki", spki, importAlg, false, ["verify"]); }
  catch (e) { return { state: "unsupported", detail: `This environment's WebCrypto cannot import the key (${e.message || "unsupported algorithm"}).` }; }
  try {
    const ok = await subtle.verify(verifyAlg, key, sig, signed);
    return ok
      ? { state: "valid", detail: "The self-signature verifies: the request is intact and made by the holder of this key." }
      : { state: "invalid", detail: "The self-signature does NOT verify — the CSR is corrupted or has been tampered with." };
  } catch (e) {
    return { state: "unsupported", detail: `Verification failed to run (${e.message || "unsupported algorithm"}).` };
  }
}

// ---- PEM input ---------------------------------------------------------

// Decode every CSR block in a paste. Certificates and private keys are
// recognised and refused with a pointed message.
export function decodeCsrPemInput(text) {
  const blocks = pemBlocks(text);
  if (blocks.length === 0) {
    throw new Error("No PEM block found. Paste a -----BEGIN CERTIFICATE REQUEST----- block (or bare base64 DER).");
  }
  const csrs = [], skipped = [];
  for (const b of blocks) {
    // pemBlocks labels bare base64 "CERTIFICATE"; here, treat bare input as a CSR attempt
    const isCsr = /CERTIFICATE REQUEST/.test(b.label) || b.bare;
    if (!isCsr) {
      if (/PRIVATE KEY/.test(b.label)) skipped.push(b.label + " (this is a PRIVATE KEY, not a CSR — treat it as compromised if you pasted it anywhere else)");
      else if (/CERTIFICATE/.test(b.label)) skipped.push(b.label + " (this is a certificate, not a CSR — use the certificate decoder at /tools/cert/)");
      else skipped.push(b.label);
      continue;
    }
    try { csrs.push({ der: b.der, decoded: decodeCsr(b.der) }); }
    catch (e) { csrs.push({ der: b.der, error: e.message }); }
  }
  return { csrs, skipped };
}
