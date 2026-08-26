// X.509 certificate decoder (RFC 5280 subset). Pure functions; all time
// context is an explicit `now` parameter. Fingerprints are async (WebCrypto).
import {
  parseElement, content, toHex, readOid, readInteger, readBitString,
  readString, readTime, pemBlocks, CLASS_CONTEXT, CLASS_UNIVERSAL,
} from "./der.js";
import { ipv6ToString } from "../subnet/subnet6.js";

// ---- OID registries ----------------------------------------------------

export const SIG_ALGS = {
  "1.2.840.113549.1.1.2": { name: "md2WithRSAEncryption", weak: "MD2" },
  "1.2.840.113549.1.1.4": { name: "md5WithRSAEncryption", weak: "MD5" },
  "1.2.840.113549.1.1.5": { name: "sha1WithRSAEncryption", weak: "SHA-1" },
  "1.2.840.113549.1.1.11": { name: "sha256WithRSAEncryption" },
  "1.2.840.113549.1.1.12": { name: "sha384WithRSAEncryption" },
  "1.2.840.113549.1.1.13": { name: "sha512WithRSAEncryption" },
  "1.2.840.113549.1.1.10": { name: "rsassaPss" },
  "1.2.840.10045.4.1": { name: "ecdsa-with-SHA1", weak: "SHA-1" },
  "1.2.840.10045.4.3.2": { name: "ecdsa-with-SHA256" },
  "1.2.840.10045.4.3.3": { name: "ecdsa-with-SHA384" },
  "1.2.840.10045.4.3.4": { name: "ecdsa-with-SHA512" },
  "1.3.101.112": { name: "Ed25519" },
  "1.3.101.113": { name: "Ed448" },
};

export const KEY_ALGS = {
  "1.2.840.113549.1.1.1": "rsaEncryption",
  "1.2.840.10045.2.1": "id-ecPublicKey",
  "1.3.101.110": "X25519",
  "1.3.101.111": "X448",
  "1.3.101.112": "Ed25519",
  "1.3.101.113": "Ed448",
};

export const CURVES = {
  "1.2.840.10045.3.1.7": "P-256 (prime256v1)",
  "1.3.132.0.34": "P-384 (secp384r1)",
  "1.3.132.0.35": "P-521 (secp521r1)",
  "1.3.132.0.10": "secp256k1",
};

// DN attribute types: short name where one exists (RFC 4514), else long name.
export const DN_ATTRS = {
  "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
  "2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
  "2.5.4.4": "SN", "2.5.4.42": "givenName", "2.5.4.12": "title",
  "2.5.4.15": "businessCategory", "2.5.4.17": "postalCode",
  "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
  "1.2.840.113549.1.9.1": "emailAddress",
  "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
  "1.3.6.1.4.1.311.60.2.1.2": "jurisdictionST",
  "1.3.6.1.4.1.311.60.2.1.1": "jurisdictionL",
};

export const EXT_NAMES = {
  "2.5.29.35": "Authority Key Identifier",
  "2.5.29.14": "Subject Key Identifier",
  "2.5.29.15": "Key Usage",
  "2.5.29.17": "Subject Alternative Name",
  "2.5.29.18": "Issuer Alternative Name",
  "2.5.29.19": "Basic Constraints",
  "2.5.29.30": "Name Constraints",
  "2.5.29.31": "CRL Distribution Points",
  "2.5.29.32": "Certificate Policies",
  "2.5.29.36": "Policy Constraints",
  "2.5.29.37": "Extended Key Usage",
  "2.5.29.54": "Inhibit anyPolicy",
  "1.3.6.1.5.5.7.1.1": "Authority Information Access",
  "1.3.6.1.5.5.7.1.11": "Subject Information Access",
  "1.3.6.1.4.1.11129.2.4.2": "Signed Certificate Timestamps (SCT)",
  "1.3.6.1.4.1.11129.2.4.3": "CT Precertificate Poison",
  "1.3.6.1.5.5.7.1.24": "TLS Feature (e.g. OCSP must-staple)",
};

export const EKU_NAMES = {
  "1.3.6.1.5.5.7.3.1": "TLS server authentication",
  "1.3.6.1.5.5.7.3.2": "TLS client authentication",
  "1.3.6.1.5.5.7.3.3": "Code signing",
  "1.3.6.1.5.5.7.3.4": "Email protection (S/MIME)",
  "1.3.6.1.5.5.7.3.8": "Time stamping",
  "1.3.6.1.5.5.7.3.9": "OCSP signing",
  "2.5.29.37.0": "Any extended key usage",
};

const KEY_USAGE_BITS = [
  "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
  "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly",
];

// ---- helpers -----------------------------------------------------------

export function expectSeq(node, what) {
  if (!node || node.cls !== CLASS_UNIVERSAL || node.tag !== 16 || !node.constructed) {
    throw new Error(`Malformed certificate: expected a SEQUENCE for ${what}.`);
  }
  return node;
}

export function algorithmIdentifier(bytes, node) {
  expectSeq(node, "AlgorithmIdentifier");
  const oid = readOid(bytes, node.children[0]);
  return { oid, params: node.children[1] || null };
}

// Name (RDNSequence) → { rdns: [[{oidName, oid, value}]], rfc2253, display }
export function parseName(bytes, node) {
  expectSeq(node, "Name");
  const rdns = [];
  for (const rdnSet of node.children) {
    const attrs = [];
    for (const atv of rdnSet.children || []) {
      const oid = readOid(bytes, atv.children[0]);
      const valNode = atv.children[1];
      let value = readString(bytes, valNode);
      let hexFallback = false;
      if (value === null) { value = "#" + toHex(content(bytes, valNode)); hexFallback = true; }
      attrs.push({ oid, name: DN_ATTRS[oid] || oid, value, hexFallback });
    }
    rdns.push(attrs);
  }
  return { rdns, rfc2253: nameToRfc2253(rdns), display: rdns.flat() };
}

// RFC 2253/4514 string form: RDNs in reverse order, escaped.
function esc2253(v) {
  let out = "";
  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    if ("+,;<>\"\\".includes(c)) out += "\\" + c;
    else if (c === "#" && i === 0) out += "\\#";
    else if (c === " " && (i === 0 || i === v.length - 1)) out += "\\ ";
    else out += c;
  }
  return out;
}

export function nameToRfc2253(rdns) {
  return rdns
    .slice().reverse()
    .map((attrs) => attrs.map((a) => `${a.name}=${a.hexFallback ? a.value : esc2253(a.value)}`).join("+"))
    .join(",");
}

function findContext(children, tagNum, constructed = true) {
  return (children || []).find((c) => c.cls === CLASS_CONTEXT && c.tag === tagNum && c.constructed === constructed) || null;
}

function formatIp(u8) {
  if (u8.length === 4) return Array.from(u8).join(".");
  if (u8.length === 16) {
    let v = 0n;
    for (const b of u8) v = (v << 8n) | BigInt(b);
    return ipv6ToString(v);
  }
  return "invalid IP (" + toHex(u8) + ")";
}

// GeneralNames → [{type, value}]
function parseGeneralNames(bytes, node) {
  const out = [];
  for (const gn of node.children || []) {
    if (gn.cls !== CLASS_CONTEXT) continue;
    switch (gn.tag) {
      case 1: out.push({ type: "email", value: new TextDecoder().decode(content(bytes, gn)) }); break;
      case 2: out.push({ type: "DNS", value: new TextDecoder().decode(content(bytes, gn)) }); break;
      case 4: {
        // directoryName is EXPLICIT: [4] wraps the Name SEQUENCE
        const inner = gn.children && gn.children[0];
        out.push({ type: "dirName", value: inner ? parseName(bytes, inner).rfc2253 : "" });
        break;
      }
      case 6: out.push({ type: "URI", value: new TextDecoder().decode(content(bytes, gn)) }); break;
      case 7: out.push({ type: "IP", value: formatIp(content(bytes, gn)) }); break;
      case 0: out.push({ type: "otherName", value: "(otherName)" }); break;
      default: out.push({ type: `[${gn.tag}]`, value: toHex(content(bytes, gn)) });
    }
  }
  return out;
}

// ---- extension decoders ------------------------------------------------

export function decodeExtension(bytes, oid, valueBytes) {
  // valueBytes is the DER inside the extension's OCTET STRING.
  const parse = () => parseElement(valueBytes, 0);
  try {
    switch (oid) {
      case "2.5.29.17": case "2.5.29.18": { // SAN / IAN
        const names = parseGeneralNames(valueBytes, parse());
        return { kind: "generalNames", names,
                 summary: names.map((n) => `${n.type}:${n.value}`).join(", ") };
      }
      case "2.5.29.19": { // BasicConstraints ::= SEQUENCE { cA BOOL DEFAULT FALSE, pathLen INTEGER OPT }
        const seq = parse();
        let ca = false, pathLen = null;
        for (const ch of seq.children || []) {
          if (ch.tag === 1) ca = valueBytes[ch.contentStart] !== 0;
          if (ch.tag === 2) pathLen = Number(readInteger(valueBytes, ch).bigint);
        }
        return { kind: "basicConstraints", ca, pathLen,
                 summary: ca ? `CA:TRUE${pathLen !== null ? `, pathlen:${pathLen}` : ""}` : "CA:FALSE" };
      }
      case "2.5.29.15": { // KeyUsage ::= BIT STRING
        const bs = readBitString(valueBytes, parse());
        const usages = [];
        for (let i = 0; i < KEY_USAGE_BITS.length; i++) {
          const byte = bs.bytes[i >> 3];
          if (byte !== undefined && (byte & (0x80 >> (i & 7))) !== 0) usages.push(KEY_USAGE_BITS[i]);
        }
        return { kind: "keyUsage", usages, summary: usages.join(", ") || "(none)" };
      }
      case "2.5.29.37": { // ExtKeyUsage ::= SEQUENCE OF OID
        const seq = parse();
        const purposes = (seq.children || []).map((c) => {
          const o = readOid(valueBytes, c);
          return { oid: o, name: EKU_NAMES[o] || o };
        });
        return { kind: "extKeyUsage", purposes, summary: purposes.map((p) => p.name).join(", ") };
      }
      case "2.5.29.14": { // SKI ::= OCTET STRING
        const n = parse();
        return { kind: "keyId", summary: toHex(content(valueBytes, n), ":") };
      }
      case "2.5.29.35": { // AKI ::= SEQUENCE { [0] keyIdentifier OPT, ... }
        const seq = parse();
        const kid = (seq.children || []).find((c) => c.cls === CLASS_CONTEXT && c.tag === 0);
        return { kind: "keyId",
                 summary: kid ? toHex(content(valueBytes, kid), ":") : "(no key id)" };
      }
      case "2.5.29.31": { // CRLDistributionPoints — pull out the URIs
        const seq = parse();
        const uris = [];
        (function walk(n) {
          if (n.cls === CLASS_CONTEXT && n.tag === 6 && !n.constructed) {
            uris.push(new TextDecoder().decode(content(valueBytes, n)));
          }
          for (const c of n.children || []) walk(c);
        })(seq);
        return { kind: "uris", uris, summary: uris.join(", ") || "(no URIs)" };
      }
      case "1.3.6.1.5.5.7.1.1": { // AIA ::= SEQ OF { method OID, location GeneralName }
        const seq = parse();
        const entries = (seq.children || []).map((ad) => {
          const method = readOid(valueBytes, ad.children[0]);
          const label = method === "1.3.6.1.5.5.7.48.1" ? "OCSP"
                      : method === "1.3.6.1.5.5.7.48.2" ? "CA Issuers" : method;
          const loc = ad.children[1];
          const value = loc.cls === CLASS_CONTEXT && loc.tag === 6
            ? new TextDecoder().decode(content(valueBytes, loc)) : "(non-URI)";
          return { label, value };
        });
        return { kind: "aia", entries,
                 summary: entries.map((e) => `${e.label}: ${e.value}`).join(", ") };
      }
      case "2.5.29.32": { // CertificatePolicies — list policy OIDs
        const seq = parse();
        const oids = (seq.children || []).map((p) => readOid(valueBytes, p.children[0]));
        return { kind: "policies", oids, summary: oids.join(", ") };
      }
      default:
        return { kind: "raw", summary: `${valueBytes.length} bytes` };
    }
  } catch (e) {
    return { kind: "error", summary: `could not decode (${e.message})` };
  }
}

// ---- public key --------------------------------------------------------

export function parseSpki(bytes, node) {
  expectSeq(node, "SubjectPublicKeyInfo");
  const alg = algorithmIdentifier(bytes, node.children[0]);
  const keyBits = readBitString(bytes, node.children[1]);
  const algName = KEY_ALGS[alg.oid] || alg.oid;
  const out = { algOid: alg.oid, algName, sizeText: `${keyBits.bytes.length} bytes` };

  if (alg.oid === "1.2.840.113549.1.1.1") { // RSA: BIT STRING wraps SEQUENCE {n, e}
    const rsa = parseElement(keyBits.bytes, 0);
    const n = readInteger(keyBits.bytes, rsa.children[0]);
    const e = readInteger(keyBits.bytes, rsa.children[1]);
    // modulus INTEGER often has a leading 0x00 to stay positive; bit length from bigint
    out.type = "RSA";
    out.bits = n.bigint.toString(2).length;
    out.exponent = e.bigint.toString();
    out.sizeText = `RSA ${out.bits}-bit, e=${out.exponent}`;
  } else if (alg.oid === "1.2.840.10045.2.1") { // EC: params = curve OID
    out.type = "EC";
    if (alg.params && alg.params.tag === 6) {
      out.curveOid = readOid(bytes, alg.params);
      out.curve = CURVES[out.curveOid] || out.curveOid;
    } else {
      out.curve = "(unnamed curve)";
    }
    out.sizeText = `EC, curve ${out.curve}`;
  } else if (algName === "Ed25519" || algName === "Ed448" || algName === "X25519" || algName === "X448") {
    out.type = algName;
    out.sizeText = `${algName} (${keyBits.bytes.length * 8}-bit)`;
  } else {
    out.type = algName;
  }
  return out;
}

// ---- the main decoder --------------------------------------------------

// Decode one DER certificate. `now` (ms epoch) drives validity status.
export function decodeCertificate(der, now) {
  let root;
  try { root = parseElement(der, 0); }
  catch (e) { throw new Error(`Not valid DER: ${e.message}`); }
  expectSeq(root, "Certificate");
  if (root.end !== der.length) {
    throw new Error(`Trailing bytes after certificate (${der.length - root.end} extra).`);
  }
  const [tbsNode, sigAlgNode, sigValNode] = root.children;
  if (!tbsNode || !sigAlgNode || !sigValNode) {
    throw new Error("Malformed certificate: expected tbsCertificate, signatureAlgorithm, signatureValue. Is this a certificate (not a key or CSR)?");
  }
  expectSeq(tbsNode, "TBSCertificate");
  const tbs = tbsNode.children;
  let i = 0;

  // version: [0] EXPLICIT INTEGER, DEFAULT v1
  let version = 1;
  if (tbs[0] && tbs[0].cls === CLASS_CONTEXT && tbs[0].tag === 0) {
    version = Number(readInteger(der, tbs[0].children[0]).bigint) + 1;
    i = 1;
  }

  const serial = readInteger(der, tbs[i++]);
  // DER pads a positive INTEGER whose top bit is set with a leading 0x00;
  // openssl/browsers display serials without that pad byte. Do the same.
  const serialHex = (!serial.negative && serial.hex.length > 2 && serial.hex.startsWith("00"))
    ? serial.hex.replace(/^(00)+(?=..)/, "") : serial.hex;
  const tbsSigAlg = algorithmIdentifier(der, tbs[i++]);
  const issuer = parseName(der, tbs[i++]);
  const validityNode = expectSeq(tbs[i++], "Validity");
  const notBefore = readTime(der, validityNode.children[0]);
  const notAfter = readTime(der, validityNode.children[1]);
  const subject = parseName(der, tbs[i++]);
  const publicKey = parseSpki(der, tbs[i++]);

  // optional [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions
  const extNode = findContext(tbs.slice(i), 3);
  const extensions = [];
  if (extNode) {
    const extSeq = extNode.children[0];
    for (const ext of extSeq.children || []) {
      const oid = readOid(der, ext.children[0]);
      let critical = false, valIdx = 1;
      if (ext.children[1] && ext.children[1].tag === 1 && ext.children[1].cls === CLASS_UNIVERSAL) {
        critical = der[ext.children[1].contentStart] !== 0;
        valIdx = 2;
      }
      const valueBytes = content(der, ext.children[valIdx]);
      extensions.push({
        oid, critical,
        name: EXT_NAMES[oid] || oid,
        ...decodeExtension(der, oid, valueBytes),
      });
    }
  }

  const sigAlg = algorithmIdentifier(der, sigAlgNode);
  const sigAlgInfo = SIG_ALGS[sigAlg.oid] || null;
  const signature = {
    oid: sigAlg.oid,
    name: sigAlgInfo ? sigAlgInfo.name : sigAlg.oid,
    weakHash: sigAlgInfo && sigAlgInfo.weak ? sigAlgInfo.weak : null,
    mismatch: sigAlg.oid !== tbsSigAlg.oid,
    bytes: readBitString(der, sigValNode).bytes.length,
  };

  // validity status
  const DAY = 86400000;
  const validityDays = Math.round((notAfter.epochMs - notBefore.epochMs) / DAY);
  let status;
  if (now < notBefore.epochMs) status = { state: "not-yet-valid", detail: `becomes valid ${notBefore.iso}` };
  else if (now > notAfter.epochMs) status = { state: "expired", detail: `expired ${notAfter.iso} (${Math.floor((now - notAfter.epochMs) / DAY)} days ago)` };
  else status = { state: "valid", detail: `${Math.floor((notAfter.epochMs - now) / DAY)} days remaining` };

  const san = extensions.find((e) => e.oid === "2.5.29.17");
  const bc = extensions.find((e) => e.oid === "2.5.29.19");
  const isCa = !!(bc && bc.ca);
  const selfIssued = subject.rfc2253 === issuer.rfc2253;

  const warnings = [];
  if (status.state === "expired") warnings.push(`Expired: ${status.detail}.`);
  if (status.state === "not-yet-valid") warnings.push(`Not yet valid: ${status.detail}.`);
  if (signature.weakHash) warnings.push(`Signature uses ${signature.weakHash}, which is broken for certificates. Do not trust this signature.`);
  if (signature.mismatch) warnings.push("The outer signature algorithm differs from the one inside tbsCertificate — malformed or tampered certificate.");
  if (publicKey.type === "RSA" && publicKey.bits < 2048) warnings.push(`RSA key is only ${publicKey.bits} bits; below the 2048-bit minimum.`);
  if (serial.negative) warnings.push("Serial number is negative, which RFC 5280 forbids.");
  if (version === 3 && !san && !isCa) warnings.push("No Subject Alternative Name — browsers ignore the CN field, so this certificate cannot match any hostname in modern TLS clients.");
  if (version < 3) warnings.push(`Version ${version} certificate — X.509 v3 (with extensions) has been the norm since the late 1990s.`);
  if (!isCa && validityDays > 398) warnings.push(`Validity is ${validityDays} days; public TLS certificates issued after 2020 are limited to 398 days (browsers reject longer).`);

  const notes = [];
  if (selfIssued) notes.push(isCa ? "Self-signed CA (subject equals issuer)." : "Subject equals issuer — self-signed certificate.");
  if (notAfter.kind === "GeneralizedTime" || notBefore.kind === "GeneralizedTime") {
    notes.push("Uses GeneralizedTime (dates in 2050 or later are encoded this way).");
  }

  return {
    version, serial: { hex: serialHex, decimal: serial.bigint.toString(), negative: serial.negative },
    signature, issuer, subject,
    notBefore, notAfter, validityDays, status,
    publicKey, extensions, isCa, selfIssued, san: san ? san.names : null,
    warnings, notes,
  };
}

// Decode every certificate block in a PEM/base64 paste.
// Returns { certs: [{decoded|error, der, label}], skipped: [labels] }.
export function decodePemInput(text, now) {
  const blocks = pemBlocks(text);
  if (blocks.length === 0) {
    throw new Error("No PEM block found. Paste one or more -----BEGIN CERTIFICATE----- blocks (or bare base64 DER).");
  }
  const certs = [], skipped = [];
  for (const b of blocks) {
    if (/CERTIFICATE REQUEST/.test(b.label)) { skipped.push(b.label + " (this is a CSR, not a certificate — use the CSR decoder at /tools/csr/)"); continue; }
    if (/PRIVATE KEY/.test(b.label)) { skipped.push(b.label + " (this is a PRIVATE KEY, not a certificate — treat it as compromised if you pasted it anywhere else)"); continue; }
    if (b.label !== "CERTIFICATE" && b.label !== "TRUSTED CERTIFICATE") { skipped.push(b.label); continue; }
    try { certs.push({ der: b.der, decoded: decodeCertificate(b.der, now) }); }
    catch (e) { certs.push({ der: b.der, error: e.message }); }
  }
  return { certs, skipped };
}

// SHA-256 and SHA-1 fingerprints of the DER. Async: WebCrypto.
export async function fingerprints(der) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) return null;
  const [s256, s1] = await Promise.all([
    subtle.digest("SHA-256", der), subtle.digest("SHA-1", der),
  ]);
  return {
    sha256: toHex(new Uint8Array(s256), ":").toUpperCase(),
    sha1: toHex(new Uint8Array(s1), ":").toUpperCase(),
  };
}
