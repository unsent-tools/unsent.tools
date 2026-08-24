// chmod.js — Unix file mode logic: octal <-> symbolic (ls -l style),
// chmod-style symbolic expressions (u+x,go-w), and plain-English readings.
// Pure functions, no DOM. A mode is an integer 0..0o7777.

const SETUID = 0o4000, SETGID = 0o2000, STICKY = 0o1000;

class ModeError extends Error {}
const fail = (msg) => { throw new ModeError(msg); };

// ---------------------------------------------------------------- octal

export function parseOctal(str) {
  str = String(str).trim();
  if (!/^[0-7]{1,4}$/.test(str)) {
    fail(`Octal modes are 1–4 digits of 0–7 (got "${str}").`);
  }
  return parseInt(str, 8);
}

export function formatOctal(mode, { pad = 3 } = {}) {
  if (mode < 0 || mode > 0o7777) fail("Mode out of range.");
  const digits = mode > 0o777 ? 4 : pad;
  return mode.toString(8).padStart(digits, "0");
}

// ------------------------------------------------------------- symbolic

// "rwxr-xr-x" (9 chars), with s/S in user/group execute slots and t/T in the
// other execute slot, exactly as ls -l prints them.
export function formatSymbolic(mode) {
  if (mode < 0 || mode > 0o7777) fail("Mode out of range.");
  const bit = (b) => (mode & b) !== 0;
  const slot = (r, w, x, special, setChar) => {
    let s = (bit(r) ? "r" : "-") + (bit(w) ? "w" : "-");
    if (bit(special)) s += bit(x) ? setChar : setChar.toUpperCase();
    else s += bit(x) ? "x" : "-";
    return s;
  };
  return (
    slot(0o400, 0o200, 0o100, SETUID, "s") +
    slot(0o040, 0o020, 0o010, SETGID, "s") +
    slot(0o004, 0o002, 0o001, STICKY, "t")
  );
}

export function parseSymbolic(str) {
  str = String(str).trim();
  // tolerate a leading file-type char from a pasted ls -l line (10 chars)
  if (/^[-dlbcsp]([rwxsStT-]{9})$/.test(str)) str = str.slice(1);
  if (!/^[rwxsStT-]{9}$/.test(str)) {
    fail(`Symbolic modes are 9 characters like rwxr-xr-x (got "${str}").`);
  }
  let mode = 0;
  const slots = [
    { off: 0, r: 0o400, w: 0o200, x: 0o100, special: SETUID, setChar: "s" },
    { off: 3, r: 0o040, w: 0o020, x: 0o010, special: SETGID, setChar: "s" },
    { off: 6, r: 0o004, w: 0o002, x: 0o001, special: STICKY, setChar: "t" },
  ];
  for (const { off, r, w, x, special, setChar } of slots) {
    const [cr, cw, cx] = str.slice(off, off + 3);
    if (cr === "r") mode |= r;
    else if (cr !== "-") fail(`Position ${off + 1} must be r or - (got "${cr}").`);
    if (cw === "w") mode |= w;
    else if (cw !== "-") fail(`Position ${off + 2} must be w or - (got "${cw}").`);
    if (cx === "x") mode |= x;
    else if (cx === setChar) mode |= special | x;
    else if (cx === setChar.toUpperCase()) mode |= special;
    else if (cx !== "-") fail(`Position ${off + 3} can't be "${cx}" here.`);
  }
  return mode;
}

// ------------------------------------------- chmod symbolic expressions

// Apply "u+x,go-w,a=r"-style clauses to a starting mode, GNU chmod semantics:
//   who: any of u g o a; omitted = a, except bits set in `umask` are not
//        affected (only when who is omitted).
//   op:  + - =    perms: r w x X s t, or empty (no-op for + and -, clear for =)
//   X:   execute only if `isDir` or some execute bit is already set.
//   s applies to u and g slots only; t to the "other" slot only (like chmod).
export function applySymbolic(expr, mode, { isDir = false, umask = 0 } = {}) {
  expr = String(expr).trim();
  if (expr === "") fail("Empty expression.");
  if (mode < 0 || mode > 0o7777) fail("Mode out of range.");

  for (const clause of expr.split(",")) {
    const m = /^([ugoa]*)([+\-=][rwxXst]*(?:[+\-=][rwxXst]*)*)$/.exec(clause.trim());
    if (!m) fail(`Can't read clause "${clause.trim()}". Expected like u+x or go-w or a=r.`);
    const whoStr = m[1];
    const whoOmitted = whoStr === "";
    const who = new Set(whoOmitted || whoStr.includes("a") ? "ugo" : whoStr);

    // multiple ops per clause are legal: u+r-w
    for (const [, op, perms] of m[2].matchAll(/([+\-=])([rwxXst]*)/g)) {
      if (op === undefined) continue;
      let bits = 0;
      const xNow = (mode & 0o111) !== 0;
      for (const p of perms) {
        for (const w of who) {
          const shift = w === "u" ? 6 : w === "g" ? 3 : 0;
          if (p === "r") bits |= 0o4 << shift;
          else if (p === "w") bits |= 0o2 << shift;
          else if (p === "x") bits |= 0o1 << shift;
          else if (p === "X") { if (isDir || xNow) bits |= 0o1 << shift; }
          else if (p === "s") { if (w === "u") bits |= SETUID; if (w === "g") bits |= SETGID; }
          else if (p === "t") { if (w === "o") bits |= STICKY; }
        }
      }
      if (whoOmitted) bits &= ~umask; // umask'd bits are neither set nor cleared
      if (op === "+") mode |= bits;
      else if (op === "-") mode &= ~bits;
      else {
        // "=": clear the who's rwx (and their special bits) then set. The
        // umask (omitted who) masks only what gets SET, not what is cleared —
        // verified against GNU chmod in the differential test.
        let clear = 0;
        for (const w of who) {
          clear |= w === "u" ? 0o700 | SETUID : w === "g" ? 0o070 | SETGID : 0o007 | STICKY;
        }
        // GNU chmod preserves a directory's setuid/setgid unless explicitly
        // specified (use u-s / g-s to clear them) — differential-verified.
        if (isDir) clear &= ~(SETUID | SETGID);
        mode = (mode & ~clear) | bits;
      }
    }
  }
  return mode;
}

// ------------------------------------------------------------- describe

const PERM_WORDS = { r: "read", w: "write", x: "execute" };

function slotWords(mode, shift) {
  const words = [];
  if (mode & (0o4 << shift)) words.push("read");
  if (mode & (0o2 << shift)) words.push("write");
  if (mode & (0o1 << shift)) words.push("execute");
  return words;
}

const list = (words) =>
  words.length === 0 ? "nothing" :
  words.length === 1 ? words[0] :
  words.slice(0, -1).join(", ") + " and " + words[words.length - 1];

// Returns { lines: [...], special: [...] } of plain-English statements.
export function describe(mode, { isDir = false } = {}) {
  if (mode < 0 || mode > 0o7777) fail("Mode out of range.");
  const noun = isDir ? "directory" : "file";
  const lines = [
    `Owner can ${list(slotWords(mode, 6))}.`,
    `Group members can ${list(slotWords(mode, 3))}.`,
    `Everyone else can ${list(slotWords(mode, 0))}.`,
  ];
  const special = [];
  if (mode & SETUID) {
    special.push(isDir
      ? "Setuid on a directory is ignored on most systems."
      : "Setuid: runs with the file owner's privileges" + ((mode & 0o100) ? "." : " — but the owner execute bit is off, so it has no effect (shown as capital S)."));
  }
  if (mode & SETGID) {
    special.push(isDir
      ? "Setgid: new files created inside inherit this directory's group."
      : "Setgid: runs with the file's group privileges" + ((mode & 0o010) ? "." : " — but the group execute bit is off, so it has no effect (shown as capital S)."));
  }
  if (mode & STICKY) {
    special.push(isDir
      ? "Sticky: only a file's owner (or root) can delete or rename files in this directory — standard for /tmp."
      : "Sticky bit on a regular file is ignored on Linux.");
  }
  if (isDir) {
    if ((mode & 0o400) && !(mode & 0o100)) special.push("Owner has read without execute: can list names but not open them or enter the directory.");
    if ((mode & 0o100) && !(mode & 0o400)) special.push("Owner has execute without read: can enter and open known names, but not list contents.");
  }
  return { lines, special, symbolic: formatSymbolic(mode), octal: formatOctal(mode) };
}

// Warnings worth surfacing for common footguns.
export function warnings(mode, { isDir = false } = {}) {
  const out = [];
  if ((mode & 0o002) && !isDir) out.push("World-writable: anyone on the system can modify this file.");
  if ((mode & 0o002) && isDir && !(mode & STICKY)) out.push("World-writable directory without the sticky bit: anyone can delete or replace anyone's files in it.");
  if (mode & SETUID && (mode & 0o100)) out.push("Setuid executables are a classic privilege-escalation surface — be sure this is intended.");
  const u = (mode >> 6) & 7, g = (mode >> 3) & 7, o = mode & 7;
  if ((g & ~u) || (o & ~u)) out.push("Group or others have permissions the owner lacks — legal, but almost always a mistake.");
  return out;
}
