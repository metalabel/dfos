/*

  FORMAT — tiny display helpers

*/

/** kid (`did:dfos:xxx#key`) → the DID prefix, '' when there is no `#` fragment. */
export const didOfKid = (kid: string): string => {
  const i = kid.indexOf('#');
  return i > 0 ? kid.slice(0, i) : '';
};

/** Ellipsize the middle of a long identifier. */
export const short = (value: string | null | undefined, head = 10, tail = 6): string => {
  if (!value) return '';
  if (value.length <= head + tail + 1) return value;
  // slice(-0) === slice(0) returns the WHOLE string — guard tail===0 explicitly
  const end = tail > 0 ? value.slice(-tail) : '';
  return `${value.slice(0, head)}…${end}`;
};

/** Unix seconds → YYYY-MM-DD (credential iat/exp). */
export const fmtUnixDate = (unix: number): string => {
  try {
    return new Date(unix * 1000).toISOString().slice(0, 10);
  } catch {
    return String(unix);
  }
};

/** Compact count: 20614 → "20.6k". */
export const fmtCount = (n: number): string =>
  n >= 10000 ? `${(n / 1000).toFixed(1)}k` : String(n);

/** ISO timestamp → coarse age like "3y" / "2mo" / "5d" / "4h" / "just now". */
export const fmtAge = (iso: string | null | undefined): string => {
  if (!iso) return '';
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return '';
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));
  const years = Math.floor(secs / 31536000);
  if (years >= 1) return `${years}y`;
  const months = Math.floor(secs / 2592000);
  if (months >= 1) return `${months}mo`;
  const days = Math.floor(secs / 86400);
  if (days >= 1) return `${days}d`;
  const hours = Math.floor(secs / 3600);
  if (hours >= 1) return `${hours}h`;
  const mins = Math.floor(secs / 60);
  if (mins >= 1) return `${mins}m`;
  return 'just now';
};

/** Bytes → "~92 MB" / "~1.2 GB" (binary units, browser-estimate precision). */
export const fmtBytes = (bytes: number | null | undefined): string => {
  if (bytes == null) return '';
  const mb = bytes / 1048576;
  if (mb >= 1024) return `~${(mb / 1024).toFixed(1)} GB`;
  if (mb >= 10) return `~${Math.round(mb)} MB`;
  if (mb >= 1) return `~${mb.toFixed(1)} MB`;
  return `~${Math.max(1, Math.round(bytes / 1024))} KB`;
};

export const copyToClipboard = (value: string): void => {
  void navigator.clipboard?.writeText(value).catch(() => {
    // clipboard denied — non-fatal
  });
};
