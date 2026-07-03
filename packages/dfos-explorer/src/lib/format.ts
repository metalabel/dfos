/*

  FORMAT — tiny display helpers

*/

/** Ellipsize the middle of a long identifier. */
export const short = (value: string | null | undefined, head = 10, tail = 6): string => {
  if (!value) return '';
  return value.length > head + tail + 1 ? `${value.slice(0, head)}…${value.slice(-tail)}` : value;
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

export const copyToClipboard = (value: string): void => {
  void navigator.clipboard?.writeText(value).catch(() => {
    // clipboard denied — non-fatal
  });
};
