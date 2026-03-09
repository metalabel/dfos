/*

  BASE64URL

  Shared base64url encoding/decoding for JWT and JWS modules

*/

/**
 * Encode bytes or a string as a base64url string (no padding)
 */
export const base64urlEncode = (data: Uint8Array | string): string => {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;

  // chunk to avoid stack overflow with spread on large payloads
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }

  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/**
 * Decode a base64url string to bytes
 */
export const base64urlDecode = (str: string): Uint8Array => {
  let padded = str.replace(/-/g, '+').replace(/_/g, '/');
  while (padded.length % 4) padded += '=';
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};
