import base64URL from "base64url";

export const clean = new RegExp(/[:\n\s\r]{1,}/g);

export const jwkConv = (prvHex, pubHex, namedCurve) => ({
  kty: "EC",
  crv: namedCurve,
  d: base64URL.encode(prvHex, "hex"),
  x: null,
  y: null,
});
