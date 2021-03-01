import base58 from "bs58";
import { createHash } from "crypto";
import ripemd160 from "ripemd160";

export function createPublicAddress(publicKey) {
  let hash = createHash("sha256").update(Buffer.from(publicKey, "hex")).digest();
  let publicKeyHash = new ripemd160().update(Buffer.from(hash, "hex")).digest("hex");
  // step 1 - add prefix "00" in hex
  const step1 = Buffer.from("00" + publicKeyHash, "hex");
  // step 2 - create SHA256 hash of step 1
  const step2 = createHash("sha256").update(step1).digest("hex");
  // step 3 - create SHA256 hash of step 2
  const step3 = createHash("sha256").update(Buffer.from(step2, "hex")).digest("hex");
  // step 4 - find the 1st byte of step 3 - save as "checksum"
  const checksum = step3.substring(0, 8);
  // step 5 - add step 1 + checksum
  const step4 = step1.toString("hex") + checksum;
  // return base 58 encoding of step 5
  const address = base58.encode(Buffer.from(step4, "hex"));
  // return address
  return address;
}
