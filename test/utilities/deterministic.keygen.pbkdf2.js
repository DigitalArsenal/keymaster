import { pbkdf2Sync } from "crypto";
import keymaster from "../../dist/index.min.mjs";

/**
 * Create a deterministic key for testing purposes
 *
 * @function createPBKDF2Key
 * @param {string} password - Password to use in Password-Based Key Derivation Function 2 (PBKDF2)
 * @param {string} seed - Seed to use in Password-Based Key Derivation Function 2 (PBKDF2)
 * @param {number} [iterations=32] - Number of iterations to use
 * @param {Boolean} [verbose=false]
 */

export const createPBKDF2Key = (password, seed, iterations = 1, byteLength = 32, verbose) => {
  console
  let pK = pbkdf2Sync(password, seed, iterations, byteLength, "sha256", 0);
  let hexKey = pK.toString("hex");
  let bigKey = BigInt(`0x${hexKey}`);

  if (verbose) {
    console.log(
      pK,
      `Deterministic Private Key:
${new Array(60).join("-")}
Buffer:`,
      pK,
      `\nhex: ${pK.toString("hex")}
BigNum: ${bigKey}
isValid: ${keymaster.validPrivateKey(pK)}
    `
    );
  }
  return pK;
};
