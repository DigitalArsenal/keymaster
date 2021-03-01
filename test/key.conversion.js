import assert from "assert";
import bitcoinjs from "bitcoinjs-lib";
import wif from "wif";
import { createPBKDF2Key } from "./utilities/deterministic.keygen.pbkdf2.js";
import { createPublicAddress } from "./utilities/bitcoin.address.from.hex.js";
import { clean } from "./utilities/utility.js";

import keymaster, {
  NID_secp256k1,
  NID_Private,
  NID_X9_62_id_ecPublicKey,
  V_ASN1_BIT_STRING,
  PEM_TYPE_ENCRYPTED,
  PEM_TYPE_CLEAR,
  POINT_CONVERSION_UNCOMPRESSED,
  POINT_CONVERSION_COMPRESSED,
} from "../dist/index.min.mjs";

import { writeFileSync, unlinkSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { execSync } from "child_process";

const key = createPBKDF2Key("SomeInput", "SomeSeed", 1);
let dPublicKeys = { uncompressed: null, compressed: null };
const dPassword = "SomePassword";
const curve = NID_secp256k1;

const Keymaster = new keymaster();

describe("public key and address from private key", () => {
  beforeEach(() => Promise.all([!Keymaster.init ? Keymaster.initialize() : Promise.resolve()]));

  const genKeys = ({ c }) => {
    const dPublicKey = Keymaster.convertKey({
      key,
      curve,
      outputtype: NID_X9_62_id_ecPublicKey,
      outformat: V_ASN1_BIT_STRING,
      compressed: c ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED,
    });
    if (c) {
      dPublicKeys.compressed = new Buffer.from(dPublicKey, "hex");
    } else {
      dPublicKeys.uncompressed = new Buffer.from(dPublicKey, "hex");
    }
    const bjsKeyPair = bitcoinjs.ECPair.fromWIF(wif.encode(128, key, c));
    assert.deepStrictEqual(key, bjsKeyPair.privateKey);
    const { address } = bitcoinjs.payments.p2pkh({
      pubkey: bjsKeyPair.publicKey,
    });
    assert.deepStrictEqual(address, createPublicAddress(dPublicKey));
  };

  const genPEM = async ({ p } = { p: false }) => {
    let PEM = Keymaster.convertKey({
      key,
      curve,
      outputtype: NID_Private,
      compressed: POINT_CONVERSION_UNCOMPRESSED,
      outformat: p ? PEM_TYPE_ENCRYPTED : PEM_TYPE_CLEAR,
      password: p,
    });

    const tmpPath = join(tmpdir(), `private.${p ? "encrypted" : "clear"}.pem`);
    writeFileSync(tmpPath, PEM);
    const output = execSync(`openssl pkey -in ${tmpPath} ${p ? ` -passin pass:${dPassword}` : ``} -text -noout`).toString("utf8");

    let priv = output.slice(output.indexOf("priv:") + 5, output.indexOf("pub:")).replace(clean, "");
    let pub = output.slice(output.indexOf("pub:") + 4).replace(clean, "");

    assert.deepStrictEqual(key, Buffer.from(priv, "hex"));
    assert.deepStrictEqual(dPublicKeys.uncompressed, Buffer.from(pub, "hex"));
    unlinkSync(tmpPath);
  };

  it("creates uncompressed public key / address", () => genKeys({ c: false }));

  it("creates compressed public key / address", () => genKeys({ c: true }));

  it("creates a clear-text PEM", () => genPEM());

  it("creates an encrypted PEM", () => genPEM({ p: dPassword }));
});
