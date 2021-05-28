import assert from "assert";
import bitcoinjs from "bitcoinjs-lib";
import wif from "wif";
import base58 from "bs58";
import { createPBKDF2Key } from "./utilities/deterministic.keygen.pbkdf2.js";
import { createPublicAddress } from "./utilities/bitcoin.address.from.hex.js";
import { clean } from "./utilities/utility.js";
import { caKeyPath, caCertTextPath, caCertPath, serverKeyPath, serverCSRPath, serverCertPath } from "./utilities/common.js";
import { writeFileSync, unlinkSync, fstat, writeFile } from "fs";
import { join } from "path";
import { tmpdir as ostmpdir } from "os";
import { execSync } from "child_process";

const tmpdir = () => process.env.DEV ? "./tmp" : ostmpdir();

import keymaster, {
  NID_X25519,
  NID_secp256k1,
  NID_X9_62_prime256v1,
  NID_ED25519,
  NID_Private,
  NID_X9_62_id_ecPublicKey,
  V_ASN1_BIT_STRING,
  PEM_TYPE_ENCRYPTED,
  PEM_TYPE_CLEAR,
  NID_x509Crl,
  NID_x509Certificate,
  NID_certBag,
  POINT_CONVERSION_UNCOMPRESSED,
  POINT_CONVERSION_COMPRESSED,
  NID_sha256,
} from "../dist/index.min.mjs";

const rootPrivateKey = createPBKDF2Key("SomeInput", "SomeSeed", 1);
const clientPrivateKey = createPBKDF2Key("SomeInput1", "SomeSeed1", 1);

let rootIssuerDN,
  clientNameDN,
  rootCertificate,
  certificateSigningRequest,
  signedClientCert,
  rootPrivateKeyPEM,
  rootPublicKey,
  clientPublicKey,
  clientPrivateKeyPEM;

const curve = NID_X9_62_prime256v1;

const rootArgs = {
  key: rootPrivateKey,
  curve,
  notBefore: -60 * 60,
  notAfter: 60 * 60 * 24 * 365.25 * 10,
  issuer: null,
  name: null,
  id: 1,
  keyUsage: {
    digitalSignature: false,
    nonRepudiation: false,
    keyEncipherment: false,
    dataEncipherment: false,
    keyAgreement: false,
    keyCertSign: true,
    cRLSign: true,
    encipherOnly: false,
    decipherOnly: false,
  },
  extKeyUsage: {
    serverAuth: false,
    clientAuth: false,
    codeSigning: false,
    emailProtection: false,
    timeStamping: false,
    OCSPSigning: false,
    ipsecIKE: false,
    msCodeInd: false,
    msCodeCom: false,
    msCTLSign: false,
    msEFS: false,
  },
  basicConstraints: { critical: true, CA: true, pathlen: 3 },
};

describe("public key and address from private key", function () {
  this.timeout(5000);

  beforeEach(async function () {
    this.Keymaster = new keymaster();
    await this.Keymaster.initialize();
  });
  it("creates a CA x509 certificate", async function () {
    let { Keymaster } = this;
    rootPublicKey = Keymaster.convertKey({
      key: rootPrivateKey,
      curve,
      outputtype: NID_X9_62_id_ecPublicKey,
      outformat: V_ASN1_BIT_STRING,
      compressed: POINT_CONVERSION_UNCOMPRESSED,
    });

    rootPrivateKeyPEM = Keymaster.convertKey({
      key: rootPrivateKey,
      curve,
      outputtype: NID_Private,
      outformat: PEM_TYPE_CLEAR,
      compressed: POINT_CONVERSION_UNCOMPRESSED,
    });

    writeFileSync(caKeyPath, rootPrivateKeyPEM);

    rootIssuerDN = `CN=AAAAAAAAAAA:${createPublicAddress(
      rootPublicKey
    )}`.slice(0, 34);
    rootCertificate = Keymaster.createCertificate({
      ...rootArgs,
      issuer: rootIssuerDN,
      name: rootIssuerDN,
    });

    writeFileSync(caCertPath, rootCertificate);
    const output = execSync(
      `openssl x509 -in ${caCertPath} -text -noout`
    ).toString("utf8");
    assert.deepStrictEqual(
      rootPublicKey,
      output
        .slice(output.indexOf("pub:\n") + 4, output.indexOf("ASN1 OID:"))
        .replace(clean, "")
    );
    if (!process.env.DEV) {
      unlinkSync(caCertPath);
    } else {
      console.log(output);
      writeFileSync(caCertTextPath, output);
    }
  });

  it("creates a CSR", async function () {
    let { Keymaster } = this;

    clientPublicKey = Keymaster.convertKey({
      key: clientPrivateKey,
      curve,
      outputtype: NID_X9_62_id_ecPublicKey,
      outformat: V_ASN1_BIT_STRING,
      compressed: POINT_CONVERSION_UNCOMPRESSED,
    });

    clientNameDN = `O=DIGITALARSENAL.IO, OU=BTC, OU=0, CN=PERSON, CN=localhost`;

    clientPrivateKeyPEM = Keymaster.convertKey({
      key: clientPrivateKey,
      curve,
      outputtype: NID_Private,
      outformat: PEM_TYPE_CLEAR
    });

    writeFileSync(serverKeyPath, clientPrivateKeyPEM);

    certificateSigningRequest = Keymaster.createCertificateSigningRequest({
      key: clientPrivateKey,
      curve,
      name: clientNameDN,
      id: "FF",
      keyUsage: {
        digitalSignature: true,
        nonRepudiation: false,
        keyEncipherment: false,
        dataEncipherment: false,
        keyAgreement: false,
        keyCertSign: true,
        cRLSign: true,
        encipherOnly: false,
        decipherOnly: false,
      },
      extKeyUsage: {
        serverAuth: false,
        clientAuth: true,
        codeSigning: true,
        emailProtection: false,
        timeStamping: true,
        OCSPSigning: false,
        ipsecIKE: false,
        msCodeInd: false,
        msCodeCom: false,
        msCTLSign: false,
        msEFS: false,
      },
      subjectAlternativeName: {
        URI: ["localhost"],
        DNS: ["localhost"],
        IP: ["10.10.10.1", "192.168.1.1"],
        email: ["info@digitalarsenal.io"],
      },
    });
    writeFileSync(serverCSRPath, certificateSigningRequest);
    const output = execSync(`openssl req -in ${serverCSRPath} -text -noout`).toString(
      "utf8"
    );
    assert.deepStrictEqual(
      clientPublicKey,
      output
        .slice(output.indexOf("pub:\n") + 4, output.indexOf("ASN1 OID:"))
        .replace(clean, "")
    );
    if (!process.env.DEV) {
      unlinkSync(serverCSRPath);
    }
  });

  it("creates a signed certificate from a signing request", async function () {
    let { Keymaster } = this;

    signedClientCert = Keymaster.createCertificate({
      key: clientPrivateKey,
      curve,
      subjectAlternativeName: {
        URI: ["localhost"],
        DNS: ["localhost"],
        IP: ["10.10.10.1", "192.168.1.1"],
        email: ["info@digitalarsenal.io"],
      },
      id: 1,
      notBefore: -60 * 60 * 24 * 365.25 * 5,
      notAfter: 0,
      issuer: rootIssuerDN,
      name: clientNameDN,
      certificateSigningRequest,
    });
    writeFileSync(serverCertPath, signedClientCert);
    const output = execSync(
      `openssl x509 -in ${serverCertPath} -text -noout`
    ).toString("utf8");
    assert.deepStrictEqual(
      clientPublicKey,
      output
        .slice(output.indexOf("pub:\n") + 4, output.indexOf("ASN1 OID:"))
        .replace(clean, "")
    );
    if (!process.env.DEV) {
      unlinkSync(serverCertPath);
    } else {
      console.log(output);
    }
  });

  /**
  let rootbagpassword = "rootbagpassword";
  let signedClientCertBag = Keymaster.createCertificate({
    caPEM: rootKeyPEM,
    caCertificate: rootCertificate,
    outformat: NID_certBag,
    certificateSigningRequest: certificateRequest,
    password: rootbagpassword,
    friendlyName: "certboBaggins",
  });

  const bagPathSigned = `./test/data/certBagSigned.p12`;
   */
});
