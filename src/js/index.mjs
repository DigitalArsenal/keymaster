globalThis.__dirname = "/";

import keymasterWASM from "../../dist/keymaster.wasm.js";

import {
  NID_secp256k1,
  NID_X9_62_prime256v1,
  NID_X9_62_id_ecPublicKey,
  POINT_CONVERSION_UNCOMPRESSED,
  POINT_CONVERSION_COMPRESSED,
  NID_basic_constraints,
  NID_key_usage,
  NID_ext_key_usage,
  NID_subject_key_identifier,
  NID_authority_key_identifier,
  NID_subject_alt_name,
  PEM_TYPE_ENCRYPTED,
  PEM_TYPE_CLEAR,
  NID_x509Crl,
  NID_x509Certificate,
  NID_certBag,
} from "../../lib/js/define.mjs";

export {
  POINT_CONVERSION_COMPRESSED,
  POINT_CONVERSION_UNCOMPRESSED,
  POINT_CONVERSION_HYBRID,
  NID_x509Crl,
  NID_x509Certificate,
  NID_certBag,
  V_ASN1_BIT_STRING,
  PEM_TYPE_ENCRYPTED,
  PEM_TYPE_CLEAR,
  NID_secp256k1,
  NID_X9_62_prime256v1,
  NID_X25519,
  NID_ED25519,
  NID_X9_62_id_ecPublicKey,
  NID_Private,
  NID_sha256,
  NID_basic_constraints,
  NID_key_usage,
  NID_ext_key_usage,
  NID_subject_key_identifier,
  NID_authority_key_identifier,
  NID_subject_alt_name,
} from "../../lib/js/define.mjs";

/**
 *
 * Class representing an keymaster instance.
 *
 */
class keymaster {
  mallocBufferAddresses = [];
  wasi = null;
  wasiBytes = null;
  instance = null;
  init = false;
  key = null;
  maxRead = 5096;

  /**
   * The key usage extension defines the purpose (e.g., encipherment,
   * signature, certificate signing) of the key contained in the
   * certificate.
   *
   * {@link https://tools.ietf.org/html/rfc5280#section-4.2.1.3}
   * @namespace
   * @property {Boolean} digitalSignature - Subject Public Key (SPK) is used for verifying digital signatures
   * @property {Boolean} nonRepudiation - SPK used to verify digital signatures
   * @property {Boolean} keyEncipherment - SPK used for enciphering private or secret keys
   * @property {Boolean} dataEncipherment - SPK used for enciphering raw user data w/o an intermediate symmetric cipher
   * @property {Boolean} keyAgreement - SPK used for key agreement, used with encipherOnly / decipherOnly
   * @property {Boolean} keyCertSign - SPK used for verifying signatures on public key certificates
   * @property {Boolean} cRLSign - SPK used for verifying signatures on certificate revocation lists
   * @property {Boolean} encipherOnly - If keyAgreement set, enciphering data while performing key agreement
   * @property {Boolean} decipherOnly - If keyAgreement set, deciphering data while performing key agreement
   */
  keyUsage = {
    digitalSignature: false,
    nonRepudiation: false,
    keyEncipherment: false,
    dataEncipherment: false,
    keyAgreement: false,
    keyCertSign: false,
    cRLSign: false,
    encipherOnly: false,
    decipherOnly: false,
  };

  /**
   * This extension indicates one or more purposes for which the certified
   * public key may be used, in addition to or in place of the basic
   * purposes indicated in the key usage extension
   *
   * {@link https://tools.ietf.org/html/rfc5280#section-4.2.1.12}
   * {@link https://tools.ietf.org/html/rfc6071#section-2.4}
   *
   * @namespace
   * @property {Boolean} serverAuth - TLS WWW server authentication
   * @property {Boolean} clientAuth - TLS WWW server authentication
   * @property {Boolean} codeSigning - Signing of downloadable executable code
   * @property {Boolean} emailProtection - Email protection
   * @property {Boolean} timeStamping - Binding the hash of an object to a time
   * @property {Boolean} OCSPSigning - Signing OCSP responses
   * @property {Boolean} ipsecIKE - Used for IP Security (IPsec) and Internet Key Exchange (IKE)
   * @property {Boolean} msCodeInd - Microsoft Individual Code Signing (authenticode)
   * @property {Boolean} msCodeCom - Microsoft Commercial Code Signing (authenticode)
   * @property {Boolean} msCTLSign - Microsoft Trust List Signing
   * @property {Boolean} msEFS - Microsoft Encrypting File System
   */
  extKeyUsage = {
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
  };

  /**
   * The subject alternative name extension allows identities to be bound
   * to the subject of the certificate.
   *
   * {@link https://tools.ietf.org/html/rfc5280#section-4.2.1.6}
   */
  subjectAlternativeName = {
    URI: [],
    DNS: [],
    IP: [],
    email: [],
  };

  /**
   * Create a keymaster instance.
   */
  constructor() { }

  /**
   * Initialize the keymaster instance.
   * Compiles the core WebAssembly System Interface (WASI) compliant WebAssembly binary.
   *
   * @async
   * @function initialize
   * @return {undefined}
   */
  async initialize() {
    if (!this.init) {
      if (ENVIRONMENT_IS_NODE) {
        ["fs", "path", "crypto"].forEach(async (t) => {
          globalThis[t] = await import(t);
        });
      }
      this.instance = keymasterWASM;
      this.instance = (
        await keymasterWASM({
          memory: new WebAssembly.Memory({
            initial: 10000,
            maximum: 65536,
          }),
        })
      ).asm;

      this.init = true;
    }
  }

  /**
   * Creates the Key Usage comma-separated string from an object of NID parameters.
   *
   * @function calcKeyUsage
   * @param {object} KU - Object with NID as parameters.
   * @return {string} The comma-separated list of NIDs
   */
  calcKeyUsage = (KU) =>
    Object.entries(KU)
      .filter((kU) => kU[1])
      .map((kU) => kU[0])
      .join(",");

  /**
   * Memory management for buffers
   *
   * @function cleanupReferences
   * @return {undefined}
   */
  cleanupReferences() {
    let { destroyBuffer, cleanup } = this.instance;
    while (this.mallocBufferAddresses.length) {
      destroyBuffer(this.mallocBufferAddresses.pop());
    }
    cleanup();
  }

  /**
   * Read UTF8 string from WASM memory location
   *
   * @function writeString
   * @param {number} memloc - Memory offset pointer
   * @return {string} UTF8 string
   */
  readString(memloc) {
    let { maxRead } = this,
      _pstr = [],
      _char;
    let pview = new Uint8Array(this.instance.memory.buffer, memloc, maxRead);
    while ((_char = pview[_pstr.length]) && _pstr.length < maxRead) _pstr.push(_char);
    let result = new TextDecoder().decode(new Uint8Array(_pstr));
    if (result.match(/[0-9a-fA-F]{2}:/) && result.match(/:/g).length > result.length / 4) {
      result = result.replace(/:/g, "");
    }
    return result;
  }

  /**
   * Write UTF8 string to WASM memory location
   *
   * @function writeString
   * @param {string} str - String to write to memory location
   * @return {number} Memory offset pointer
   */
  writeString(str) {
    if (!str) return 0;
    let { createBuffer, memory } = this.instance;

    if (typeof str !== "string") {
      str = str.toString(str instanceof Buffer ? "hex" : 16);
    }

    const strBuf = new TextEncoder().encode(str + "\0");
    let offset = createBuffer(strBuf.length);
    this.mallocBufferAddresses.push(offset);
    const outBuf = new Uint8Array(memory.buffer, offset, strBuf.length);
    for (let i = 0; i < strBuf.length; i++) {
      outBuf[i] = strBuf[i];
    }
    return offset;
  }

  /**
   * Write an array of 32-bit unsigned integers to WASM memory location
   *
   * @function writeUint32Array
   * @param {Uint32Array} uint32Array - array of 32-bit unsigned integers to write to wasm memory
   * @return {number} Memory offset pointer
   */
  writeUint32Array(uint32Array) {
    uint32Array.push(0);
    let { createBuffer, memory } = this.instance;
    let offset = createBuffer(4 * uint32Array.length);
    this.mallocBufferAddresses.push(offset);
    new Uint32Array(memory.buffer, offset, uint32Array.length).set(Uint32Array.from(uint32Array));

    return offset;
  }

  /**
   * Load key from Buffer
   *
   * @function loadKey
   * @param {buffer|arrayBuffer|string|string[]|Object} [key=buffer] - Buffer to load
   * @return {number} Memory offset pointer
   */
  loadKey(key = Buffer.from([])) {
    if (!(key instanceof Buffer)) {
      key = Buffer.from(key);
    }
    this.key = key;
  }

  /**
   * The keyHex property is the current key in hexidecimal
   *
   * @type {string}
   * @return {string} Current key in hexidecimal
   */
  get keyHex() {
    return this.key ? this.key.toString("hex") : null;
  }

  /**
   * Convert key to serialization format
   *
   * @function convertKey
   * @param {Object} settings - The configuration object to tell OpenSSL how to format the key
   * @param {buffer|arrayBuffer|string|string[]|Object} [settings.key=null] - Key, default is current instance key. If not null, replaces key.
   * @param {number} [settings.curve=NID_secp256k1] - Numerical ID (NID) for the Elliptic Curve (EC) to use
   * @param {number} [settings.outputtype=NID_X9_62_id_ecPublicKey] - NID for OpenSSL output type
   * @param {number} [settings.outformat=V_ASN1_BIT_STRING] - NID for OpenSSL output format
   * @param {number} [settings.compressed=POINT_CONVERSION_UNCOMPRESSED] - Which X9.62 (ECDSA) form, for encoding an EC point
   * @param {string} [settings.password=null] - Password to use
   * @return {string} String representation of formatted key
   */
  convertKey({
    key = null,
    curve = NID_secp256k1,
    outputtype = NID_X9_62_id_ecPublicKey,
    outformat = V_ASN1_BIT_STRING,
    compressed = POINT_CONVERSION_UNCOMPRESSED,
    password = null,
  }) {
    if (key) {
      this.key = key;
    }
    if (!this.init) throw Error("Not initialized; call .initialize() on instance.");
    let { keyHex } = this;
    let writeoffset = this.writeString(keyHex);
    let memorylocation = this.instance.convertKey(curve, writeoffset, outputtype, outformat, compressed, this.writeString(password));
    let pstring = this.readString(memorylocation);
    this.cleanupReferences();
    return pstring;
  }

  /**
   * Create a certificate
   *
   * @function createCertificate
   * @param {Object} settings - The configuration object to tell OpenSSL how to format the key
   * @param {buffer|arrayBuffer|string|string[]|Object} [settings.key=null] - Key, default is current instance key. If not null, replaces key.
   * @param {number} [settings.curve=NID_secp256k1] - Numerical ID (NID) for the Elliptic Curve (EC) to use
   * @param {number} [settings.compressed=POINT_CONVERSION_UNCOMPRESSED] - Which X9.62 (ECDSA) form, for encoding an EC point
   * @param {string} [settings.password=null] - Password to use
   * @param {number} [settings.notBefore=0] - Certificate validity start in seconds from current system time
   * @param {number} [settings.notAfter=31536000] - Certificate validity stop in seconds from current system time
   * @param {number} [settings.version=2] - Certificate version (actual version is 1 less than number)
   * @param {string} [settings.issuer=C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=ISSUER] - Certificate issuer csv Distinguished Name (DN) string
   * @param {string} [settings.name=C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=NAME] - Certificate name csv Distinguished Name (DN) string
   * @param {number} [settings.id=0] - Certificate ID number
   * @param {Object} settings.basicConstraints - Basic constraints on this certificate
   * @param {Boolean} settings.basicConstraints.CA - The subject of the cert is a CA
   * @param {number} settings.basicConstraints.pathlen -  The max depth of valid cert paths that include cert
   * @param {Object|string} [settings.keyUsage=this.keyUsage] - Key usage extensions.
   * @param {Object|string} [settings.extKeyUsage=this.extKeyUsage] - Extended Key usage extensions.
   * @param {Object} [settings.subjectAlternativeName] - Object with properties enumerating SAN (additional host names) for certificate
   * @param {string} [settings.subjectKeyIdentifier=hash"] - Either hash per {@link https://tools.ietf.org/html/rfc3280#section-4.2.1.2} or a hex string (strongly discouraged).
   * @param {string} [settings.authorityKeyIdentifier=keyid:always] - {@link https://www.openssl.org/docs/man1.0.2/man5/x509v3_config.html} Can be either 'keyid', 'issuer', or both, each with optional value 'always'
   * @param {string} [settings.friendlyName=null] - Friendly Name for Microsoft .p12
   * @param {string} [settings.certificateSigningRequest=null] - CSR as a string
   * @param {number} [settings.outformat=NID_x509Certificate] - NID for the output format
   * @param {number} [settings.caPEM=null] - PEM of Certificate Authority for signing
   * @param {number} [settings.caCertificate=null] - CA Certificate
   * @return {string} String representation of certificate
   */
  createCertificate({
    key = null,
    curve = null,
    compressed = POINT_CONVERSION_UNCOMPRESSED,
    password = null,
    notBefore = 0,
    notAfter = 31536000,
    version = 2,
    issuer = "C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=ISSUER",
    name = "C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=NAME",
    id = 0,
    basicConstraints = { CA: false, pathlen: 0 },
    keyUsage = this.keyUsage,
    extKeyUsage = this.extKeyUsage,
    subjectAlternativeName = this.subjectAlternativeName,
    subjectKeyIdentifier = "hash",
    authorityKeyIdentifier = "keyid:always",
    friendlyName = null,
    certificateSigningRequest = null,
    outformat = NID_x509Certificate,
    caPEM = null,
    caCertificate = null,
  }) {
    this.key = key;

    id = parseInt(id).toString();

    let { keyHex, calcKeyUsage } = this;

    let _pathlen = basicConstraints.CA ? `,pathlen:${Math.abs(parseInt(basicConstraints.pathlen) || 0)}` : "";

    let _san = [];

    for (let ext in subjectAlternativeName) {
      let sE = subjectAlternativeName[ext];
      if (sE instanceof Array && sE.length) {
        sE.forEach((a) => {
          _san.push(`${ext}:${a}`);
        });
      }
    }

    let extensions = new Map([
      [NID_basic_constraints, `critical,${basicConstraints.CA ? "CA:TRUE" : "CA:FALSE"}${_pathlen}`],
      [NID_key_usage, typeof keyUsage === "string" ? keyUsage : calcKeyUsage(keyUsage)],
      [NID_ext_key_usage, typeof extKeyUsage === "string" ? extKeyUsage : calcKeyUsage(extKeyUsage)],
      [NID_subject_key_identifier, subjectKeyIdentifier],
      [NID_authority_key_identifier, authorityKeyIdentifier],
      [NID_subject_alt_name, _san.join(",")],
    ]);

    let memLocCert = this.instance.createCertificate(
      curve,
      compressed,
      this.writeString(password),
      notBefore,
      notAfter,
      version,
      ...[keyHex, name, issuer, id, friendlyName, certificateSigningRequest].map((a) => this.writeString(a)),
      this.writeUint32Array([...extensions.entries()].filter((a) => a[1].length).map((a) => [a[0], this.writeString(a[1])]).flat()),
      outformat,
      ...[caPEM, caCertificate].map((a) => this.writeString(a))
    );

    let certString = this.readString(memLocCert);
    this.cleanupReferences();
    return certString;
  }

  /**
   * Create a certificate signing request
   *
   * @function createCertificateSigningRequest
   * @param {Object} settings - The configuration object to tell OpenSSL how to format the key
   * @param {buffer|arrayBuffer|string|string[]|Object} [settings.key=null] - Key, default is current instance key. If not null, replaces key.
   * @param {number} [settings.curve=NID_secp256k1] - Numerical ID (NID) for the Elliptic Curve (EC) to use
   * @param {number} [settings.compressed=POINT_CONVERSION_UNCOMPRESSED] - Which X9.62 (ECDSA) form, for encoding an EC point
   * @param {string} [settings.password=null] - Password to use
   * @param {number} [settings.version=2] - Certificate version (actual version is 1 less than number)
   * @param {string} [settings.name=C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=NAME] - Certificate name csv Distinguished Name (DN) string
   * @param {number} [settings.id=0] - Certificate ID number
   * @param {Object} settings.basicConstraints - Basic constraints on this certificate
   * @param {Object|string} [settings.keyUsage=this.keyUsage] - Key usage extensions.
   * @param {Object|string} [settings.extKeyUsage=this.extKeyUsage] - Extended Key usage extensions.
   * @param {Object} [settings.subjectAlternativeName] - Object with properties enumerating SAN (additional host names) for certificate
   * @param {string} [settings.subjectKeyIdentifier=hash] - Either hash per {@link https://tools.ietf.org/html/rfc3280#section-4.2.1.2} or a hex string (strongly discouraged).
   * @return {string} String representation of certificate
   */
  createCertificateSigningRequest({
    key = null,
    curve = NID_secp256k1,
    compressed = POINT_CONVERSION_UNCOMPRESSED,
    password = null,
    version = 2,
    name = "C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=DEFAULT",
    id = "0",
    basicConstraints = { CA: false, pathlen: 0 },
    keyUsage = this.keyUsage,
    extKeyUsage = this.extKeyUsage,
    subjectAlternativeName = this.subjectAlternativeName,
    subjectKeyIdentifier = "hash",
  }) {
    if (key) {
      this.key = key;
    }
    let { keyHex, calcKeyUsage } = this;

    let _pathlen = basicConstraints.CA ? `,pathlen:${Math.abs(parseInt(basicConstraints.pathlen) || 0)}` : "";

    let _san = [];

    for (let ext in subjectAlternativeName) {
      let sE = subjectAlternativeName[ext];
      if (sE instanceof Array && sE.length) {
        sE.forEach((a) => {
          _san.push(`${ext}:${a}`);
        });
      }
    }

    let extensions = new Map([
      [NID_basic_constraints, `critical,${basicConstraints.CA ? "CA:TRUE" : "CA:FALSE"}${_pathlen}`],
      [NID_key_usage, typeof keyUsage === "string" ? keyUsage : calcKeyUsage(keyUsage)],
      [NID_ext_key_usage, typeof extKeyUsage === "string" ? extKeyUsage : calcKeyUsage(extKeyUsage)],
      [NID_subject_key_identifier, subjectKeyIdentifier],
      [NID_subject_alt_name, _san.join(",")],
    ]);

    let memLocCSR = this.instance.createCertificateSigningRequest(
      curve,
      compressed,
      this.writeString(password),
      version,
      ...[keyHex, name, id].map((a) => this.writeString(a)),
      this.writeUint32Array([...extensions.entries()].map((a) => [a[0], this.writeString(a[1])]).flat())
    );

    let certRequest = this.readString(memLocCSR);

    this.cleanupReferences();

    return certRequest;
  }

  /**
   * Range Check Private Key
   *
   * @function validPrivateKey
   * @static
   * @param {buffer|arrayBuffer|string|string[]|Object} privateKey - Private Key to compare
   * @param {string} [min=0] - Minimum value as a hex string
   * @param {string} [max=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140] - Maximum value as a hex string
   * @return {Boolean}
   */
  static validPrivateKey(privateKey, min = "0", max = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140") {
    if (!(privateKey instanceof Buffer)) {
      privateKey = Buffer.from(privateKey);
    }
    max = Buffer.from(max, "hex");
    min = Buffer.from(min, "hex");
    return Buffer.compare(max, privateKey) === 1 && Buffer.compare(privateKey, min) === 1;
  }
}

export default keymaster;
