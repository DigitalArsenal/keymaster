export default keymaster;
/**
 *
 * Class representing an keymaster instance.
 *
 */
declare class keymaster {
    /**
     * Range Check Private Key
     *
     * @function validPrivateKey
     * @static
     * @param {buffer|arrayBuffer|string|string[]|Object} privateKey - Private Key to compare
     * @param {string} [min="0"] - Minimum value as a hex string
     * @param {string} [max="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"] - Maximum value as a hex string
     * @return {Boolean}
     */
    static validPrivateKey(privateKey: any | any | string | string[] | any, min?: string, max?: string): boolean;
    mallocBufferAddresses: any[];
    wasi: any;
    wasiBytes: any;
    instance: any;
    init: boolean;
    key: any;
    maxRead: number;
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
    keyUsage: {
        digitalSignature: boolean;
        nonRepudiation: boolean;
        keyEncipherment: boolean;
        dataEncipherment: boolean;
        keyAgreement: boolean;
        keyCertSign: boolean;
        cRLSign: boolean;
        encipherOnly: boolean;
        decipherOnly: boolean;
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
    extKeyUsage: {
        serverAuth: boolean;
        clientAuth: boolean;
        codeSigning: boolean;
        emailProtection: boolean;
        timeStamping: boolean;
        OCSPSigning: boolean;
        ipsecIKE: boolean;
        msCodeInd: boolean;
        msCodeCom: boolean;
        msCTLSign: boolean;
        msEFS: boolean;
    };
    /**
     * The subject alternative name extension allows identities to be bound
     * to the subject of the certificate.
     *
     * {@link https://tools.ietf.org/html/rfc5280#section-4.2.1.6}
     */
    subjectAlternativeName: {
        URI: any[];
        DNS: any[];
        IP: any[];
        email: any[];
    };
    /**
     * Initialize the keymaster instance.
     * Compiles the core WebAssembly System Interface (WASI) compliant WebAssembly binary.
     *
     * @async
     * @function initialize
     * @return {undefined}
     */
    initialize(): undefined;
    /**
     * Creates the Key Usage comma-separated string from an object of NID parameters.
     *
     * @function calcKeyUsage
     * @param {object} KU - Object with NID as parameters.
     * @return {string} The comma-separated list of NIDs
     */
    calcKeyUsage: (KU: object) => string;
    /**
     * Memory management for buffers
     *
     * @function cleanupReferences
     * @return {undefined}
     */
    cleanupReferences(): undefined;
    /**
     * Read UTF8 string from WASM memory location
     *
     * @function writeString
     * @param {number} memloc - Memory offset pointer
     * @return {string} UTF8 string
     */
    readString(memloc: number): string;
    /**
     * Write UTF8 string to WASM memory location
     *
     * @function writeString
     * @param {string} str - String to write to memory location
     * @return {number} Memory offset pointer
     */
    writeString(str: string): number;
    /**
     * Write an array of 32-bit unsigned integers to WASM memory location
     *
     * @function writeUint32Array
     * @param {Uint32Array} uint32Array - array of 32-bit unsigned integers to write to wasm memory
     * @return {number} Memory offset pointer
     */
    writeUint32Array(uint32Array: Uint32Array): number;
    /**
     * Load key from Buffer
     *
     * @function loadKey
     * @param {buffer|arrayBuffer|string|string[]|Object} [key=buffer] - Buffer to load
     * @return {number} Memory offset pointer
     */
    loadKey(key?: any | any | string | string[] | any): number;
    /**
     * The keyHex property is the current key in hexidecimal
     *
     * @type {string}
     * @return {string} Current key in hexidecimal
     */
    get keyHex(): string;
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
    convertKey({ key, curve, outputtype, outformat, compressed, password, }: {
        key: any | any | string | string[] | any;
        curve: number;
        outputtype: number;
        outformat: number;
        compressed: number;
        password: string;
    }): string;
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
     * @param {string} [settings.issuer="C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=ISSUER"] - Certificate issuer csv Distinguished Name (DN) string
     * @param {string} [settings.name="C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=NAME"] - Certificate name csv Distinguished Name (DN) string
     * @param {number} [settings.id=0] - Certificate ID number
     * @param {Object} settings.basicConstraints - Basic constraints on this certificate
     * @param {Boolean} settings.basicConstraints.CA - The subject of the cert is a CA
     * @param {number} settings.basicConstraints.pathlen -  The max depth of valid cert paths that include cert
     * @param {Object|string} [settings.keyUsage=this.keyUsage] - Key usage extensions.
     * @param {Object|string} [settings.extKeyUsage=this.extKeyUsage] - Extended Key usage extensions.
     * @param {Object} [settings.subjectAlternativeName] - Object with properties enumerating SAN (additional host names) for certificate
     * @param {string} [settings.subjectKeyIdentifier="hash"] - Either hash per {@link https://tools.ietf.org/html/rfc3280#section-4.2.1.2} or a hex string (strongly discouraged).
     * @param {string} [settings.authorityKeyIdentifier="keyid:always"] - {@link https://www.openssl.org/docs/man1.0.2/man5/x509v3_config.html} Can be either 'keyid', 'issuer', or both, each with optional value 'always'
     * @param {string} [settings.friendlyName=null] - Friendly Name for Microsoft .p12
     * @param {string} [settings.certificateSigningRequest=null] - CSR as a string
     * @param {number} [settings.outformat=NID_x509Certificate] - NID for the output format
     * @param {number} [settings.caPEM=null] - PEM of Certificate Authority for signing
     * @param {number} [settings.caCertificate=null] - CA Certificate
     * @return {string} String representation of certificate
     */
    createCertificate({ key, curve, compressed, password, notBefore, notAfter, version, issuer, name, id, basicConstraints, keyUsage, extKeyUsage, subjectAlternativeName, subjectKeyIdentifier, authorityKeyIdentifier, friendlyName, certificateSigningRequest, outformat, caPEM, caCertificate, }: {
        key: any | any | string | string[] | any;
        curve: number;
        compressed: number;
        password: string;
        notBefore: number;
        notAfter: number;
        version: number;
        issuer: string;
        name: string;
        id: number;
        basicConstraints: {
            CA: boolean;
            pathlen: number;
        };
        keyUsage: any | string;
        extKeyUsage: any | string;
        subjectAlternativeName: any;
        subjectKeyIdentifier: string;
        authorityKeyIdentifier: string;
        friendlyName: string;
        certificateSigningRequest: string;
        outformat: number;
        caPEM: number;
        caCertificate: number;
    }): string;
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
     * @param {string} [settings.name="C=US, ST=VA, L=DZM, O=MyOrg, OU=dev, CN=NAME"] - Certificate name csv Distinguished Name (DN) string
     * @param {number} [settings.id=0] - Certificate ID number
     * @param {Object} settings.basicConstraints - Basic constraints on this certificate
     * @param {Object|string} [settings.keyUsage=this.keyUsage] - Key usage extensions.
     * @param {Object|string} [settings.extKeyUsage=this.extKeyUsage] - Extended Key usage extensions.
     * @param {Object} [settings.subjectAlternativeName] - Object with properties enumerating SAN (additional host names) for certificate
     * @param {string} [settings.subjectKeyIdentifier="hash"] - Either hash per {@link https://tools.ietf.org/html/rfc3280#section-4.2.1.2} or a hex string (strongly discouraged).
     * @return {string} String representation of certificate
     */
    createCertificateSigningRequest({ key, curve, compressed, password, version, name, id, basicConstraints, keyUsage, extKeyUsage, subjectAlternativeName, subjectKeyIdentifier, }: {
        key: any | any | string | string[] | any;
        curve: number;
        compressed: number;
        password: string;
        version: number;
        name: string;
        id: number;
        basicConstraints: any;
        keyUsage: any | string;
        extKeyUsage: any | string;
        subjectAlternativeName: any;
        subjectKeyIdentifier: string;
    }): string;
}
