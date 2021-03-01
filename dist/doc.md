## Classes

<dl>
<dt><a href="#keymaster">keymaster</a></dt>
<dd><p>Class representing an keymaster instance.</p>
</dd>
</dl>

## Functions

<dl>
<dt><a href="#initialize">initialize()</a> ⇒ <code>undefined</code></dt>
<dd><p>Initialize the keymaster instance.
Compiles the core WebAssembly System Interface (WASI) compliant WebAssembly binary.</p>
</dd>
<dt><a href="#calcKeyUsage">calcKeyUsage(KU)</a> ⇒ <code>string</code></dt>
<dd><p>Creates the Key Usage comma-separated string from an object of NID parameters.</p>
</dd>
<dt><a href="#cleanupReferences">cleanupReferences()</a> ⇒ <code>undefined</code></dt>
<dd><p>Memory management for buffers</p>
</dd>
<dt><a href="#writeString">writeString(memloc)</a> ⇒ <code>string</code></dt>
<dd><p>Read UTF8 string from WASM memory location</p>
</dd>
<dt><a href="#writeString">writeString(str)</a> ⇒ <code>number</code></dt>
<dd><p>Write UTF8 string to WASM memory location</p>
</dd>
<dt><a href="#writeUint32Array">writeUint32Array(uint32Array)</a> ⇒ <code>number</code></dt>
<dd><p>Write an array of 32-bit unsigned integers to WASM memory location</p>
</dd>
<dt><a href="#loadKey">loadKey([key])</a> ⇒ <code>number</code></dt>
<dd><p>Load key from Buffer</p>
</dd>
<dt><a href="#convertKey">convertKey(settings)</a> ⇒ <code>string</code></dt>
<dd><p>Convert key to serialization format</p>
</dd>
<dt><a href="#createCertificate">createCertificate(settings)</a> ⇒ <code>string</code></dt>
<dd><p>Create a certificate</p>
</dd>
<dt><a href="#createCertificateSigningRequest">createCertificateSigningRequest(settings)</a> ⇒ <code>string</code></dt>
<dd><p>Create a certificate signing request</p>
</dd>
</dl>

<a name="keymaster"></a>

## keymaster
Class representing an keymaster instance.

**Kind**: global class  

* [keymaster](#keymaster)
    * [new keymaster()](#new_keymaster_new)
    * [.subjectAlternativeName](#keymaster+subjectAlternativeName)
    * [.keyHex](#keymaster+keyHex) ⇒ <code>string</code>
    * [.keyUsage](#keymaster+keyUsage) : <code>object</code>
    * [.extKeyUsage](#keymaster+extKeyUsage) : <code>object</code>

<a name="new_keymaster_new"></a>

### new keymaster()
Create a keymaster instance.

<a name="keymaster+subjectAlternativeName"></a>

### keymaster.subjectAlternativeName
The subject alternative name extension allows identities to be bound
to the subject of the certificate.

[https://tools.ietf.org/html/rfc5280#section-4.2.1.6](https://tools.ietf.org/html/rfc5280#section-4.2.1.6)

**Kind**: instance property of [<code>keymaster</code>](#keymaster)  
<a name="keymaster+keyHex"></a>

### keymaster.keyHex ⇒ <code>string</code>
The keyHex property is the current key in hexidecimal

**Kind**: instance property of [<code>keymaster</code>](#keymaster)  
**Returns**: <code>string</code> - Current key in hexidecimal  
<a name="keymaster+keyUsage"></a>

### keymaster.keyUsage : <code>object</code>
The key usage extension defines the purpose (e.g., encipherment,
signature, certificate signing) of the key contained in the
certificate.

[https://tools.ietf.org/html/rfc5280#section-4.2.1.3](https://tools.ietf.org/html/rfc5280#section-4.2.1.3)

**Kind**: instance namespace of [<code>keymaster</code>](#keymaster)  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| digitalSignature | <code>Boolean</code> | Subject Public Key (SPK) is used for verifying digital signatures |
| nonRepudiation | <code>Boolean</code> | SPK used to verify digital signatures |
| keyEncipherment | <code>Boolean</code> | SPK used for enciphering private or secret keys |
| dataEncipherment | <code>Boolean</code> | SPK used for enciphering raw user data w/o an intermediate symmetric cipher |
| keyAgreement | <code>Boolean</code> | SPK used for key agreement, used with encipherOnly / decipherOnly |
| keyCertSign | <code>Boolean</code> | SPK used for verifying signatures on public key certificates |
| cRLSign | <code>Boolean</code> | SPK used for verifying signatures on certificate revocation lists |
| encipherOnly | <code>Boolean</code> | If keyAgreement set, enciphering data while performing key agreement |
| decipherOnly | <code>Boolean</code> | If keyAgreement set, deciphering data while performing key agreement |

<a name="keymaster+extKeyUsage"></a>

### keymaster.extKeyUsage : <code>object</code>
This extension indicates one or more purposes for which the certified
public key may be used, in addition to or in place of the basic
purposes indicated in the key usage extension

[https://tools.ietf.org/html/rfc5280#section-4.2.1.12](https://tools.ietf.org/html/rfc5280#section-4.2.1.12)
[https://tools.ietf.org/html/rfc6071#section-2.4](https://tools.ietf.org/html/rfc6071#section-2.4)

**Kind**: instance namespace of [<code>keymaster</code>](#keymaster)  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| serverAuth | <code>Boolean</code> | TLS WWW server authentication |
| clientAuth | <code>Boolean</code> | TLS WWW server authentication |
| codeSigning | <code>Boolean</code> | Signing of downloadable executable code |
| emailProtection | <code>Boolean</code> | Email protection |
| timeStamping | <code>Boolean</code> | Binding the hash of an object to a time |
| OCSPSigning | <code>Boolean</code> | Signing OCSP responses |
| ipsecIKE | <code>Boolean</code> | Used for IP Security (IPsec) and Internet Key Exchange (IKE) |
| msCodeInd | <code>Boolean</code> | Microsoft Individual Code Signing (authenticode) |
| msCodeCom | <code>Boolean</code> | Microsoft Commercial Code Signing (authenticode) |
| msCTLSign | <code>Boolean</code> | Microsoft Trust List Signing |
| msEFS | <code>Boolean</code> | Microsoft Encrypting File System |

<a name="initialize"></a>

## initialize() ⇒ <code>undefined</code>
Initialize the keymaster instance.
Compiles the core WebAssembly System Interface (WASI) compliant WebAssembly binary.

**Kind**: global function  
<a name="calcKeyUsage"></a>

## calcKeyUsage(KU) ⇒ <code>string</code>
Creates the Key Usage comma-separated string from an object of NID parameters.

**Kind**: global function  
**Returns**: <code>string</code> - The comma-separated list of NIDs  

| Param | Type | Description |
| --- | --- | --- |
| KU | <code>object</code> | Object with NID as parameters. |

<a name="cleanupReferences"></a>

## cleanupReferences() ⇒ <code>undefined</code>
Memory management for buffers

**Kind**: global function  
<a name="writeString"></a>

## writeString(memloc) ⇒ <code>string</code>
Read UTF8 string from WASM memory location

**Kind**: global function  
**Returns**: <code>string</code> - UTF8 string  

| Param | Type | Description |
| --- | --- | --- |
| memloc | <code>number</code> | Memory offset pointer |

<a name="writeString"></a>

## writeString(str) ⇒ <code>number</code>
Write UTF8 string to WASM memory location

**Kind**: global function  
**Returns**: <code>number</code> - Memory offset pointer  

| Param | Type | Description |
| --- | --- | --- |
| str | <code>string</code> | String to write to memory location |

<a name="writeUint32Array"></a>

## writeUint32Array(uint32Array) ⇒ <code>number</code>
Write an array of 32-bit unsigned integers to WASM memory location

**Kind**: global function  
**Returns**: <code>number</code> - Memory offset pointer  

| Param | Type | Description |
| --- | --- | --- |
| uint32Array | <code>Uint32Array</code> | array of 32-bit unsigned integers to write to wasm memory |

<a name="loadKey"></a>

## loadKey([key]) ⇒ <code>number</code>
Load key from Buffer

**Kind**: global function  
**Returns**: <code>number</code> - Memory offset pointer  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [key] | <code>buffer</code> \| <code>arrayBuffer</code> \| <code>string</code> \| <code>Array.&lt;string&gt;</code> \| <code>Object</code> | <code>buffer</code> | Buffer to load |

<a name="convertKey"></a>

## convertKey(settings) ⇒ <code>string</code>
Convert key to serialization format

**Kind**: global function  
**Returns**: <code>string</code> - String representation of formatted key  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| settings | <code>Object</code> |  | The configuration object to tell OpenSSL how to format the key |
| [settings.key] | <code>buffer</code> \| <code>arrayBuffer</code> \| <code>string</code> \| <code>Array.&lt;string&gt;</code> \| <code>Object</code> | <code></code> | Key, default is current instance key. If not null, replaces key. |
| [settings.curve] | <code>number</code> | <code>NID_secp256k1</code> | Numerical ID (NID) for the Elliptic Curve (EC) to use |
| [settings.outputtype] | <code>number</code> | <code>NID_X9_62_id_ecPublicKey</code> | NID for OpenSSL output type |
| [settings.outformat] | <code>number</code> | <code>V_ASN1_BIT_STRING</code> | NID for OpenSSL output format |
| [settings.compressed] | <code>number</code> | <code>POINT_CONVERSION_UNCOMPRESSED</code> | Which X9.62 (ECDSA) form, for encoding an EC point |
| [settings.password] | <code>string</code> | <code>null</code> | Password to use |

<a name="createCertificate"></a>

## createCertificate(settings) ⇒ <code>string</code>
Create a certificate

**Kind**: global function  
**Returns**: <code>string</code> - String representation of certificate  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| settings | <code>Object</code> |  | The configuration object to tell OpenSSL how to format the key |
| [settings.key] | <code>buffer</code> \| <code>arrayBuffer</code> \| <code>string</code> \| <code>Array.&lt;string&gt;</code> \| <code>Object</code> | <code></code> | Key, default is current instance key. If not null, replaces key. |
| [settings.curve] | <code>number</code> | <code>NID_secp256k1</code> | Numerical ID (NID) for the Elliptic Curve (EC) to use |
| [settings.compressed] | <code>number</code> | <code>POINT_CONVERSION_UNCOMPRESSED</code> | Which X9.62 (ECDSA) form, for encoding an EC point |
| [settings.password] | <code>string</code> | <code>null</code> | Password to use |
| [settings.notBefore] | <code>number</code> | <code>0</code> | Certificate validity start in seconds from current system time |
| [settings.notAfter] | <code>number</code> | <code>31536000</code> | Certificate validity stop in seconds from current system time |
| [settings.version] | <code>number</code> | <code>2</code> | Certificate version (actual version is 1 less than number) |
| [settings.issuer] | <code>string</code> | <code>&quot;\&quot;C&#x3D;US, ST&#x3D;VA, L&#x3D;DZM, O&#x3D;MyOrg, OU&#x3D;dev, CN&#x3D;ISSUER\&quot;&quot;</code> | Certificate issuer csv Distinguished Name (DN) string |
| [settings.name] | <code>string</code> | <code>&quot;\&quot;C&#x3D;US, ST&#x3D;VA, L&#x3D;DZM, O&#x3D;MyOrg, OU&#x3D;dev, CN&#x3D;NAME\&quot;&quot;</code> | Certificate name csv Distinguished Name (DN) string |
| [settings.id] | <code>number</code> | <code>0</code> | Certificate ID number |
| settings.basicConstraints | <code>Object</code> |  | Basic constraints on this certificate |
| settings.basicConstraints.CA | <code>Boolean</code> |  | The subject of the cert is a CA |
| settings.basicConstraints.pathlen | <code>number</code> |  | The max depth of valid cert paths that include cert |
| [settings.keyUsage] | <code>Object</code> \| <code>string</code> | <code>this.keyUsage</code> | Key usage extensions. |
| [settings.extKeyUsage] | <code>Object</code> \| <code>string</code> | <code>this.extKeyUsage</code> | Extended Key usage extensions. |
| [settings.subjectAlternativeName] | <code>Object</code> |  | Object with properties enumerating SAN (additional host names) for certificate |
| [settings.subjectKeyIdentifier] | <code>string</code> | <code>&quot;\&quot;hash\&quot;&quot;</code> | Either hash per [https://tools.ietf.org/html/rfc3280#section-4.2.1.2](https://tools.ietf.org/html/rfc3280#section-4.2.1.2) or a hex string (strongly discouraged). |
| [settings.authorityKeyIdentifier] | <code>string</code> | <code>&quot;\&quot;keyid:always\&quot;&quot;</code> | [https://www.openssl.org/docs/man1.0.2/man5/x509v3_config.html](https://www.openssl.org/docs/man1.0.2/man5/x509v3_config.html) Can be either 'keyid', 'issuer', or both, each with optional value 'always' |
| [settings.friendlyName] | <code>string</code> | <code>null</code> | Friendly Name for Microsoft .p12 |
| [settings.certificateSigningRequest] | <code>string</code> | <code>null</code> | CSR as a string |
| [settings.outformat] | <code>number</code> | <code>NID_x509Certificate</code> | NID for the output format |
| [settings.caPEM] | <code>number</code> | <code></code> | PEM of Certificate Authority for signing |
| [settings.caCertificate] | <code>number</code> | <code></code> | CA Certificate |

<a name="createCertificateSigningRequest"></a>

## createCertificateSigningRequest(settings) ⇒ <code>string</code>
Create a certificate signing request

**Kind**: global function  
**Returns**: <code>string</code> - String representation of certificate  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| settings | <code>Object</code> |  | The configuration object to tell OpenSSL how to format the key |
| [settings.key] | <code>buffer</code> \| <code>arrayBuffer</code> \| <code>string</code> \| <code>Array.&lt;string&gt;</code> \| <code>Object</code> | <code></code> | Key, default is current instance key. If not null, replaces key. |
| [settings.curve] | <code>number</code> | <code>NID_secp256k1</code> | Numerical ID (NID) for the Elliptic Curve (EC) to use |
| [settings.compressed] | <code>number</code> | <code>POINT_CONVERSION_UNCOMPRESSED</code> | Which X9.62 (ECDSA) form, for encoding an EC point |
| [settings.password] | <code>string</code> | <code>null</code> | Password to use |
| [settings.version] | <code>number</code> | <code>2</code> | Certificate version (actual version is 1 less than number) |
| [settings.name] | <code>string</code> | <code>&quot;\&quot;C&#x3D;US, ST&#x3D;VA, L&#x3D;DZM, O&#x3D;MyOrg, OU&#x3D;dev, CN&#x3D;NAME\&quot;&quot;</code> | Certificate name csv Distinguished Name (DN) string |
| [settings.id] | <code>number</code> | <code>0</code> | Certificate ID number |
| settings.basicConstraints | <code>Object</code> |  | Basic constraints on this certificate |
| [settings.keyUsage] | <code>Object</code> \| <code>string</code> | <code>this.keyUsage</code> | Key usage extensions. |
| [settings.extKeyUsage] | <code>Object</code> \| <code>string</code> | <code>this.extKeyUsage</code> | Extended Key usage extensions. |
| [settings.subjectAlternativeName] | <code>Object</code> |  | Object with properties enumerating SAN (additional host names) for certificate |
| [settings.subjectKeyIdentifier] | <code>string</code> | <code>&quot;\&quot;hash\&quot;&quot;</code> | Either hash per [https://tools.ietf.org/html/rfc3280#section-4.2.1.2](https://tools.ietf.org/html/rfc3280#section-4.2.1.2) or a hex string (strongly discouraged). |

<a name="validPrivateKey"></a>

## .validPrivateKey(privateKey, [min], [max]) ⇒ <code>Boolean</code>
Range Check Private Key

**Kind**: static function  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| privateKey | <code>buffer</code> \| <code>arrayBuffer</code> \| <code>string</code> \| <code>Array.&lt;string&gt;</code> \| <code>Object</code> |  | Private Key to compare |
| [min] | <code>string</code> | <code>&quot;\&quot;0\&quot;&quot;</code> | Minimum value as a hex string |
| [max] | <code>string</code> | <code>&quot;\&quot;FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140\&quot;&quot;</code> | Maximum value as a hex string |

