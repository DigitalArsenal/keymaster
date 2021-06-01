
import elliptic from "elliptic";
import { jwkConv } from "./utility.js";
import { crypto as lcrypto } from "webcrypto-liner";
import { pbkdf2Sync } from 'crypto';
import * as x509 from '@peculiar/x509';
import { tmpdir as ostmpdir } from "os";
import { execSync } from "child_process";
import { caKeyPath, caCertPath, serverKeyPath, serverCSRPath, serverCertPath } from "./common.js";

import { writeFileSync } from 'fs';

x509.cryptoProvider.set(lcrypto);

let { subtle: cs } = lcrypto;

let { importKey, exportKey, deriveBits, deriveKey, generateKey } = cs;

let _b = (b) => b.bind(cs);
importKey = _b(importKey);
exportKey = _b(exportKey);
deriveBits = _b(deriveBits);
deriveKey = _b(deriveKey);
generateKey = _b(generateKey);

const getPublicFromPrivateHex = (privateHex, curve = "secp256k1", compressed = true) => {
    let ec = new elliptic.ec(curve);
    let key = ec.keyFromPrivate(privateHex, "hex");
    return key.getPublic(compressed, "hex");
};

let password = "password", salt = "salt", pin = 1, keyLength = 32;

async function main() {

    let pK = pbkdf2Sync(password, salt, 1, 32, "sha256", 0);
    const privateKeyHex = pK.toString("hex");

    const publicKeyHex = getPublicFromPrivateHex(privateKeyHex, undefined, false);
    const publicKeyHexCompressed = getPublicFromPrivateHex(privateKeyHex, undefined, true);
    console.log(publicKeyHex);
    const namedCurve = "P-256";
    const keys = await importKey("jwk", jwkConv(privateKeyHex, publicKeyHex, namedCurve), { name: "ECDSA", namedCurve }, true, ["sign", "verify"]);

    const keyExt = await exportKey("jwk", keys);

    let algorithm = {
        name: "ECDSA",
        hash: "SHA-256",
        namedCurve: "P-256",
        length: 256
    };

    let { d, ...pubKeyExt } = keyExt;

    const caKeys = {
        privateKey: await importKey("jwk", keyExt, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]),
        publicKey: await importKey("jwk", pubKeyExt, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]),
    };

    let { digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment } = x509.KeyUsageFlags;

    const caCert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: "CN=AAA.x509.localhostCA",
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2022/01/02"),
        signingAlgorithm: algorithm,
        keys: caKeys,
        extensions: [
            new x509.BasicConstraintsExtension(true, 2, true),
            await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
            await x509.AuthorityKeyIdentifierExtension.create(caKeys.publicKey),
            new x509.KeyUsagesExtension(digitalSignature | nonRepudiation | keyEncipherment | dataEncipherment, true),

        ]
    });

    let exportedCAKey = await exportKey("pkcs8", caKeys.privateKey);


    writeFileSync(caKeyPath, x509.PemConverter.encode(
        exportedCAKey,
        "private key"
    ));
    writeFileSync(caCertPath, caCert.toString("pem"));

    console.log(execSync(
        `openssl x509 -in ${caCertPath} -text -noout`
    ).toString("utf8"));

    let SAN = new x509.SubjectAlternativeNameExtension({
        dns: ["localhost"]
    });


    const serverKey = await generateKey({
        name: "ECDSA", namedCurve: "P-256"
    }, true, ["sign", "verify"]);

    let exportedServerKey = await exportKey("pkcs8", serverKey.privateKey);

    writeFileSync(serverKeyPath, x509.PemConverter.encode(
        exportedServerKey,
        "private key"
    ));

    const serverCert = await x509.X509CertificateGenerator.create({
        serialNumber: `${Date.now()}`,
        subject: `CN=localhost`,
        issuer: caCert.issuer,
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2022/01/02"),
        signingAlgorithm: algorithm,
        publicKey: serverKey.publicKey,
        signingKey: caKeys.privateKey,
        extensions: [
            new x509.KeyUsagesExtension(digitalSignature | nonRepudiation | keyEncipherment | dataEncipherment, true),
            await x509.AuthorityKeyIdentifierExtension.create(caKeys.publicKey),
            SAN
        ]
    });
    writeFileSync(serverCertPath, serverCert.toString('pem'));

    console.log(execSync(
        `openssl x509 -in ${serverCertPath} -text -noout`
    ).toString("utf8"));
}

main();