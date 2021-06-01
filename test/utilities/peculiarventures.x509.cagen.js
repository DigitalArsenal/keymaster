
import elliptic from "elliptic";
import { jwkConv } from "./utility.js";
import { crypto as lcrypto } from "webcrypto-liner";
import base64URL from "base64url";
import { pbkdf2Sync } from 'crypto';
import * as x509 from '@peculiar/x509';
import { tmpdir as ostmpdir } from "os";
import { execSync } from "child_process";
import { caKeyPath, caCertPath, serverKeyPath, serverCSRPath, serverCertPath } from "./common.js";

const tmpdir = () => process.env.DEV ? "./tmp" : ostmpdir();
import { readFileSync, writeFileSync } from 'fs';

x509.cryptoProvider.set(lcrypto);

let { subtle: cs } = lcrypto;

let { importKey, exportKey, deriveBits, deriveKey, generateKey } = cs;

let _b = (b) => b.bind(cs);
importKey = _b(importKey);
exportKey = _b(exportKey);
deriveBits = _b(deriveBits);
deriveKey = _b(deriveKey);
generateKey = _b(generateKey);
let port = 8000;

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

    const keys = await importKey("jwk", jwkConv(privateKeyHex), { name: "ECDSA", namedCurve: "K-256" }, true, ["sign", "verify"]);

    console.log(keys, "\n", jwkConv(privateKeyHex));

    const keyExt = await exportKey("jwk", keys);
    console.log(publicKeyHex, "\n\n", publicKeyHexCompressed, "\n\n", base64URL.decode(keyExt.d, "hex"));
    console.log(base64URL.decode(keyExt.x, "hex"));
    console.log(base64URL.decode(keyExt.y, "hex"));

    let algorithm = {
        name: "ECDSA",
        hash: "SHA-256",
        namedCurve: "P-256",
        length: 256
    };

    const caKeys = await generateKey(algorithm, true, ["sign", "verify"]);

    let { d, ...pubKeyExt } = keyExt;

    const caCert = await x509.X509CertificateGenerator.createSelfSigned({
        serialNumber: "01",
        name: "CN=localhostCA",
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2022/01/02"),
        signingAlgorithm: algorithm,
        keys: caKeys,
        extensions: [
            new x509.BasicConstraintsExtension(true, 2, true),
            new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
            await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
        ]
    });

    let exportedCAKey = await exportKey("pkcs8", caKeys.privateKey);


    writeFileSync(caKeyPath, x509.PemConverter.encode(
        exportedCAKey,
        "private key"
    ));
    writeFileSync(caCertPath, caCert.toString("pem"));

    const convertedCAKeys = {
        privateKey: await importKey("jwk", keyExt, { name: "ECDSA", namedCurve: "K-256" }, true, ["sign"]),
        publicKey: await importKey("jwk", pubKeyExt, { name: "ECDSA", namedCurve: "K-256" }, true, ["verify"]),
    };

    let SAN = new x509.SubjectAlternativeNameExtension({
        dns: ["localhost", `localhost:${port}`],
        email: ["root@localhost"],
        ip: ["127.0.0.1", "0.0.0.0", "192.168.1.227"],
        guid: ["{ccc98a31-ff44-bc31-9a31-47bde489900a}"],
        upn: ["user"],
        url: [`https://localhost:${port}`, "https://localhost"]
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
        signingKey: convertedCAKeys.privateKey,
        extensions: [
            await new x509.AuthorityKeyIdentifierExtension(caCert),
            SAN
        ]
    });
    writeFileSync(serverCertPath, serverCert.toString('pem'));
    const output = execSync(
        `openssl x509 -in ${serverCertPath} -text -noout`
    ).toString("utf8");
    console.log(output);
}

main();