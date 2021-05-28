import https from 'https';
import assert from "assert";
import bitcoinjs from "bitcoinjs-lib";
import wif from "wif";
import base58 from "bs58";
import { createPBKDF2Key } from "./deterministic.keygen.pbkdf2.js";
import { createPublicAddress } from "./bitcoin.address.from.hex.js";
import { clean } from "./utility.js";
import { caKeyPath, caCertPath, serverKeyPath, serverCSRPath, serverCertPath } from "./common.js";

import { writeFileSync, unlinkSync, fstat, readFileSync } from "fs";
import { join } from "path";
import { tmpdir as ostmpdir } from "os";
import { execSync } from "child_process";

const tmpdir = () => process.env.DEV ? "./tmp" : ostmpdir();
let port = 8000;

https.createServer({
    key: readFileSync(serverKeyPath),
    cert: readFileSync(serverCertPath)
}, (req, res) => {
    res.writeHead(200);
    res.end('hello world\n');
}).listen(port);
console.log(`listening on: ${port}`);

