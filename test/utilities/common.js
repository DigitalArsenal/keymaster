
import { tmpdir as ostmpdir } from "os";
import { join } from "path";

const tmpdir = () => process.env.DEV ? "./tmp" : ostmpdir();

const caKeyPath = join(tmpdir(), `ca.key.pem`),
    caCertPath = join(tmpdir(), `ca.cert.pem`),
    caCertTextPath = join(tmpdir(), `ca.cert.pem.txt`),
    serverKeyPath = join(tmpdir(), `server.key.pem`),
    serverCSRPath = join(tmpdir(), `server.csr.pem`),
    serverCSRTextPath = join(tmpdir(), `server.csr.pem.txt`),
    serverCertPath = join(tmpdir(), `signed.client.pem`),
    serverCertTextPath = join(tmpdir(), `signed.client.pem.txt`);

export { caKeyPath, caCertTextPath, caCertPath, serverKeyPath, serverCSRPath, serverCSRTextPath, serverCertPath, serverCertTextPath };
