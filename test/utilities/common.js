
import { tmpdir as ostmpdir } from "os";
import { join } from "path";

const tmpdir = () => process.env.DEV ? "./tmp" : ostmpdir();

const caKeyPath = join(tmpdir(), `ca.key.pem`),
    caCertPath = join(tmpdir(), `ca.cert.crt`),
    caCertTextPath = join(tmpdir(), `ca.cert.crt`),
    serverKeyPath = join(tmpdir(), `server.key.pem`),
    serverCSRPath = join(tmpdir(), `server.csr.pem`),
    serverCertPath = join(tmpdir(), `signed.client.crt`);

export { caKeyPath, caCertTextPath, caCertPath, serverKeyPath, serverCSRPath, serverCertPath };
