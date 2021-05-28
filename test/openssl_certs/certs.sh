#!/usr/bin/sh

export prefix="AAAAAAAAAAAAAAAAAAA:localhostCA"
export tmpdir="../../tmp/gencerts"
export ca_key="$tmpdir/ca.key.pem"
export ca_cert="$tmpdir/ca.pem"
export server_key="$tmpdir/server.key.pem"
export server_csr="$tmpdir/server.csr"
export server_crt="$tmpdir/server.crt"

mkdir -p $tmpdir

if [ ! -f $ca_key ]; then
echo "Generating CA Key $ca_key"
#prime256v1
#secp256k1
#secp384r1
#openssl ecparam -name secp256k1 -genkey -noout -out $ca_key
#openssl genrsa -aes256 -out $ca_key 2048
openssl ecparam -name prime256v1 -genkey -noout -out $ca_key

chmod 400 $ca_key
fi

if [ ! -f $ca_cert ]; then
echo "Generating CA Certificate $ca_cert"
openssl req -new -x509 -subj "/CN=$prefix" -extensions v3_ca -days 3650 -key $ca_key -sha256 -out $ca_cert -config ./ca.cnf -set_serial 0x01
fi

openssl x509 -in $ca_cert -text -noout
openssl x509 -in $ca_cert -text -noout > $tmpdir/ca.pem.txt

if [ ! -f $server_key ]; then
echo "Generating Server Key"
openssl ecparam -name prime256v1 -genkey -noout -out $server_key
fi

openssl req -subj "/CN=localhost" -extensions v3_req -sha256 -new -key $server_key -out $server_csr

openssl req -in $server_csr -text -noout
openssl req -in $server_csr -text -noout > $tmpdir/csr.pem.txt

openssl x509 -req -extensions v3_req -days 3650 -sha256 -in $server_csr -CA $ca_cert -CAkey $ca_key -CAcreateserial -out $server_crt -extfile ./server.ext

openssl x509 -in $server_crt -text -noout
openssl x509 -in $server_crt -text -noout > $tmpdir/server.crt.txt