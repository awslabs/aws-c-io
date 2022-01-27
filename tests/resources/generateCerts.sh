#!/usr/bin/env bash
# stop script on error
set -e

mkdir certGeneration
cp unittests.key certGeneration/unittests.key
cp unittests.conf certGeneration/unittests.conf
cp ca_root.cnf certGeneration/ca_root.cnf
cd certGeneration

touch index.txt
echo 1000 > serial

openssl genrsa -out ca_root.key 2048

openssl req -config ca_root.cnf \
            -key ca_root.key \
            -new -x509 -days 824 -sha256 -extensions v3_ca \
            -out ca_root.crt \
            -set_serial 00 \
            -subj '/C=US/ST=Washington/L=Seattle/O=Amazon/OU=SDKs/CN=localhostCA/emailAddress=aws-sdk-common-runtime@amazon.com'

openssl genrsa -out server.key 2048

openssl req -new -sha256 \
            -key server.key \
            -out server.csr \
            -set_serial 02 \
            -subj '/C=US/ST=Washington/L=Seattle/O=Amazon/OU=SDKs/CN=localhost/emailAddress=aws-sdk-common-runtime@amazon.com'

yes | openssl ca -config ca_root.cnf \
            -extensions server_cert \
            -days 824 -notext -md sha256 \
            -in server.csr \
            -out server.crt

cat server.crt ca_root.crt > certChain.crt

openssl req -x509 -new \
            -key unittests.key \
            -config unittests.conf \
            -out unittests.crt \
            -days 824

openssl pkcs8 -topk8 \
            -out unittests.p8 \
            -in unittests.key \
            -nocrypt

openssl pkcs12 -export \
            -out unittests.p12 \
            -inkey unittests.key \
            -in unittests.crt \
            -password pass:1234

cd ..
cp certGeneration/ca_root.crt ./ca_root.crt
cp certGeneration/server.crt ./server.crt
cp certGeneration/server.key ./server.key
cp certGeneration/certChain.crt ./certChain.crt
cp certGeneration/server.crt ./server.crt

cp certGeneration/unittests.crt ./unittests.crt
cp certGeneration/unittests.p8 ./unittests.p8
cp certGeneration/unittests.p12 ./unittests.p12

rm -r certGeneration
