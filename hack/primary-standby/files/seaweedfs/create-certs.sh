cat <<EOF >openssl.cnf
[req]
default_bits       = 4096
prompt             = no
default_md         = sha256
x509_extensions    = v3_req
distinguished_name = dn

[dn]
C = US
ST = CA
L = SanFrancisco
O = MyOrg
CN = seaweedfs

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = seaweedfs
DNS.2 = localhost
EOF

mkdir -p certs

openssl req -x509 -nodes -days 365 \
  -newkey rsa:4096 \
  -keyout certs/private.key \
  -out certs/public.crt \
  -config openssl.cnf

rm -f openssl.cnf
