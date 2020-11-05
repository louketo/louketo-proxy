#! /bin/bash
#
# Generate certs according to kubernetes naming constraints
#
set -e -o pipefail
cd "$(git rev-parse --show-toplevel)"
cd fixtures/certs
domain=".localtest.me"
#podDomain=""
for radix in ca app gatekeeper upstream auth ; do
  key=${radix}.pem
  csr=${radix}.csr
  crt=${radix}.crt
  rm -f ${csr} ${crt} ${key}
  openssl genrsa -out ${key} 2048

  if [[ ${radix} == "ca" ]] ; then
    openssl req -x509 -new -nodes -key ${key} -sha256 -days 1024 -out ${crt} \
     -subj "/C=US/ST=CA/L=Palo Alto/O=OneConcern [test purpose]/OU=OneConcern [test purpose]/CN=${domain}"
  else
    openssl req -new -key ${key} -out ${csr} \
     -subj "/C=US/ST=CA/L=Palo Alto/O=OneConcern [test purpose]/OU=OneConcern [test purpose]/CN=${radix}${domain}"

    openssl x509 -req -in ${csr} -CA ./ca.crt -CAkey ./ca.pem -CAcreateserial -out ${crt} -days 1024 -sha256 \
                 -extensions SAN \
                 -extfile <(printf "\n[SAN]\nsubjectAltName = DNS:%s, DNS:%s, IP:127.0.0.1" "${radix}" "${radix}${domain}")
  fi
done
