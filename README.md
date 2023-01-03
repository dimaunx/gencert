[![Test](https://github.com/dimaunx/gencert/actions/workflows/test.yaml/badge.svg)](https://github.com/dimaunx/gencert/actions/workflows/test.yaml) 
[![Go Report](https://goreportcard.com/badge/github.com/dimaunx/gencert)](https://goreportcard.com/badge/github.com/dimaunx/gencert) 
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# gencert

### Simple certificate generation tool for testing.

This tool was originally created to quickly generate certificate chains for local development and testing.
The generated files are especially useful when testing code that deals with certificate chains and their verification.

### Prerequisites for local development.

- [task]
- go1.19.x
- [curl]

### Optional.

- [goimports] go install golang.org/x/tools/cmd/goimports@latest
- [gofumpt] go install mvdan.cc/gofumpt@latest
- [golangci-lint] or task install/lint
- [trivy] or task install/trivy

### Installation

Binaries for Linux, Windows and Mac are available as tarballs on the [release] page.

If you have go installed.

```shell
go install github.com/dimaunx/gencert@latest
```

### Build manually on Mac or Linux.

```
sh -c "$(curl -sL https://taskfile.dev/install.sh)" -- -d -b /usr/local/bin
git clone https://github.com/dimaunx/gencert.git
cd gencert
task build
```

## Help.

```shell
gencert create -h
```

### Usage.

```shell
gencert create -v
```

Above command is equivalent to:

```shell
gencert create -v --path ca01 --can-cn ca01 --ca-days 365 --int-num 1 --int-hierarchy forest --int-days 364 --cert-cn test.example.com --cert-days 363
```

The command will generate in a local `ca01` folder a root CA, intermediate CA, one leaf client/server certificate
and export the CA chain to a file in PEM format. The chain file will not include the client/server certificate,
only root and intermediate CA certificates.

The chain can be verified with:

```shell
openssl verify -CAfile ca01/ca-chain.cert ca01/test.example.com.cert
```

The folder will also contain CA private keys. These keys can be used to generate more certificates with `openssl`
command if required. It is recommended to sign the leaf certificate with the intermediate keys and not with the
root certificate keys.

```shell
openssl req -new -nodes -out ca01/test.local.csr -newkey rsa:2048 -keyout ca01/test.local.key -subj '/C=US/L=Los Angeles/O=Example/OU=Example/CN=test.local'
cat > ca01/test.local_v3_ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = test.test.local
DNS.2 = www.test.local
IP.1 = 192.168.1.1
IP.2 = 192.168.2.1
EOF
openssl x509 -req -in ca01/test.local.csr -CA ca01/ca01-int01.cert -CAkey ca01/ca01-int01.key -CAcreateserial -out ca01/test.local.cert -days 7 -sha256 -extfile ca01/test.local_v3_ext
openssl x509 -noout -text -in ca01/test.local.cert # view the certificate
openssl verify -CAfile ca01/ca-chain.cert ca01/test.local.cert # verify chain
```

### Advanced usage.

```shell
gencert create --path ca02 --ca-cn ca02 --ca-days 7 --int-num 2 --int-hierarchy ladder --int-days 6 --cert-cn test.test.com --cert-days 5
```

* --path - Location for the generated files, relative to the folder that the `gencert` binary was executed from.
* --ca-cn - Root CA common name.
* --ca-days - Root CA duration in days.
* --int-num - Number of intermediate certificates to generate. If `0` is used no intermediates will be generated.
* --int-hierarchy - Can be `forest` or `ladder`. `ladder` means that each intermediate (if more than one requested)
  will be signed by a previous intermediate. `forest` means that all intermediates are signed by the same root CA.
* --int-days - Intermediate certificates duration in days.
* --cert-cn - Client/Server leaf certificate common name.
* --cert-days - Client/Server leaf certificate duration in days.

The chain can be verified with:

```shell
openssl verify -CAfile ca02/ca-chain.cert ca02/test.test.com.cert
```

### forest vs ladder.

![forest vs Ladder](images/hierarchy.png?raw=true "Hierarchy")

### List all available tasks.

```shell
task -l
```

### Run tests.

```shell
task test
task cover
```

### Run linter.

```shell
task lint
```

### Run `gofumpt` with fixes.

```shell
task gofumpt
```

### Run and fix go imports.

```shell
task goimports
```

### Run local security scan with trivy.

```shell
task trivy
```

<!--links-->

[release]: https://github.com/dimaunx/gencert/releases

[task]: https://taskfile.dev/installation/

[goimports]: https://pkg.go.dev/golang.org/x/tools/cmd/goimports

[gofumpt]: https://github.com/mvdan/gofumpt

[curl]: https://curl.se/download.html

[golangci-lint]: https://golangci-lint.run/usage/install/

[trivy]: https://github.com/aquasecurity/trivy

