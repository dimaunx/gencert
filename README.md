[![Test](https://github.com/dimaunx/gencert/actions/workflows/test.yaml/badge.svg)](https://github.com/dimaunx/gencert/actions/workflows/test.yaml) [![Go Report](https://goreportcard.com/badge/github.com/dimaunx/gencert)](https://goreportcard.com/badge/github.com/dimaunx/gencert) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# gencert

### Simple certificate generation tool for testing.

This tool was created to quickly generate certificates and chains for local development and testing.
The generated files are useful when we need to write tests for code that deals with certificate chains and their verification.

### Prerequisites for local development.

- [task]
- go1.19.x
- [curl]

### Optional.

- [goimports] go install golang.org/x/tools/cmd/goimports@latest
- [gofumpt] go install mvdan.cc/gofumpt@latest
- [golangci-lint] or task install/lint
- [trivy] or task install/trivy

### Build.

```
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
gencert create
```

Above command is equivalent to:

```shell
gencert create --path ca01 --can-cn ca01 --ca-days 365 --int-num 1 --int-hierarchy forest --int-days 364 --cert-cn test.example.com --cert-days 363
```

The command will generate locally in `ca01` folder a Root CA, intermediate CA, leaf certificate and export the CA chain.

The chain can be verified with:

```shell
openssl verify -CAfile ca01/ca-chain.cert ca01/test.example.com.cert
```

### Advanced usage.

```shell
gencert create --path ca02 --ca-cn ca02 --ca-days 7 --int-num 2 --int-hierarchy ladder --int-days 6 --cert-cn test.test.com --cert-days 5
```

* --path - Location for the generated certificates, relative to the folder that the `gencert` binary was executed from.
* --ca-cn - Root CA common name.
* --ca-days - Root CA duration in days.
* --int-num - Number of intermediate certificates to generate. If `0` is used no intermediates will be generated.
* --int-hierarchy - can be `forest` or `ladder`. Ladder mean that each intermediate (if more than one requested)
  will be signed by a previous intermediate. Forest means that all intermediates are signed by the root CA.
* --int-days - Intermediate certificates duration in days.
* --cert-cn - Server leaf certificate common name.
* --cert-days - Server leaf certificate duration in days.

The chain can be verified with:

```shell
openssl verify -CAfile ca02/ca-chain.cert ca02/test.test.com.cert
```

### Forest vs ladder.

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

[task]: https://taskfile.dev/installation/

[goimports]: https://pkg.go.dev/golang.org/x/tools/cmd/goimports

[gofumpt]: https://github.com/mvdan/gofumpt

[curl]: https://curl.se/download.html

[golangci-lint]: https://golangci-lint.run/usage/install/

[trivy]: https://github.com/aquasecurity/trivy

