# Poseidon Hash Gnark Circuit Implementation

This repository contains the gnark circuit implementation of the Poseidon hash function, designed for integration into the [zk-Harness project](https://github.com/zkCollective/zk-Harness).

## Introduction

The Poseidon hash function is a cryptographic primitive designed for efficient computation in zero-knowledge proofs. This repository provides a gnark circuit implementation of Poseidon, which can be used with the zk-Harness project to create, verify, and benchmark zero-knowledge proofs.

## Installation

To install the necessary dependencies, you can clone this repository and use the Go package manager:

```shell
git clone https://github.com/AlpinYukseloglu/poseidon-gnark
cd poseidon-gnark
go get
```

## Usage

After installation, you can import the Poseidon hash gnark circuit into your Go projects like this:

```go
import "github.com/AlpinYukseloglu/poseidon-gnark"
```

You can then use the poseidon.Hash function to compute Poseidon hashes in your gnark circuits.

## Integration with zk-Harness

This implementation is designed for integration with the zk-Harness project. To use it within zk-Harness, you'll need to import the Poseidon gnark circuit and use it in the construction of your zk-SNARK. For more information on using gnark with zk-Harness, see the zk-Harness documentation.

## Contributing

Contributions are welcome! Please feel free to submit a pull request.

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.

## Acknowledgements

We are grateful for the work of the zkCollective and the larger zero-knowledge proof community in developing the tools and techniques that make this implementation possible.

## Disclaimer

This is a research-quality implementation. It has not been extensively reviewed or tested for security. Please use at your own risk.
