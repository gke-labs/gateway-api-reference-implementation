# gateway-api-reference-implementation

A minimal implementation of the Gateway API.

## Goals

The goal of this project is to create a simple, pure Go implementation of the [Gateway API](https://gateway-api.sigs.k8s.io/).

- **Reference Implementation**: This project aims to be a reference implementation rather than a high-performance one. It prioritizes clarity and correctness over speed.
- **Full Feature Support**: We want to support all Gateway API features.
- **Fallback Model**: We are exploring a model where this reference implementation can serve as a fallback for specialized implementations for configurations they cannot accelerate.
- **Pure Go**: The implementation should be written in pure Go.

## Contributing

This project is licensed under the [Apache 2.0 License](LICENSE).

We welcome contributions! Please see [docs/contributing.md](docs/contributing.md) for more information.

We follow [Google's Open Source Community Guidelines](https://opensource.google.com/conduct/).

## Disclaimer

This is not an officially supported Google product.

This project is not eligible for the Google Open Source Software Vulnerability Rewards Program.