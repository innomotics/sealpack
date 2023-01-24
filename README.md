# Sealpack - sealed packaging for files and containers

This project allows the secure bundling of mobile code.
This means, files and container images can be packed like with any compression tool, but with a focus on the 
(CIA triad)[https://www.f5.com/labs/learning-center/what-is-the-cia-triad].
In addition, it was designed for flexibility and extensibility, so it can be used in various contexts.

## Basic operation

In a very basic way, `sealpack` is a single-command CLI with the 3 actions `seal`, `inspect`, and `unseal`

The `seal` action
* Creates a compressed archive from files __and/or__  container images
* Cryptographically signs the contents
* Encrypts the archive with a randomly generated key
* Seals the key for specific receivers

The `inspect` action
* Checks if a file is a `sealpack` file
* Display size of compressed payload, used Hashing-Algorithm and number of potential receivers

The `unseal` action
* Verifies that a file is a `sealpack` file
* Checks if encryption key is included and unseals the key
* Decompresses the contents and verifies the contents to match the signature
* Decrypts the files into a target directory and images to a container registry or a local `containerd` instance

### Prerequisites
The prerequisite for a fully featured usage of `sealpack` is every entity having a private-public-key-pair (PPK).

> Private keys must never be shared, best is to (use TPM as PPK storage)[https://blog.hansenpartnership.com/using-your-tpm-as-a-secure-key-store/].
> If not possible, use files with the least access permissions possible.

A mutual trust must be established by exchanging the public Keys. This means, the sender must have access to all public 
keys of potential receivers and each receiver must have access to the public key of the sender.

![](doc/Prerequisites.png)

On the sender side, collection, packaging, signing, encryption, and sealing can then be performed in a single flow:

![](doc/Seal.png)

On the receiver side, unsealing, verification, unpacking and importing is also a single step:

![](doc/Unseal.png)