# EML System

## Requirements
- Tested on Ubuntu 22.04.2 x86_64 with 5.15.0-76-generic kernel.
- Only tested under hardware mode.

## Build

This project uses CMake for building. Use the following commands to build the project:

``` console
$ mkdir build
$ cd build
$ cmake ..
$ make
```

## Configuration

Before running the EML system, configure the `config.toml` file as follows:

- Provide `SPID`, `IAS_PRIMARY_SUBSCRIPTION_KEY`, and `IAS_SECONDARY_SUBSCRIPTION_KEY` from the Intel API portal.
- Update `POLICY_MRSIGNER` value with the corresponding value from the MAKE output console.

## Execution

Run the following commands in order to start the EML system:

```bash
$sudo ./eml config.toml <app_port> <enclave_port>
$./app_owner config.toml 127.0.0.1 <app_port>
$sudo ./app_enclave config.toml 127.0.0.1 <enclave_port>
```

## Overview

The EML System, inspired by the paper "[ReplicaTEE: Enabling Seamless Replication of SGX Enclaves in the Cloud](https://arxiv.org/pdf/1809.05027.pdf)", is comprised of three main components:

1. **App Owner**: The App Owner initiates the auditing process by providing the EML with necessary keys after a secure connection has been established through remote attestation (RA).

2. **EML (Enclave Management Layer)**: The EML serves as a bridge between the App Owner and the App Enclaves (remotely in cloud). It receives keys from the App Owner, establishes a secure connection with the App Enclaves through enclave-to-enclave RA, and securely transfers the keys.

3. **App Enclave**: Once a App Enclave completes enclave-to-enclave RA with the EML and receives the necessary keys, it can start providing services while maintaining a secure, tamper-evident operating environment.

The implementation of the EML System relies on the integrity of Intel's Software Guard Extensions (SGX) enclaves and their ability to perform RA, Sealing and UnSealing.

> Note: This implementation does not include the Byzantine Fault-Tolerant Storage Layer described in the original paper.



## References

- [Intel SGX Linux](https://github.com/intel/linux-sgx)
- [SGX Enclave-to-Enclave RA](https://github.com/LuminousXLB/SGX-enclave-to-enclave-ra) 