###### fireice-uk's and psychocrypt's
###### Ported by nioroso-x3 

# XMR-Stak - Cryptonight All-in-One Mining Software

XMR-Stak is a universal Stratum pool miner. This miner supports CPUs.
AMD and NVIDIA GPUs and can be used to mine the crypto currencies Monero, Aeon and many more Cryptonight coins but are not  tested in IBM POWER.


## Overview
* [Features](#features)
* [Usage](doc/usage.md)

## Features

- support CPU only, GPU not tested.
- Linux only 
- supports algorithm cryptonight for Monero (XMR) other shitcoins not tested.
- open source software (GPLv3)
- TLS support
- [HTML statistics](doc/usage.md#html-and-json-api-report-configuraton)
- [JSON API for monitoring](doc/usage.md#html-and-json-api-report-configuraton)

## Supported altcoins

Monero, others not tested.

Currently best performance is with 4 pinned threads per core, using low power mode 1 and int_sqrt set to true.
Low power modes 1,2 and 3 are supported.
To use big endian AES optimization for Power8, set aesoverride in config.txt to true.


Benchmarks:
20 core power8, 2.83 GHz = 1600 hash/s, 80 hash/s per core CNv2

## Download

No binary releases.

To compile use gcc 6.3.0 or newer.

## Default Developer Donation

By default, the miner will donate 1%, only for Monero.

If you want to donate directly to support further development, here is my wallet

nioroso-x3:
```
x
```

fireice-uk:
```
x
```

psychocrypt:
```
x
```
