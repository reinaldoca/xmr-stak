###### fireice-uk's and psychocrypt's
###### Ported by nioroso-x3 

# XMR-Stak - Cryptonight All-in-One Mining Software

XMR-Stak is a universal Stratum pool miner. This miner supports CPUs.
AMD and NVIDIA GPUs and can be used to mine the crypto currencies Monero, Aeon and many more Cryptonight coins. Never tested in IBM POWER.


## Overview
* [Features](#features)
* [Supported altcoins](#supported-altcoins)
* [Download](#download)
* [Usage](doc/usage.md)
* [HowTo Compile](doc/compile.md)
* [FAQ](doc/FAQ.md)
* [Developer Donation](#default-developer-donation)
* [Developer PGP Key's](doc/pgp_keys.md)

## Features

- support CPU only
- Linux only 
- supports algorithm cryptonight for Monero (XMR) other shitcoins not tested.
- open source software (GPLv3)
- TLS support
- [HTML statistics](doc/usage.md#html-and-json-api-report-configuraton)
- [JSON API for monitoring](doc/usage.md#html-and-json-api-report-configuraton)

## Supported altcoins

Monero, others not tested.

Currently best performance is with 4 pinned threads per core, using low power mode 1 and int_sqrt set to true.
Only low power modes 1 and 2 supported.


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
42UwBFuWj9uM7RjH15MXAFV7oLWUC9yLTArz4bmD3gbVWu1obYRUDe8K9v8StqXPhP2Uz1BJZgDQTUVhvT1cHFMBHA6aPg2
```

fireice-uk:
```
4581HhZkQHgZrZjKeCfCJxZff9E3xCgHGF25zABZz7oR71TnbbgiS7sK9jveE6Dx6uMs2LwszDuvQJgRZQotdpHt1fTdDhk
```

psychocrypt:
```
45tcqnJMgd3VqeTznNotiNj4G9PQoK67TGRiHyj6EYSZ31NUbAfs9XdiU5squmZb717iHJLxZv3KfEw8jCYGL5wa19yrVCn
```
