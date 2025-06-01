# aerocrack
An enhanced wireless security toolkit that builds upon Aircrack-ng with modern features
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
![aerocrack](./aerocrack.png)
[![All Contributors](https://img.shields.io/badge/all_contributors-3-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->
![License](https://img.shields.io/github/license/occupyashanti/aerocrack?style=flat-square)
![Issues](https://img.shields.io/github/issues/occupyashanti/aerocrack?style=flat-square)
> Next-generation Wi-Fi auditing toolkit with AI-driven prediction, enhanced SIMD compression, and security research utilitie
---

##  Overview

**aerocrack** is a fork and evolution of legacy wireless auditing tools, re-engineered to support modern chipsets, AI prediction models, hardware-accelerated compression (via SIMD), and advanced password cracking workflows.

This toolkit is intended for **security professionals**, **penetration testers**, and **researchers** focused on wireless security and cryptographic analysis.

---

## Features

- Monitor, inject, and capture packets on modern Wi-Fi networks
-  AI-based WPA key prediction engine
-  Neural compression pipeline using SIMD and tANS
-  Support for WPA/WPA2/WPA3 handshake cracking
-  Research utilities for EAPOL deconstruction and mutation
-  Wordlist mutation and parallel cracking tools
-  Support for Linux, Windows (WSL/MINGW64), and ARM

---

##  Installation

> Requires: Python 3.10+, Node.js (for contributor automation), Git, GCC/Clang

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install build-essential python3 python3-pip git
git clone https://github.com/occupyashanti/aerocrack.git
cd aerocrack
chmod +x aerocrack.sh
./aerocrack.sh --install
````

### Windows (MINGW64 / WSL)

```bash
git clone https://github.com/occupyashanti/aerocrack.git
cd aerocrack
bash aerocrack.sh --install
```

---

##  Quick Start

```bash
./aerocrack.sh --monitor wlan0
./aerocrack.sh --handshake capture.cap
./aerocrack.sh --predict keyspace.bin
```

See `docs/USAGE.md` for full CLI documentation.

---

##  Project Structure

```bash
.
├── aerocrack.sh            # Entry script
├── src/                    # Source code and utilities
├── docs/                   # Documentation
├── contributors.md         # Maintainers and contributors
├── .all-contributorsrc     # Contributor automation config
└── README.md               # This file
```

---

##  Contributors

We use [all-contributors](https://github.com/all-contributors/all-contributors) to recognize our contributors.
Thanks goes to:

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->

<!-- Contributions are automatically updated -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

>  Want to see your face here? See [How to Contribute](#-how-to-contribute)!

---

##  How to Contribute

We welcome code, docs, testing, and security research contributions.

###  Code

```bash
git checkout -b feature/my-feature
# make changes
git commit -s -m "feat: add my feature"
git push origin feature/my-feature
```

###  Docs

* Improve `README.md`, `docs/USAGE.md`
* Translate docs into other languages

### Testing & Security

* Report issues via [GitHub Issues](https://github.com/occupyashanti/aerocrack/issues)
* Contact us at `security@aerocrack.org` for sensitive disclosures

---

##  License

This project is licensed under the [MIT License](LICENSE).
Use responsibly and ethically.

---

## Acknowledgements

* Original inspiration from [Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng)
* SIMD compression based on open research in entropy coding
* Contributors who push boundaries of wireless security

---

<p align="center">
  Made with ⚡ by <a href="https://github.com/occupyashanti">Vyron Mino</a> & contributors
</p>
```

---

