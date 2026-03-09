# SafeStorage

A C project that shows secure handling and persistent storage.

## Architectural Overview

* **SafeStorage (CLI):** Orchestrates operations, user input, and telemetry.
* **SafeStorageLib (Core):** Abstracts cryptographic primitives (ciphers, stream management).
* **SafeStorageUnitTests (Validation):** Ensures reliability and guards against algorithmic regressions.

## Security Features

* **Confidentiality:** Industry-standard encryption for data at rest.
* **Integrity:** MACs/Hashing to detect unauthorized modification.
* **Memory Security:** Programmatically sanitized buffers to prevent leakage.

## Build Instructions

1. **Environment:** Open `SafeStorage.sln` in Visual Studio 2022.
2. **Configuration:** Select `Debug | x86`.
3. **Compilation:** `Ctrl+Shift+B`.
4. **Validation:** Execute the **Validation Suite** via Test Explorer.

---

**Disclaimer:** This project is for educational/research purposes. It has not undergone an external cryptographic audit and is not recommended for production use.
