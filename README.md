<img width="1185" height="537" alt="image" src="https://github.com/user-attachments/assets/2d643e30-d86c-4be7-9f7d-dc8fef60bde6" />


1. Sensor.py:

A read-only Windows 11 host auditor that scans obscure peripheral and
root-of-trust surfaces and reports what it found, what it could not establish,
and which source could have lied about each value. Python 3, standalone, no
dependencies outside the standard library.

Eighteen sections: TPM, BitLocker, device inventory, device risk notes,
DMA/Thunderbolt, interception surface, boot integrity, low-level hardware
access, firmware surface, smart-card certificates, generic driver & INF audit,
SDR/TV tuner, historical residue, source trust, posture gaps, findings, host,
collection errors.

2. Audiocam.py:

Read-only Windows 10/11 auditor for **microphones**, **cameras**, and the **apps and sites that were allowed to use them**.


3. Bluejack.py:

Read-only Bluetooth posture audit for a single Windows host.

Bluejack answers one question from one machine: **what is this host's Bluetooth
posture right now, and what should I fix first?** It enumerates adapters, bonded
Classic and BLE devices, offered profiles, discoverability, authentication,
encryption-key-length policy, and stale pairings, then maps what it finds to stable
MITRE ATT&CK techniques.

It does not change anything. It does not talk to the radio. It does not emit link
keys. It does not touch the network.

4. Intention.py:

Read-only collector of **interactive command-line history** on Windows, plus
the installation and configuration facts needed to interpret it. Collects and identifies obscure shells to include zsh, fish, nushell, xonsh, elvish, Atuin, Cygwin, and many others.
