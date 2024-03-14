# QuickMerge Helper
Shortcut signer for stock iOS.

# What you'll need
- A QMD file containing your private key and auth data; [https://github.com/0xilis/QMCDumper-Simulator](https://github.com/0xilis/QMCDumper-Simulator) can dump this for you.
- An unsigned shortcut to sign

# Uses

This uses my [libshortcutsign](https://github.com/0xilis/libshortcutsign) library to sign shortcut files, which is a result of my countless hours reverse engineering WorkflowKit. This also uses libqmc, a library for handling QMC/QMD files, a file format I made for this project to hold the cached auth data & key.

# TODO
After a shortcut is signed, the app crashes. For some reason the debugger says it's due to a function (`signing_private_key_for_raw_qmd`) that we call long before the crash(???). However it still exports the signed shortcut to files prior to crash, so it's fully usable.

# Licensing
Unsigncuts for macOS is licensed under MIT.
