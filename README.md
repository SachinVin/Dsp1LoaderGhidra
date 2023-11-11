# Dsp1LoaderGhidra
A 3DS DSP Binary Loader for Ghidra

# Building and installing
1. Clone the repo
2. Ensure you have at least JDK 17 installed.
3. Run `gradlew -PGHIDRA_INSTALL_DIR=<Path_to_ghidra>` on *nix or `gradlew.bat -PGHIDRA_INSTALL_DIR=<Path_to_ghidra>` on Windows.
4. The extension will be generated at `dist/*.zip`.
5. The extension can be installed in Ghidra from `File -> Install Extensions... -> Add Extension`
