# Dsp1LoaderGhidra
A 3DS DSP Binary Loader for Ghidra

# Building and installing
Clone the repo
Ensure you have at least JDK 17 installed.
Run `gradlew -PGHIDRA_INSTALL_DIR=<Path_to_ghidra>` on *nix or `gradlew.bat -PGHIDRA_INSTALL_DIR=<Path_to_ghidra>` on Windows.
The extension will be gerrated at `dist/*.zip`
The extension can be installed in Ghidra from File -> Install Extensions... -> Add Extension
