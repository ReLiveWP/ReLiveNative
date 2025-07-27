# ReLiveWP Natives
This repository contains a set of native binaries built to replace the Windows Live ID service and Microsoft Account DLL on Windows Phone 7 devices.

# Building
Included is all required source code and toolchain files, but no signing certificates. You will have to generate these yourself if you wish to deploy these binaries to your devices for testing. In future, test certificates may be provided to aid development efforts. 

Currently, the project expects a non-password protected PKCS#12 certificate chain named `certs/codesign.pfx`.

This project heavily depends on cegcc and CMake. cegcc must be patched to disable position independent code, these patches are not yet included here but will be shortly.

Other patches for dependencies such as curl, zlib, mbedtls, etc. are available in the `patches/` directory. Once these are built and installed, you can then run

```sh
$ mkdir build
$ cd build
$ cmake --toolchain=../cmake/toolchain/arm-mingw32ce.cmake .. -G Ninja
$ ninja
```

This will compile and sign the binaries and place them in `build/bin`