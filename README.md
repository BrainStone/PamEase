# PamEase

Pam modules to make your logging-in experience better

## Building and Installing

### Dependencies

This project requires the pam dev files as well as the boost base dev files.  
For Ubuntu you can use this command:

```console
sudo apt-get install libpam0g-dev libboost-dev
```

### CMake

This is a normal CMake project. If you are familiar with, there's nothing special about it. If not, here's a quick
guide:

```console
# Prepare build environment
cmake -B build
# Useful options:
#   - `-D CMAKE_BUILD_TYPE=Release`: Specify the build type. This defaults to Debug, so if you
#     want to use the project in production/a live system, specify it as Release.
#   - `-D CMAKE_INSTALL_PREFIX=/usr`: Specifies the install prefix. For productive use, set it
#     to `/usr`.
#   - `-D CMAKE_CXX_COMPILER=g++-14`: Specifies the compiler. GCC 14 or above is required. Not
#     sure about which Clang version is required, but you'll figure it out.

# Build the project
cmake --build build -j "$(nproc)"

# Install the project
sudo cmake --install build
```
