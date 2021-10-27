# Tlskeydump

Tlskeydump extracts TLS key material from processes at runtime so that packet captures containing TLS-encrypted data can be decrypted and analyzed. It can connect to either an already-running\* or a new process, and dump key material both for new connections and for connections that were already open when tlskeydump was attached. Tlskeydump outputs key material in the [NSS Keylog format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format), which can be [directly read by Wireshark](https://gitlab.com/wireshark/wireshark/-/wikis/TLS) and other tools.

\* See project status below though!

## Project status
This is SSS-UUU-PPP-EEE-RRR early, experimental, and incomplete. Here's a short list of the things it's lacking (in no particular order):

* The `--pid` flag from the manual is actually not yet implemented - it can only start new child processes right now, not attach to existing ones.
* Test suite needs to be _much_ more filled out
* Support for more versions of OpenSSL than just 1.1.1 (I think others will actually work, but I need to add some tests)
* Support for TLS libraries other than OpenSSL - e.g. GNUTLS, LibreSSL, Golang's SSL stack
* Support for re-checking for TLS libraries after dlopen(3) is called (I think this is how e.g. Ruby/Python would import OpenSSL)
* Support for statically linked versions copies of TLS libraries (by finding symbols in a different, dynamically-linked copy of the library, and praying, most likely)
* Support for server processes (tests are curently just running against client processes - I suspect that servers might actually work, but I haven't tested it)
* Support for using eBPF programs to find the secret material in process memory, rather than user-space breakpoints like its doing now (I believe this will make it quite a bit faster)
* I want to benchmark how much this impacts performance of the traced process
* Set up packages & downloads for the program (including static builds that can be simply dropped in to a running container easily - at the moment tlskeydump depends on half of Debian).
* Build instructions for various Linux distros.
* Work out some sensible minimum versions of the dependencies that we actually need.
* CI and things like that
* Actually render the manual page nicely somewhere
* Support for architectures that aren't x86_64. Would be good to at least get this working on arm64, since that's increasingly being used for server workloads.
* Support for non-Linux platforms.

If you want to help out, please get in touch! Open an issue or email me at `kjtsanaktsidis@gmail.com`.

## Building & Running

To build the program, you'll need the following dependencies:

* gcc/g++/binutils
* cmake
* OpenSSL headers & libraries (libssl/libcrypto)
* Boost headers & libraries (thread, iostreams, program-options and log)
* ELFUtils libraries (libelf, libdw, libdwfl, and libdebuginfod)

And to run the tests, you'll need these too:

* Ruby & Bundler
* clang-format

On debian unstable, this should be enough to install what's needed:

```bash
sudo apt install \
    build-essential \
    cmake \
    clang-format \
    libboost-dev \
    libboost-log-dev \
    libboost-thread-dev \
    libboost-iostreams-dev \
    libboost-program-options-dev \
    libssl-dev \
    libelf-dev \
    libdw-dev \
    libdebuginfod-dev \
    ruby-dev \
    ruby-bundler
```

To build tlskeydump, from the checked-out source directory:

```bash
mkdir build; cd build;

# If you're not going to run the test suite, do this
cmake -D BUILD_TESTING=off ..

# Otherwise, you'll need this - note that the test suite builds OpenSSL several times
# with different options, so it's _incredibly_ slow to build.
cmake ..

# add VERBOSE=1 or -j64 as you prefer
make

# run openssl s_client under tlskeydump!
./tlskeydump -o keylog.txt -- openssl s_client -connect google.com:443
# Type some junk in here, like GET / HTTP/1.0 or something, then quit

cat keylog.txt
# Should see something like the following!
EXPORTER_SECRET 402430b12bb4f95d515a4ff35cc21310d6814f6df8169703ea3c91072ea5f395 c5cda78f80594a6f2df6d7c769f2f0e36d193901fc4721176ac146705b27d3b5d2c7772714b4e849276d98d21f616413
CLIENT_HANDSHAKE_TRAFFIC_SECRET 402430b12bb4f95d515a4ff35cc21310d6814f6df8169703ea3c91072ea5f395 10f8a38bca80bb2b9268ec0e92d9d8b632399b2e920a77a30fc709ae6cb7ec183e7d3a47b31037425a676370a4a30eb1
SERVER_HANDSHAKE_TRAFFIC_SECRET 402430b12bb4f95d515a4ff35cc21310d6814f6df8169703ea3c91072ea5f395 f0d345354cc30f62bc3102845e73a75c11e87e49e8b4b79138f09691c8fb7c25342d8d40fe3d6ffbc0483f7d9a245921
CLIENT_TRAFFIC_SECRET_0 402430b12bb4f95d515a4ff35cc21310d6814f6df8169703ea3c91072ea5f395 6354d0f88f7797c8331b989703566d57b4bb5de4c92803fafc4c29cba02a7f639c41a66dcc2b85746d47ef85bf89997b
SERVER_TRAFFIC_SECRET_0 402430b12bb4f95d515a4ff35cc21310d6814f6df8169703ea3c91072ea5f395 8a5bb962e24cc846ab944e0238a71a29fcda42322bf4c1df57ee0dd640e9f256591fd57441f11caa13d287ad4a417ba6

# If you want to run the test suite:
ctest --verbose
```

## Documentation
There's a [man page](https://github.com/KJTsanaktsidis/tlskeydump/blob/main/tlskeydump.1.ronn) here.

## How it works

Tlskeydump works by attaching to the target process using [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html), which gives total control over the execution of target and, depending on [system configuration](https://www.kernel.org/doc/Documentation/security/Yama.txt), may require that you run it as root. Once attached, the processes memory map is searched for common TLS libraries (at the moment, only OpenSSL is supported). Tlskeydump then attempts to find DWARF debug symbols (more on that later) for the library, and attaches a breakpoint to a handful of functions from the library (by literally overwriting it with an architecture-specific trap instructon).

When the trap is hit, tlskeydump gets the pointer to the SSL context structure from the function arguments (e.g. for OpenSSL, this will be the `SSL` pointer). This pointer, along with the associated debug symbols from the structure, is then used to find the TLS key material for the session (e.g. CLIENT_RANDOM, CLIENT_HANDSHAKE_TRAFFIC_SECRET, etc.) inside the structure. This data is then emitted to the NSS keylog file.

