**Senetas Cryptographic Software Development Kit**

Technical Integration & Custom Cipher User Guide (CSDK v0.0.4 Codename
Papa)

| **Specification Component** | **Details & Supported Environment**                                     |
|-----------------------------|-------------------------------------------------------------------------|
| Target Platforms            | Senetas DPDK-Enabled Encryptors (CS1000, CV1000, CN7000 / DELL VEP4600) |
| Supported Firmware          | Senetas Encryptor ESW 5.5.1 / ESW 5.6.4                                 |
| SDK Engine Core             | OpenSSL EVP Engine Integration Framework                                |

# 1. Executive Overview & System Architecture

The Senetas Cryptographic Software Development Kit (CSDK v0.0.4)
provides an extensible build system and integration framework for
deploying customized symmetric encryption algorithms onto Senetas
high-performance hardware and virtual encryption platforms. Utilizing
the OpenSSL EVP (Envelope) engine architecture, the CSDK enables
organization-specific cipher algorithms, sovereign crypto libraries, or
tailored cryptographic primitives to run directly within the high-speed
Data Plane Development Kit (DPDK) network data path.

Custom ciphers developed within the CSDK compile into a packaged OpenSSL
engine binary library (libcsdk.csdk). Once deployed onto a Senetas
encryptor, the custom engine overrides default symmetric encryption
algorithms, seamlessly protecting line-rate network communications.

## 1.1 Substitutable Symmetric Primitives

The CSDK allows custom symmetric block ciphers to replace standard
algorithms for network data plane encryption. The following OpenSSL
primitives and modes can be substituted:

| **Primitive / OpenSSL NID Identifier** | **Cryptographic Mode & Description**                |
|----------------------------------------|-----------------------------------------------------|
| NID_aes_128_cfb128                     | AES 128-bit in Cipher Feedback Mode (128-bit block) |
| NID_aes_256_cfb128                     | AES 256-bit in Cipher Feedback Mode (128-bit block) |
| NID_aes_128_ctr                        | AES 128-bit in Counter Mode                         |
| NID_aes_256_ctr                        | AES 256-bit in Counter Mode                         |
| NID_aes_128_gcm                        | AES 128-bit in Galois/Counter Mode (AEAD)           |
| NID_aes_256_gcm                        | AES 256-bit in Galois/Counter Mode (AEAD)           |
| NID_chacha20_poly1305                  | ChaCha20 256-bit with Poly1305 AEAD Mode            |

# 2. Development Environment Setup

The CSDK development environment is delivered as a pre-configured
Virtual Machine in Open Virtual Appliance (OVA) format. It runs Debian
Bullseye (Linux 11.3) with the full build toolchain, CMake scripts, and
sample cipher implementations pre-installed.

## 2.1 Virtual Machine Access Credentials

| **Account Type**    | **Username** | **Default Password** |
|---------------------|--------------|----------------------|
| Administrative Root | root         | $CSDKEngine          |
| Standard Developer  | csdk         | \#CSDKEngine         |

| **\[NETWORK & ENVIRONMENT NOTE\]** The VM is configured with DHCP enabled on network startup and has SSH enabled for secure remote terminal access. VirtualBox environment networking may require Secure Copy (SCP) if internal FTP routing issues occur. |
|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

## 2.2 CSDK Directory Structure

From the developer home directory (/home/csdk), the CSDK file hierarchy
is organized as follows:

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p>/home/csdk/</p>
<p>└── csdk/</p>
<p>└── libcsdk/</p>
<p>├── build.sh # Master CSDK wrapper build script</p>
<p>├── CMakeLists.txt # CMake build system configuration</p>
<p>├── src/csdk/cipher/ # Symmetric cipher source implementations</p>
<p>│ ├── custom.c # Custom cipher template file</p>
<p>│ ├── aesni.c # Intel AES-NI optimized implementation</p>
<p>│ ├── aessbox.c # Custom S-Box AES implementation</p>
<p>│ ├── camellia.c # Reference Camellia implementation</p>
<p>│ ├── camellia_ossl.c # OpenSSL assembler optimized Camellia</p>
<p>│ ├── twofish.c # Reference Twofish implementation</p>
<p>│ ├── xor.c # GCC intrinsic optimized XOR cipher</p>
<p>│ └── chacha20_poly1305.c # OpenSSL exported ChaCha20-Poly1305</p>
<p>└── tests/ # Known/Unknown Answer Test frameworks</p>
<p>├── csdk_test_custom.c # Custom test vector template file</p>
<p>└── csdk_test_*.c # KAT/UKAT implementations per cipher</p></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 3. Cipher Examples & Build Framework

The CSDK includes multiple sample cipher implementations demonstrating
different optimization techniques, architectural targets, and external
library integrations.

## 3.1 Reference Cipher Implementations

| **Cipher Name / Source File**           | **Implementation Details & Architectural Focus**                                                                                |
|-----------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| AES (aesni.c)                           | Complete OpenSSL AESNI export demonstrating performance deltas between native internal OpenSSL code and CSDK engine structures. |
| Custom S-Box AES (aessbox.c)            | Allows custom AES S-Box replacement. Includes gen_sbox.c to compile Te_words.inc / Td_words.inc tables using SSSE3/AVX opcodes. |
| Camellia Reference (camellia.c)         | Quick-start reference implementation presenting straightforward integration of author reference designs.                        |
| Camellia OpenSSL (camellia_ossl.c)      | Optimized assembler-based implementation illustrating performance scaling against reference designs.                            |
| Twofish (twofish.c)                     | Unoptimized reference design directly utilizing author reference source code.                                                   |
| XOR (xor.c)                             | Trivial GCC intrinsic-optimized cipher for initial logical testing of the framework.                                            |
| ChaCha20-Poly1305 (chacha20_poly1305.c) | Reference AEAD algorithm override allowing dual operation with standard AES algorithms.                                         |
| Aria KLIB (aria-klib)                   | Demonstrates integration of third-party pre-certified sovereign crypto shared libraries into the CSDK.                          |

## 3.2 Executing the CSDK Build System

To build a cipher and generate an installable OpenSSL engine package,
execute the master build script from /home/csdk/csdk/libcsdk:

| ./build.sh \<aes\|twofish\|xor\|camellia\|aessbox\|custom\> |
|-------------------------------------------------------------|

The build wrapper performs the following automated steps:

-   1\. Executes a clean CMake compilation of the CSDK tools and target
    cipher source.

-   2\. Runs Known Answer Tests (KAT) and Unknown Answer Tests (UKAT)
    for native/corei7 host builds.

-   3\. Creates the final OpenSSL engine CSDK library binary
    (libcsdk.csdk).

-   4\. Generates an upgrade package in the packages/ directory ready
    for deployment.

| **\[ARCHITECTURE OPTIMIZATION\]** Specific target processor architectures can be specified during build (e.g., skylake-avx512 for the CN7000 DELL VEP4600 platform). When cross-building for non-native target architectures, host self-tests are bypassed during compile, but the KAT/UKAT suite remains embedded in the payload for target-side verification upon startup. |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

# 4. Developer Integration Guide: Four Cipher Hooks

Developing a custom cipher requires implementing the cipher algorithms
in C within src/csdk/cipher/custom.c and exposing four required function
hooks to interface with the CSDK OpenSSL engine framework.

| **\[DESIGN CONSIDERATION\]** Because network data plane operating modes (such as CFB and CTR) construct decryption streams using forward block encryption, an explicit block decryption function is not required. Initialisation should be handled inside key expansion callbacks. |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

## 4.1 The Four Required Cipher Function Hooks

### Hook 1: Define Key Structure

Specifies a uniform key representation structure containing key size
(128 or 256 bits), block size (16 bytes / 128 bits), and a private data
area for cipher-specific structures (e.g., round key tables):

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><p>typedef struct {</p>
<p>int key_size_bits; /* Configured size: 128 or 256 bits */</p>
<p>int block_size_bytes; /* Fixed block size: 16 bytes (128 bits) */</p>
<p>void *keyTable; /* Private cipher state / expanded key schedule
*/</p>
<p>} custom_key_t;</p></th>
</tr>
</thead>
<tbody>
</tbody>
</table>

### Hook 2: Key Initialisation & Decryption Callback

Initializes and expands the key schedule prior to decryption operations:

| int custom_key_dec_init(custom_key_t \*key, const unsigned char \*user_key); |
|------------------------------------------------------------------------------|

### Hook 3: Key Initialisation & Encryption Callback

Initializes and expands the key schedule prior to encryption operations:

| int custom_key_enc_init(custom_key_t \*key, const unsigned char \*user_key); |
|------------------------------------------------------------------------------|

### Hook 4: Block Encryption Callback

Performs core block encryption transform, taking a pointer to a 128-bit
plaintext block and generating a 128-bit ciphertext block:

| void custom_block_encrypt(const custom_key_t \*key, const unsigned char \*in, unsigned char \*out); |
|-----------------------------------------------------------------------------------------------------|

# 5. Validation & Operational Assurance Framework

The CSDK integrates an operational self-test suite embedded directly
into the binary package. This ensures cryptographic integrity both
during build validation and upon initial boot on Senetas encryptors.

## 5.1 Self-Test Mechanisms

| **Test Category**           | **Verification Methodology & Operational Purpose**                                                                       |
|-----------------------------|--------------------------------------------------------------------------------------------------------------------------|
| Known Answer Tests (KAT)    | Compares cipher execution results against pre-computed expected output vectors, returning explicit Pass/Fail indicators. |
| Unknown Answer Tests (UKAT) | Computes cipher output transforms and outputs raw hex values for manual cryptographic verification.                      |

Custom test vectors are defined in tests/csdk_test_custom.c. Upon
building with build.sh custom, test functions are compiled into the
payload and executed automatically when the engine initializes on the
encryptor.

# 6. Deployment & Device Provisioning (CM7 Quick Start)

Deployment of compiled CSDK engine libraries onto Senetas encryptors
(e.g., CS1000, CV1000, CN7000) is managed using the Senetas Element
Manager (CM7) GUI or CLI commands.

## 6.1 Step-by-Step Provisioning Lifecycle

-   Step 1: Discover Encryptors

Launch CM7 from the CSDK VM terminal (type 'CM' or use Desktop menu).
Under the Discover tab, discover target encryptors (e.g., 10.65.65.170 /
10.65.65.171) via SNMPv3 and select 'Add selected Encryptors'.

-   Step 2: Firmware Requirements & Licensing

Verify encryptors run compatible firmware (ESW 5.5.1 / 5.6.4). Transfer
firmware image files via the VM FTP server (/srv/ftp) if upgrade is
required.

| **\[HARDWARE LICENSING REQUIREMENT\]** Hardware platforms (such as the CN7000) require an additional USB upgrade script tied to the unit serial number to enable CSDK operation. Contact Senetas support for access. |
|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

-   Step 3: Disable FIPS Mode

CSDK engines cannot be installed while the encryptor operates in FIPS
140-2 mode. Disable FIPS mode via CM7 or the CLI before engine
installation.

-   Step 4: Device Activation

Execute the CLI command 'activate -l' and set new administrator
credentials replacing factory defaults.

-   Step 5: Install CSDK Engine

Copy the compiled engine file (libcsdk.csdk) into the VM FTP directory
(/srv/ftp). Initiate software upgrade via CM7 or CLI upgrade options.
Perform a device reboot following installation.

-   Step 6: Configure Operating Mode & Enable Encryption

Configure the desired network operating mode (e.g., Line, VLAN, MAC,
TIM) via CLI commands. Switch global encryption mode to ENCRYPT to
protect traffic using the CSDK engine.

## 6.2 Device Verification & Monitoring CLI Commands

The following front-panel or SSH CLI commands are available to inspect
and manage CSDK engine state:

| **CLI Command** | **Operational Description & Action**                                                                |
|-----------------|-----------------------------------------------------------------------------------------------------|
| csdk            | Displays front panel CSDK engine status and configuration summary.                                  |
| csdk status     | Outputs detailed engine operational health and active cipher parameters.                            |
| csdk selftest   | Triggers on-demand execution of embedded KAT/UKAT verification suites.                              |
| csdk remove     | Uninstalls CSDK engine and reinstates default built-in AES symmetric encryption. (Requires reboot). |

Engine performance and operational metrics can be confirmed using
profiling counters and the 'tunnels' CLI command once active network
traffic is flowing between encryptors.
