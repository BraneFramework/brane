#!/usr/bin/env python3
# MAKE.py
#   by Lut99
#
# Created:
#   09 Jun 2022, 12:20:28
# Last edited:
#   13 Apr 2023, 10:07:16
# Auto updated?
#   Yes
#
# Description:
#   Python script that implements the (more advanced) make script for the
#   Brane infrastructure.
#

from __future__ import annotations

import abc
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import typing


##### CONSTANTS #####
# List of services that live in the control part of an instance
CENTRAL_SERVICES = [ "prx", "api", "drv", "plr" ]
# List of auxillary services in the control part of an instance
# At least, the ones we have to build.
AUX_CENTRAL_SERVICES = [ "xenon" ]
# List of services that live in a worker node in an instance
WORKER_SERVICES = [ "prx", "job", "reg" ]
# List of auxillary services in a worker node in an instance
AUX_WORKER_SERVICES = []

# The directory where we compile OpenSSL to
OPENSSL_DIR = "./target/openssl/$ARCH"

# The desired source files that we want to build against for OpenSSL
OPENSSL_FILES = [
    OPENSSL_DIR + "/lib/libcrypto.a", OPENSSL_DIR + "/lib/libssl.a",
    OPENSSL_DIR + "/lib/pkgconfig/libcrypto.pc", OPENSSL_DIR + "/lib/pkgconfig/libssl.pc", OPENSSL_DIR + "/lib/pkgconfig/openssl.pc",
    OPENSSL_DIR + "/include/openssl/aes.h", OPENSSL_DIR + "/include/openssl/asn1err.h", OPENSSL_DIR + "/include/openssl/asn1.h",
    OPENSSL_DIR + "/include/openssl/asn1_mac.h", OPENSSL_DIR + "/include/openssl/asn1t.h", OPENSSL_DIR + "/include/openssl/asyncerr.h",
    OPENSSL_DIR + "/include/openssl/async.h", OPENSSL_DIR + "/include/openssl/bioerr.h", OPENSSL_DIR + "/include/openssl/bio.h",
    OPENSSL_DIR + "/include/openssl/blowfish.h", OPENSSL_DIR + "/include/openssl/bnerr.h", OPENSSL_DIR + "/include/openssl/bn.h",
    OPENSSL_DIR + "/include/openssl/buffererr.h", OPENSSL_DIR + "/include/openssl/buffer.h", OPENSSL_DIR + "/include/openssl/camellia.h",
    OPENSSL_DIR + "/include/openssl/cast.h", OPENSSL_DIR + "/include/openssl/cmac.h", OPENSSL_DIR + "/include/openssl/cmserr.h",
    OPENSSL_DIR + "/include/openssl/cms.h", OPENSSL_DIR + "/include/openssl/comperr.h", OPENSSL_DIR + "/include/openssl/comp.h",
    OPENSSL_DIR + "/include/openssl/conf_api.h", OPENSSL_DIR + "/include/openssl/conferr.h", OPENSSL_DIR + "/include/openssl/conf.h",
    OPENSSL_DIR + "/include/openssl/cryptoerr.h", OPENSSL_DIR + "/include/openssl/crypto.h", OPENSSL_DIR + "/include/openssl/cterr.h",
    OPENSSL_DIR + "/include/openssl/ct.h", OPENSSL_DIR + "/include/openssl/des.h", OPENSSL_DIR + "/include/openssl/dherr.h",
    OPENSSL_DIR + "/include/openssl/dh.h", OPENSSL_DIR + "/include/openssl/dsaerr.h", OPENSSL_DIR + "/include/openssl/dsa.h",
    OPENSSL_DIR + "/include/openssl/dtls1.h", OPENSSL_DIR + "/include/openssl/ebcdic.h", OPENSSL_DIR + "/include/openssl/ecdh.h",
    OPENSSL_DIR + "/include/openssl/ecdsa.h", OPENSSL_DIR + "/include/openssl/ecerr.h", OPENSSL_DIR + "/include/openssl/ec.h",
    OPENSSL_DIR + "/include/openssl/engineerr.h", OPENSSL_DIR + "/include/openssl/engine.h", OPENSSL_DIR + "/include/openssl/e_os2.h",
    OPENSSL_DIR + "/include/openssl/err.h", OPENSSL_DIR + "/include/openssl/evperr.h", OPENSSL_DIR + "/include/openssl/evp.h",
    OPENSSL_DIR + "/include/openssl/hmac.h", OPENSSL_DIR + "/include/openssl/idea.h", OPENSSL_DIR + "/include/openssl/kdferr.h",
    OPENSSL_DIR + "/include/openssl/kdf.h", OPENSSL_DIR + "/include/openssl/lhash.h", OPENSSL_DIR + "/include/openssl/md2.h",
    OPENSSL_DIR + "/include/openssl/md4.h", OPENSSL_DIR + "/include/openssl/md5.h", OPENSSL_DIR + "/include/openssl/mdc2.h",
    OPENSSL_DIR + "/include/openssl/modes.h", OPENSSL_DIR + "/include/openssl/objectserr.h", OPENSSL_DIR + "/include/openssl/objects.h",
    OPENSSL_DIR + "/include/openssl/obj_mac.h", OPENSSL_DIR + "/include/openssl/ocsperr.h", OPENSSL_DIR + "/include/openssl/ocsp.h",
    OPENSSL_DIR + "/include/openssl/opensslconf.h", OPENSSL_DIR + "/include/openssl/opensslv.h", OPENSSL_DIR + "/include/openssl/ossl_typ.h",
    OPENSSL_DIR + "/include/openssl/pem2.h", OPENSSL_DIR + "/include/openssl/pemerr.h", OPENSSL_DIR + "/include/openssl/pem.h",
    OPENSSL_DIR + "/include/openssl/pkcs12err.h", OPENSSL_DIR + "/include/openssl/pkcs12.h", OPENSSL_DIR + "/include/openssl/pkcs7err.h",
    OPENSSL_DIR + "/include/openssl/pkcs7.h", OPENSSL_DIR + "/include/openssl/rand_drbg.h", OPENSSL_DIR + "/include/openssl/randerr.h",
    OPENSSL_DIR + "/include/openssl/rand.h", OPENSSL_DIR + "/include/openssl/rc2.h", OPENSSL_DIR + "/include/openssl/rc4.h",
    OPENSSL_DIR + "/include/openssl/rc5.h", OPENSSL_DIR + "/include/openssl/ripemd.h", OPENSSL_DIR + "/include/openssl/rsaerr.h",
    OPENSSL_DIR + "/include/openssl/rsa.h", OPENSSL_DIR + "/include/openssl/safestack.h", OPENSSL_DIR + "/include/openssl/seed.h",
    OPENSSL_DIR + "/include/openssl/sha.h", OPENSSL_DIR + "/include/openssl/srp.h", OPENSSL_DIR + "/include/openssl/srtp.h",
    OPENSSL_DIR + "/include/openssl/ssl2.h", OPENSSL_DIR + "/include/openssl/ssl3.h", OPENSSL_DIR + "/include/openssl/sslerr.h",
    OPENSSL_DIR + "/include/openssl/ssl.h", OPENSSL_DIR + "/include/openssl/stack.h", OPENSSL_DIR + "/include/openssl/storeerr.h",
    OPENSSL_DIR + "/include/openssl/store.h", OPENSSL_DIR + "/include/openssl/symhacks.h", OPENSSL_DIR + "/include/openssl/tls1.h",
    OPENSSL_DIR + "/include/openssl/tserr.h", OPENSSL_DIR + "/include/openssl/ts.h", OPENSSL_DIR + "/include/openssl/txt_db.h",
    OPENSSL_DIR + "/include/openssl/uierr.h", OPENSSL_DIR + "/include/openssl/ui.h", OPENSSL_DIR + "/include/openssl/whrlpool.h",
    OPENSSL_DIR + "/include/openssl/x509err.h", OPENSSL_DIR + "/include/openssl/x509.h", OPENSSL_DIR + "/include/openssl/x509v3err.h",
    OPENSSL_DIR + "/include/openssl/x509v3.h", OPENSSL_DIR + "/include/openssl/x509_vfy.h"
]





##### HELPER FUNCTIONS #####
def supports_color():
    """
        Returns True if the running system's terminal supports color, and False
        otherwise.

        From: https://stackoverflow.com/a/22254892
    """
    plat = sys.platform
    supported_platform = plat != 'Pocket PC' and (plat != 'win32' or
                                                  'ANSICON' in os.environ)
    # isatty is not always implemented, #6223.
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return supported_platform and is_a_tty

def wrap_description(text: str, indent: int, max_width: int, skip_first_indent: bool = False) -> str:
    """
        Wraps the given piece of text to be at most (but not including) `max_width` characters wide.

        The `indent` indicates some arbitrary amount of indent to add before each line. This is included in the total width of the line.
    """

    # Sanity check the indent
    if indent >= max_width:
        raise ValueError(f"indent must be lower than max_width (assertion {indent} < {max_width} fails)")

    # Go through the text word-by-word
    result = f"{(' ' * indent) if not skip_first_indent else ''}"
    w = indent
    for word in text.split():
        # Get the length of the word minus the ansi escaped codes
        word_len = 0
        i = 0
        while i < len(word):
            # Get the char
            c = word[i]

            # Switch on ansi escape character or not
            if c == '\033':
                c = word[i + 1]
                if c == '[':
                    # It is ansi; skip until and including the 'm'
                    j = 0
                    while i + j < len(word) and word[i + j] != 'm':
                        j += 1
                    i += 1 + j + 1

            # Go to the next char
            word_len += 1
            i += 1

        # Check if this word fits as a whole
        if w + word_len < max_width:
            # It does, add it
            result += word
            w      += word_len
        else:
            # Otherwise, always go to a new line
            result += f"\n{' ' * indent}"
            w       = indent

            # Now pop entire lines off the word if it's always too long
            while w + word_len >= max_width:
                # Write the front line worth of characters
                result += f"{word[:max_width - w]}\n{' ' * indent}"
                w       = indent
                # Shrink the word
                word      = word[max_width - w:]
                word_len -= max_width - w

            # The word *must* fit now, so write it
            result += word
            w      += word_len

        # If it still fits, add a space
        if w + 1 < max_width:
            result += ' '
            w      += 1

    # Done
    return result

def to_bytes(val: int) -> str:
    """
        Pretty-prints the given value to some byte count.
    """

    if val < 1000:
        return f"{val:.2f} bytes"
    elif val < 1000000:
        return f"{val / 1000:.2f} KB"
    elif val < 1000000000:
        return f"{val / 1000000:.2f} MB"
    elif val < 1000000000000:
        return f"{val / 1000000000:.2f} GB"
    elif val < 1000000000000000:
        return f"{val / 1000000000000:.2f} TB"
    else:
        return f"{val / 1000000000000000:.2f} PB"

def perror(text: str = "", colour: bool = True):
    """
        Writes text to stderr, as an Error.
    """

    # Get colours
    start = "\033[91;1m" if colour and supports_color() else ""
    end   = "\033[0m" if colour and supports_color() else ""

    # Print it
    print(f"{start}[ERROR] {text}{end}", file=sys.stderr)

def pwarning(text: str = "", colour: bool = True):
    """
        Writes text to srderr, as a warning string.
    """

    # Get colours
    start = "\033[93;1m" if colour and supports_color() else ""
    end   = "\033[0m" if colour and supports_color() else ""

    # Print it
    print(f"{start}[warning] {text}{end}", file=sys.stderr)

def pdebug(text: str = "", colour: bool = True):
    """
        Writes text to stdout, as a debug string.
    """

    # Skip if not debugging
    if not debug: return

    # Get colours
    start = "\033[90m" if colour and supports_color() else ""
    end   = "\033[0m" if colour and supports_color() else ""

    # Print it
    print(f"{start}[debug] {text}{end}")

def cancel(text: str = "", code = 1, colour: bool = True) -> typing.NoReturn:
    """
        Prints some error message to stderr, then quits the program by calling exit().
    """

    perror(text, colour=colour)
    exit(code)

def resolve_args(text: str, args: argparse.Namespace) -> str:
    """
        Returns the same string, but with a couple of values replaced:
        - `$RELEASE` with 'release' or 'debug' (depending on the '--dev' flag)
        - `$OS` with a default identifier for the OS (see '$RUST_OS')
        - `$RUST_OS` with a Rust-appropriate identifier for the OS (based on the '--os' flag)
        - `$ARCH` with a default identifier for the architecture (see '$RUST_ARCH')
        - `$RUST_ARCH` with a Rust-appropriate identifier for the architecture (based on the '--arch' flag)
        - `$DOCKER_ARCH` with a Docker-appropriate identifier for the architecture (based on the '--arch' flag)
        - `$JUICEFS_ARCH` with a JuiceFS-appropriate identifier for the architecture (based on the '--arch' flag)
        - `$CWD` with the current working directory (based on what `os.getcwd()` reports)
    """

    return text \
        .replace("$RELEASE", "release" if not args.dev else "debug") \
        .replace("$OS", args.os.to_rust()) \
        .replace("$RUST_OS", args.os.to_rust()) \
        .replace("$ARCH", args.arch.to_rust()) \
        .replace("$RUST_ARCH", args.arch.to_rust()) \
        .replace("$DOCKER_ARCH", args.arch.to_docker()) \
        .replace("$JUICEFS_ARCH", args.arch.to_juicefs()) \
        .replace("$CWD", os.getcwd())

def cache_outdated(args: argparse.Namespace, file: str, is_src: bool) -> bool:
    """
        Checks if the given source file/directory exists and needs
        recompilation.

        It needs recompilation if:
        - It's a directory:
          - Any of its source files (recursively) needs to be recompiled
        - It's a file:
          - The file's hash wasn't cached yet
          - The hashes of the file & directory do not match
        
        Additionally, the user will be warned if the source doesn't exist.
    """

    # Get absolute version of the hash_cache
    hash_cache = os.path.abspath(args.cache + ("/srcs" if is_src else "/dsts"))

    # Match the type of the source file
    if os.path.isfile(file):
        # It's a file; check if we know its hash
        hsrc = os.path.abspath(hash_cache + f"/{file}")
        if hsrc[:len(hash_cache)] != hash_cache: raise ValueError(f"Hash source '{hsrc}' is not in the hash cache ({hash_cache}); please do not escape it")
        if not os.path.exists(hsrc):
            pdebug(f"Cached file '{file}' marked as outdated because it has no cache entry (missing '{hsrc}')")
            return True

        # Compute the hash of the file
        try:
            with open(file, "rb") as h:
                src_hash = hashlib.md5()
                while True:
                    data = h.read(65536)
                    if not data: break
                    src_hash.update(h.read())
        except IOError as e:
            pwarning(f"Failed to read source file '{file}' for hashing: {e} (assuming target needs to be rebuild)")
            return True

        # Compare it with that in the file
        try:
            with open(hsrc, "r") as h:
                cache_hash = h.read()
        except IOError as e:
            pwarning(f"Failed to read hash cache file '{hsrc}': {e} (assuming target needs to be rebuild)")
            return True
        if src_hash.hexdigest() != cache_hash:
            pdebug(f"Cached file '{file}' marked as outdated because its hash does not match that in the cache (cache file: '{hsrc}')")
            return True

        # Otherwise, no recompilation needed
        return False

    elif os.path.isdir(file):
        # It's a dir; recurse
        for nested_file in os.listdir(file):
            if cache_outdated(args, os.path.join(file, nested_file), is_src):
                pdebug(f"Cached directory '{file}' marked as outdated because one of its children ('{nested_file}') is outdated")
                return True
        return False

    else:
        # In this case, we're sure rebuilding needs to happen (since they may be as a result from a dependency)
        pwarning(f"Cached file '{file}' is not a file or directory (is the sources/results list up-to-date?)")
        return True

def update_cache(args: argparse.Namespace, file: str, is_src: bool):
    """
        Updates the hash of the given source file in the given hash cache.
        If the src is a file, then we simply compute the hash.
        We recurse if it's a directory.
    """

    # Get absolute version of the hash_cache
    hash_cache = os.path.abspath(args.cache + ("/srcs" if is_src else "/dsts"))

    # Match the type of the source file
    if os.path.isfile(file):
        # Attempt to compute the hash
        try:
            with open(file, "rb") as h:
                src_hash = hashlib.md5()
                while True:
                    data = h.read(65536)
                    if not data: break
                    src_hash.update(h.read())
        except IOError as e:
            pwarning(f"Failed to read source file '{file}' to compute hash: {e} (compilation will likely always happen until fixed)")
            return

        # Check if the target directory exists
        hsrc = os.path.abspath(hash_cache + f"/{file}")
        if hsrc[:len(hash_cache)] != hash_cache: raise ValueError(f"Hash source '{hsrc}' is not in the hash cache ({hash_cache}); please do not escape it")
        os.makedirs(os.path.dirname(hsrc), exist_ok=True)

        # Write the hash to it
        try:
            with open(hsrc, "w") as h:
                h.write(src_hash.hexdigest())
        except IOError as e:
            pwarning(f"Failed to write hash cache to '{hsrc}': {e} (compilation will likely always happen until fixed)")

    elif os.path.isdir(file):
        # It's a dir; recurse
        for nested_file in os.listdir(file):
            update_cache(args, os.path.join(file, nested_file), is_src)

    else:
        # Warn the user
        pwarning(f"Path '{file}' not found (are the source and destination lists up-to-date?)")

def flags_changed(args: argparse.Namespace, name: str) -> bool:
    """
        Given the list of arguments, examines if the last time the given Target was compiled any relevant flags were different.

        Flags examined are:
        - `--dev`
        - `--con`
    """

    # Get absolute version of the hash_cache
    flags_cache = os.path.abspath(args.cache + "/flags")
    fsrc = flags_cache + f"/{name}"

    # If the file does not exist, then we always go on
    if not os.path.exists(fsrc):
        pdebug(f"Flags file '{fsrc}' not found; assuming target is outdated")
        return True

    # Attempt to read the cache file
    cached: dict[str, typing.Any] = {
        "dev": None,
        "con": None,
    }
    try:
        with open(fsrc, "r") as h:
            # Read line-by-line
            l = 0
            for line in h.readlines():
                l += 1

                # Attempt to split into flag/value pair
                parts = [p.strip() for p in line.split("=")]
                if len(parts) != 2:
                    pwarning(f"Line {l} in flags cache file '{fsrc}' is not a valid flag/value pair (skipping line)")
                    continue
                (flag, value) = (parts[0].lower(), parts[1])

                # See if we now this flag
                if flag not in cached:
                    pwarning(f"Line {l} in flags cache file '{fsrc}' has unknown flag '{flag}' (ignoring)")
                    continue

                # Split on the flag to parse further
                if flag == "dev":
                    cached["dev"] = value.lower() == "true"
                elif flag == "con":
                    cached["con"] = value.lower() == "true"

    except IOError as e:
        pwarning(f"Could not read flags cache file '{fsrc}': {e} (assuming target is outdated)")
        return True

    # Now compare
    for flag in cached:
        # Make sure we parsed this one
        if cached[flag] is None:
            pwarning(f"Missing flag '{flag}' in flags cache file '{fsrc}' (assuming target is outdated)")
            return True
        # Check if outdated
        if getattr(args, flag) != cached[flag]:
            pdebug(f"Flags in flags file '{fsrc}' do not match current flags; assuming target is outdated")
            return True

    # No outdating occurred
    return False

def update_flags(args: argparse.Namespace, name: str):
    """
        Updates the flag cache for the given Target to the current args dict.
    """

    # Get absolute version of the hash_cache
    flags_cache = os.path.abspath(args.cache + "/flags")

    # Set the values
    cached = {
        "dev": args.dev,
        "con": args.con,
    }

    # Write it
    fsrc = flags_cache + f"/{name}"
    os.makedirs(os.path.dirname(fsrc), exist_ok=True)
    try:
        with open(fsrc, "w") as h:
            for (flag, value) in cached.items():
                h.write(f"{flag}={value}\n")
    except IOError as e:
        pwarning(f"Could not write flags cache file '{fsrc}': {e} (recompilation will occur for this target until fixed)")

def deduce_toml_src_dirs(toml: str) -> typing.List[str] | None:
    """
        Given a Cargo.toml file, attempts to deduce the (local) source crates.

        Returns a list of the folders that are the crates on which the
        Cargo.toml depends, including the one where it lives (i.e., its
        directory-part).
    """

    res = [ os.path.dirname(toml) ]

    # Scan the lines in the file
    try:
        with open(toml, "r") as h:
            # Read it all
            text = h.read()

            # Parse
            parser = CargoTomlParser(text)
            (res, errs) = parser.parse()
            if len(errs) > 0:
                for err in errs:
                    perror(f"{err}")
                return None
            
            # Else, resolve the given paths
            for i in range(len(res)):
                res[i] = os.path.join(os.path.dirname(toml), res[i])
            # Add the cargo path
            res.append(os.path.dirname(toml))
            # Make all paths absolute
            for i in range(len(res)):
                res[i] = os.path.abspath(res[i])

            # Done
            return res

    except IOError as e:
        cancel(f"Could not read given Cargo.toml '{toml}': {e}")

def get_image_digest(path: str) -> str:
    """
        Given a Docker image .tar file, attempts to read the digest and return it.
    """

    # Open the tar file
    archive = tarfile.open(path)

    # Find the manifest file
    digest = None
    for file in archive.getmembers():
        # Skip if not the proper file
        if not file.isfile() or file.name != "manifest.json": continue

        # Attempt to read it
        f = archive.extractfile(file)
        if f is None:
            cancel(f"Failed to extract archive member '{file}' in '{path}'.")
        smanifest = f.read().decode("utf-8")
        f.close()

        # Read as json
        manifest = json.loads(smanifest)

        # Extract the config blob (minus prefix)
        config = manifest[0]["Config"]
        if config[:13] != "blobs/sha256/": cancel("Found Config in manifest.json, but blob had incorrect start (corrupted image .tar?)")
        config = config[13:]

        # Done
        digest = config

    # Throw a failure
    if digest is None:
        cancel(f"Did not find image digest in {path} (is it a valid Docker image file?)")

    # Done
    archive.close()
    return digest



##### HELPER CLASSES #####
class CargoTomlParser:
    """
        Parses a given file as if it were a Cargo.toml file.

        This is definitely not a TOML compliant-parser, though, not least of
        which because it only extracts stuff under the 'dependencies' toplevel
        section.
    """


    # Baseclasses
    class Symbol(abc.ABC):
        """
            Baseclass for all the symbols.
        """

        is_term : bool
        start   : typing.Tuple[int, int]
        end     : typing.Tuple[int, int]


        def __init__(self, is_term: bool, start: typing.Tuple[int, int], end: typing.Tuple[int, int]) -> None:
            """
                Constructor for the Symbol.

                # Arguments
                - `is_term`: Whether this Symbol is a terminal or not (it's a nonterminal).
                - `start`: The (inclusive) start position of this symbol in the text.
                - `stop`: The (inclusive) stop position of this symbol in the text.
            """

            self.is_term = is_term
            self.start   = start
            self.end     = end

        def __str__(self) -> str:
            return "Symbol"

    class Terminal(Symbol):
        """
            Baseclass for all the parser tokens.
        """

        def __init__(self, start: typing.Tuple[int, int], end: typing.Tuple[int, int]):
            """
                Constructor for the Terminal.

                # Arguments
                - `start`: The (inclusive) start position of this symbol in the text.
                - `end`: The (inclusive) stop position of this symbol in the text.
            """

            CargoTomlParser.Symbol.__init__(self, True, start, end)

        def __str__(self) -> str:
            return "Terminal"

    class Nonterminal(Symbol):
        """
            Baseclass for all the parser nonterminals.
        """

        def __init__(self, start: typing.Tuple[int, int], end: typing.Tuple[int, int]):
            """
                Constructor for the Nonterminal.

                # Arguments
                - `start`: The (inclusive) start position of this symbol in the text.
                - `end`: The (inclusive) stop position of this symbol in the text.
            """

            CargoTomlParser.Symbol.__init__(self, False, start, end)

        def __str__(self) -> str:
            return "NonTerminal"


    # Terminals
    class Identifier(Terminal):
        """
            Helper class for the CargoTomlParser which represents a string token.
        """

        value : str


        def __init__(self, value: str, start: typing.Tuple[int, int], end: typing.Tuple[int, int]) -> None:
            """
                Constructor for the String

                Arguments
                - `value`: The value of the String.
                - `start`: The start position (as (row, col), inclusive) of the token.
                - `end`: The end position (as (row, col), inclusive) of the token.
            """

            CargoTomlParser.Terminal.__init__(self, start, end)

            self.value = value

        def __str__(self) -> str:
            return f"Identifier({self.value})"

    class String(Terminal):
        """
            Helper class for the CargoTomlParser which represents a string value.
        """

        value : str


        def __init__(self, value: str, start: typing.Tuple[int, int], end: typing.Tuple[int, int]) -> None:
            """
                Constructor for the String

                Arguments
                - `value`: The value of the String.
                - `start`: The start position (as (row, col), inclusive) of the token.
                - `end`: The end position (as (row, col), inclusive) of the token.
            """

            CargoTomlParser.Terminal.__init__(self, start, end)

            self.value = value

        def __str__(self) -> str:
            return f"String({self.value})"

    class Boolean(Terminal):
        """
            Helper class for the CargoTomlParser which represents a boolean value.
        """

        value : bool


        def __init__(self, value: bool, start: typing.Tuple[int, int], end: typing.Tuple[int, int]) -> None:
            """
                Constructor for the Boolean

                Arguments
                - `value`: The value of the Boolean.
                - `start`: The start position (as (row, col), inclusive) of the token.
                - `end`: The end position (as (row, col), inclusive) of the token.
            """

            CargoTomlParser.Terminal.__init__(self, start, end)

            self.value = value

        def __str__(self) -> str:
            return f"Boolean({self.value})"

    class Equals(Terminal):
        """
            Helper class for the CargoTomlParser which represents an equals sign.
        """


        def __init__(self, start: typing.Tuple[int, int], end: typing.Tuple[int, int]) -> None:
            """
                Constructor for the Equals

                Arguments
                - `start`: The start position (as (row, col), inclusive) of the token.
                - `end`: The end position (as (row, col), inclusive) of the token.
            """

            CargoTomlParser.Terminal.__init__(self, start, end)

        def __str__(self) -> str:
            return "Equals"

    class Comma(Terminal):
        """
            Helper class for the CargoTomlParser which represents a comma.
        """


        def __init__(self, start: typing.Tuple[int, int], end: typing.Tuple[int, int]) -> None:
            """
                Constructor for the Comma

                Arguments
                - `start`: The start position (as (row, col), inclusive) of the token.
                - `end`: The end position (as (row, col), inclusive) of the token.
            """

            CargoTomlParser.Terminal.__init__(self, start, end)

        def __str__(self) -> str:
            return "Comma"

    class LCurly(Terminal):
        """
            Helper class for the CargoTomlParser which represents a left curly bracket.
        """


        def __init__(self, start: typing.Tuple[int, int], end: typing.Tuple[int, int]) -> None:
            """
                Constructor for the LCurly

                Arguments
                - `start`: The start position (as (row, col), inclusive) of the token.
                - `end`: The end position (as (row, col), inclusive) of the token.
            """

            CargoTomlParser.Terminal.__init__(self, start, end)

        def __str__(self) -> str:
            return "LCurly"

    class RCurly(Terminal):
        """
            Helper class for the CargoTomlParser which represents a right curly bracket.
        """


        def __init__(self, start: typing.Tuple[int, int], end: typing.Tuple[int, int]) -> None:
            """
                Constructor for the RCurly

                Arguments
                - `start`: The start position (as (row, col), inclusive) of the token.
                - `end`: The end position (as (row, col), inclusive) of the token.
            """

            CargoTomlParser.Terminal.__init__(self, start, end)

        def __str__(self) -> str:
            return "RCurly"

    class LSquare(Terminal):
        """
            Helper class for the CargoTomlParser which represents a left square bracket.
        """


        def __init__(self, start: typing.Tuple[int, int], end: typing.Tuple[int, int]) -> None:
            """
                Constructor for the LSquare

                Arguments
                - `start`: The start position (as (row, col), inclusive) of the token.
                - `end`: The end position (as (row, col), inclusive) of the token.
            """

            CargoTomlParser.Terminal.__init__(self, start, end)

        def __str__(self) -> str:
            return "LSquare"

    class RSquare(Terminal):
        """
            Helper class for the CargoTomlParser which represents a right square bracket.
        """


        def __init__(self, start: typing.Tuple[int, int], end: typing.Tuple[int, int]) -> None:
            """
                Constructor for the RSquare

                Arguments
                - `start`: The start position (as (row, col), inclusive) of the token.
                - `end`: The end position (as (row, col), inclusive) of the token.
            """

            CargoTomlParser.Terminal.__init__(self, start, end)

        def __str__(self) -> str:
            return "RSquare"


    # Nonterminals
    class Section(Nonterminal):
        """
            Represents a section in the TOML file.
        """

        header : CargoTomlParser.SectionHeader
        pairs  : typing.List[CargoTomlParser.KeyValuePair]


        def __init__(self, header: CargoTomlParser.SectionHeader, pairs: typing.List[CargoTomlParser.KeyValuePair], start: typing.Tuple[int, int], end: typing.Tuple[int, int]):
            """
                Constructor for the SectionHeader nonterminal.

                # Arguments
                - `header`: The header of the section.
                - `pairs`: The key/value pairs in this section.
                - `start`: The (inclusive) start position of this token.
                - `end`: The (inclusive) end position of this token.
            """

            CargoTomlParser.Nonterminal.__init__(self, start, end)

            self.header = header
            self.pairs  = pairs

        def __str__(self) -> str:
            return f"Section({self.header}, ...)"

    class SectionHeader(Nonterminal):
        """
            Represents a section header.
        """

        name : str

        def __init__(self, name: str, start: typing.Tuple[int, int], end: typing.Tuple[int, int]):
            """
                Constructor for the SectionHeader nonterminal.

                # Arguments
                - `name`: The name of the section.
                - `start`: The (inclusive) start position of this token.
                - `end`: The (inclusive) end position of this token.
            """

            CargoTomlParser.Nonterminal.__init__(self, start, end)

            self.name = name

        def __str__(self) -> str:
            return f"SectionHeader({self.name})"

    class KeyValuePair(Nonterminal):
        """
            Represents a Key/Value pair in the stack.
        """

        key   : CargoTomlParser.Identifier
        value : CargoTomlParser.Value


        def __init__(self, key: CargoTomlParser.Identifier, value: CargoTomlParser.Value, start: typing.Tuple[int, int], end: typing.Tuple[int, int]):
            """
                Constructor for the SectionHeader nonterminal.

                # Arguments
                - `key`: The key of the pair (which is an Identifier).
                - `value`: The value of the pair (which is a Value).
                - `start`: The (inclusive) start position of this token.
                - `end`: The (inclusive) end position of this token.
            """

            CargoTomlParser.Nonterminal.__init__(self, start, end)

            self.key   = key
            self.value = value

        def __str__(self) -> str:
            return f"KeyValuePair({self.key}, {self.value})"

    class Value(Nonterminal):
        """
            Abstracts away over the specific value.
        """

        value : CargoTomlParser.String | CargoTomlParser.Boolean | CargoTomlParser.List | CargoTomlParser.Dict

        def __init__(self, value: CargoTomlParser.String | CargoTomlParser.Boolean | CargoTomlParser.List | CargoTomlParser.Dict, start: typing.Tuple[int, int], end: typing.Tuple[int, int]):
            """
                Constructor for the SectionHeader nonterminal.

                # Arguments
                - `value`: The value of the Value.
                - `start`: The (inclusive) start position of this token.
                - `end`: The (inclusive) end position of this token.
            """

            CargoTomlParser.Nonterminal.__init__(self, start, end)

            self.value = value

        def __str__(self) -> str:
            return f"Value({self.value})"

    class Dict(Nonterminal):
        """
            Represents a dictionary of key/value pairs.
        """

        pairs : typing.List[CargoTomlParser.KeyValuePair]


        def __init__(self, pairs: typing.List[CargoTomlParser.KeyValuePair], start: typing.Tuple[int, int], end: typing.Tuple[int, int]):
            """
                Constructor for the SectionHeader nonterminal.

                # Arguments
                - `pairs`: The list of KeyValuePairs in this dictionary.
                - `start`: The (inclusive) start position of this token.
                - `end`: The (inclusive) end position of this token.
            """

            CargoTomlParser.Nonterminal.__init__(self, start, end)

            self.pairs = pairs

        def __str__(self) -> str:
            res = "Dict({\n"
            for p in self.pairs:
                res += f"    {p},\n"
            return res + "})"

    class List(Nonterminal):
        """
            Represents a list of values.
        """

        values : typing.List[CargoTomlParser.Value]


        def __init__(self, values: typing.List[CargoTomlParser.Value], start: typing.Tuple[int, int], end: typing.Tuple[int, int]):
            """
                Constructor for the SectionHeader nonterminal.

                # Arguments
                - `values`: The list of Values in this list.
                - `start`: The (inclusive) start position of this token.
                - `end`: The (inclusive) end position of this token.
            """

            CargoTomlParser.Nonterminal.__init__(self, start, end)

            self.values = values

        def __str__(self) -> str:
            res = "List(["
            for i, v in enumerate(self.values):
                if i > 0: res += ", "
                res += f"{v}"
            return res + "])"



    _lines : typing.List[str]
    _col   : int
    _line  : int


    def __init__(self, raw: str) -> None:
        """
            Constructor for the CargoTomlParser.

            Arguments:
            - `raw`: The raw text to parse as a Cargo.toml file.
        """

        # Initialize stuff
        self._lines = raw.split('\n')
        self._col   = 0
        self._line  = 0

    def _token(self) -> Terminal | Exception | None:
        """
            Consumes the next token from the internal text.

            If the returned value derived from an Exception, then the text is
            invalid TOML.
            If the returned value is None, then no more tokens are available.
        """

        start = (0, 0)
        buffer = ""
        mode = "start"
        while self._line < len(self._lines):
            if self._col >= len(self._lines[self._line]):
                # Update the values
                self._col = 0
                self._line += 1

                # Throw errors where it matters
                if mode == "identifier":
                    return CargoTomlParser.Identifier(buffer, start, (self._line - 1, len(self._lines[self._line - 1]) - 1))
                elif mode == "section":
                    return ValueError(f"{self._line}:{self._col}: Encountered unterminated section header (missing ']')")
                elif mode == "string":
                    return ValueError(f"{self._line}:{self._col}: Encountered unterminated string (missing '\"')")
                elif mode == "string_escape":
                    return ValueError(f"{self._line}:{self._col}: Missing escape character")
                elif mode == "comment":
                    # Go back to start mode
                    mode = "start"
            if self._line >= len(self._lines):
                break
            if self._col  >= len(self._lines[self._line]):
                continue
            c = self._lines[self._line][self._col]
            # print(f"\n >>> [{mode}] CHAR {self._line}:{self._col}: '{c}'")

            # Switch on the mode
            if mode == "start":
                start = (self._line, self._col)

                # Switch on the character
                if (ord(c) >= ord('a') and ord(c) <= ord('z')) or (ord(c) >= ord('A') and ord(c) <= ord('Z')) or c == '_':
                    # Switch to parsing an identifier token
                    mode = "identifier"
                    buffer += c
                    self._col += 1
                    continue
                elif c == '\'' or c == '"':
                    # Switch to parsing as string literal
                    mode = "string"
                    self._col += 1
                    continue
                elif c == '=':
                    # Just parse as an equals-sign
                    self._col += 1
                    return CargoTomlParser.Equals(start, start)
                elif c == ',':
                    # Just parse as a comma
                    self._col += 1
                    return CargoTomlParser.Comma(start, start)
                elif c == '{':
                    # Return the character as a token
                    self._col += 1
                    return CargoTomlParser.LCurly(start, start)
                elif c == '}':
                    # Return the character as a token
                    self._col += 1
                    return CargoTomlParser.RCurly(start, start)
                elif c == '[':
                    # Simply return the LBracket
                    self._col += 1
                    return CargoTomlParser.LSquare(start, start)
                elif c == ']':
                    # Simply return the RBracket
                    self._col += 1
                    return CargoTomlParser.RSquare(start, start)
                elif c == ' ' or c == '\t' or c == '\r':
                    # Skip
                    self._col += 1
                    continue
                elif c == '#':
                    # Comment
                    mode = "comment"
                    self._col += 1
                    continue
                else:
                    self._col += 1
                    return ValueError(f"{start[0]}:{start[1]}: Unexpected character '{c}'")

            elif mode == "identifier":
                # Switch on the character
                if (ord(c) >= ord('a') and ord(c) <= ord('z')) or \
                   (ord(c) >= ord('A') and ord(c) <= ord('Z')) or \
                   (ord(c) >= ord('0') and ord(c) <= ord('9')) or \
                    c == '-' or c == '_':
                    # Keep parsing
                    buffer += c
                    self._col += 1
                    continue
                else:
                    # Done parsing; let start handle this char

                    # If keyword, intercept that
                    if buffer == "true" or buffer == "false":
                        # It's a boolean instead
                        return CargoTomlParser.Boolean(buffer == "true", start, (self._line, self._col - 1))

                    # Otherwise, identifier
                    return CargoTomlParser.Identifier(buffer, start, (self._line, self._col - 1))

            elif mode == "string":
                # Switch on the character
                if c == '\\':
                    # Parse as escaped string
                    mode = "string_escape"
                    self._col += 1
                    continue
                elif c == '"':
                    # We're done!
                    self._col += 1
                    return CargoTomlParser.String(buffer, start, (self._line, self._col - 1))
                else:
                    # Parse as part of the token
                    buffer += c
                    self._col += 1
                    continue

            elif mode == "string_escape":
                # Switch on the character
                if c == '\\' or c == '"' or c == '\'':
                    buffer += c
                    mode = "string"
                    self._col += 1
                    continue
                elif c == 'n':
                    buffer += '\n'
                    mode = "string"
                    self._col += 1
                    continue
                elif c == 't':
                    buffer += '\t'
                    mode = "string"
                    self._col += 1
                    continue
                elif c == 'r':
                    buffer += '\r'
                    mode = "string"
                    self._col += 1
                    continue
                else:
                    # Ignore
                    perror(f"{self._line}:{self._col}: Unknown escape character '{c}' (ignoring)")
                    mode = "string"
                    self._col += 1
                    continue

            elif mode == "comment":
                # Do nothing
                self._col += 1
                continue

            else:
                raise ValueError(f"Unknown mode '{mode}'; this should never happen!")
        return None

    def _reduce(self, stack: typing.List[Symbol]) -> typing.Tuple[typing.List[Symbol], str | None | Exception]:
        """
            Attempts to apply one of the reduction rules to the current stack of tokens.

            Upon success, returns some string that identifies the rule applied.
            If no rule has been applied, returns None.
            Upon failure, returns an Exception.
        """

        # Start at the end, go backwards to identify the rules
        mode = "start"
        i = len(stack) - 1
        list_values = []
        while i >= 0:
            # Get the current symbol
            s = stack[i]

            # Match the mode
            if mode == "start":
                # Switch between token or not
                if s.is_term:
                    # Match the type of it
                    if type(s) == CargoTomlParser.RSquare:
                        # Might be a section header or a list!
                        mode = "rsquare"
                        i -= 1
                        continue

                    elif type(s) == CargoTomlParser.RCurly:
                        # Might be a dict!
                        mode = "dict"
                        i -= 1
                        continue

                    elif type(s) == CargoTomlParser.String:
                        # Immediately cast to a value
                        return (stack[:i] + [ CargoTomlParser.Value(s, s.start, s.end) ], "value_string")

                    elif type(s) == CargoTomlParser.Boolean:
                        # Immediately cast to a value
                        return (stack[:i] + [ CargoTomlParser.Value(s, s.start, s.end) ], "value_boolean")

                    else:
                        # No rule (yet)
                        return (stack, None)

                else:
                    # Match the type of it
                    if type(s) == CargoTomlParser.SectionHeader:
                        # Cast to a Section
                        return (stack[:i] + [ CargoTomlParser.Section(s, [], s.start, s.end) ], "section_header")

                    elif type(s) == CargoTomlParser.KeyValuePair:
                        # See if it is preceded by a Section
                        mode = "key_value_pair"
                        i -= 1
                        continue

                    elif type(s) == CargoTomlParser.Value:
                        # Might be a key/value pair
                        mode = "value"
                        i -= 1
                        continue

                    elif type(s) == CargoTomlParser.List:
                        # Cast to a value
                        return (stack[:i] + [ CargoTomlParser.Value(s, s.start, s.end) ], "value_list")

                    elif type(s) == CargoTomlParser.Dict:
                        # Cast to a value
                        return (stack[:i] + [ CargoTomlParser.Value(s, s.start, s.end) ], "value_dict")

                    else:
                        # No rule (yet)
                        return (stack, None)

            elif mode == "key_value_pair":
                # Switch between token or not
                if s.is_term:
                    # Ignore
                    return (stack, None)

                else:
                    # Match the type of it
                    if type(s) == CargoTomlParser.Section:
                        # Append to the section
                        s.pairs.append(typing.cast(CargoTomlParser.KeyValuePair, stack[i + 1]))
                        s.end = stack[i + 1].end
                        return (stack[:i + 1], "section_append")

                    else:
                        # No rule (yet)
                        return (stack, None)

            elif mode == "rsquare":
                # Switch between token or not
                if s.is_term:
                    # Match the type of it
                    if type(s) == CargoTomlParser.Identifier:
                        # Yes, on the road to section header!
                        mode = "rsquare_ident"
                        i -= 1
                        continue

                    elif type(s) == CargoTomlParser.LSquare:
                        # Empty list, we can only assume
                        new_l = CargoTomlParser.List([], stack[i].start, stack[i + 1].end)
                        return (stack[:i] + [ new_l ], "empty-list")

                    else:
                        # No rule (yet)
                        return (stack, None)

                else:
                    # Match the type of it
                    if type(s) == CargoTomlParser.Value:
                        # It must be the start of a list
                        mode = "list"
                        continue

                    else:
                        # No rule (yet)
                        return (stack, None)

            elif mode == "rsquare_ident":
                # Switch between token or not
                if s.is_term:
                    # Match the type of it
                    if type(s) == CargoTomlParser.LSquare:
                        # Whohoo, replace them in the stack (reduce)
                        new_sh = CargoTomlParser.SectionHeader(typing.cast(CargoTomlParser.String, stack[i + 1]).value, stack[i + 2].start, stack[i].end)
                        return (stack[:i] + [ new_sh ], "section-header")

                    else:
                        # No rule (yet)
                        return (stack, None)

                else:
                    # No rule (yet)
                    return (stack, None)

            elif mode == "dict":
                # Switch between token or not
                if s.is_term:
                    # Match the type of it
                    if type(s) == CargoTomlParser.LCurly:
                        # It's an empty dict
                        new_d = CargoTomlParser.Dict([], stack[i].start, stack[i + 1].end)
                        return (stack[:i] + [ new_d ], "empty-dict")

                    else:
                        return (stack[:i], ValueError(f"Invalid dict entry: expected a key/value pair, got {s}"))

                else:
                    # Match the type of it
                    if type(s) == CargoTomlParser.KeyValuePair:
                        # It's a key/value pair; start parsing it as such
                        list_values.append(s)
                        mode = "dict_pair"
                        i -= 1
                        continue

                    else:
                        return (stack[:i], ValueError(f"Invalid dict entry: expected a key/value pair, got {s}"))

            elif mode == "dict_pair":
                # Switch between token or not
                if s.is_term:
                    # Match the type of it
                    if type(s) == CargoTomlParser.LCurly:
                        # End of the list
                        list_values.reverse()
                        new_d = CargoTomlParser.Dict(list_values, stack[i].start, stack[len(stack) - 1].end)
                        return (stack[:i] + [ new_d ], "dict")

                    elif type(s) == CargoTomlParser.Comma:
                        # The list continious
                        mode = "dict"
                        i -= 1
                        continue

                    else:
                        return (stack[:i], ValueError(f"Invalid dict: expected ',' or '{{', got {s}"))

                else:
                    # We don't accept any nonterminals at this stage
                    return (stack[:i], ValueError(f"Invalid list: expected ',' or '[', got {s}"))

            elif mode == "list":
                # Switch between token or not
                if s.is_term:
                    # Match the type of it
                    if len(list_values) == 0 and type(s) == CargoTomlParser.LSquare:
                        # End of the list, but it is empty
                        new_l = CargoTomlParser.List([], stack[i].start, stack[i + 1].end)
                        return (stack[:i] + [ new_l ], "empty-list")

                    else:
                        return (stack[:i], ValueError(f"Invalid list entry: expected a Value, got {s}"))

                else:
                    # Match the type of it
                    if type(s) == CargoTomlParser.Value:
                        # Yes, keep parsing
                        list_values.append(typing.cast(CargoTomlParser.KeyValuePair, s))
                        mode = "list_value"
                        i -= 1
                        continue

                    else:
                        return (stack[:i], ValueError(f"Invalid list entry: expected a Value, got {s}"))

            elif mode == "list_value":
                # Switch between token or not
                if s.is_term:
                    # Match the type of it
                    if type(s) == CargoTomlParser.LSquare:
                        # End of the list
                        list_values.reverse()
                        new_l = CargoTomlParser.List(typing.cast(typing.List[CargoTomlParser.Value], list_values), stack[i].start, stack[len(stack) - 1].end)
                        return (stack[:i] + [ new_l ], "list")

                    elif type(s) == CargoTomlParser.Comma:
                        # The list continious
                        mode = "list"
                        i -= 1
                        continue

                    else:
                        return (stack[:i], ValueError(f"Invalid list: expected ',' or '[', got {s}"))

                else:
                    # We don't accept any nonterminals at this stage
                    return (stack[:i], ValueError(f"Invalid list: expected ',' or '[', got {s}"))

            elif mode == "value":
                # Switch between token or not
                if s.is_term:
                    # Match the type of it
                    if type(s) == CargoTomlParser.Equals:
                        # Yes, good going!
                        mode = "value_equals"
                        i -= 1
                        continue

                    else:
                        # No rule (yet)
                        return (stack, None)

                else:
                    # No rule (yet)
                    return (stack, None)

            elif mode == "value_equals":
                # Switch between token or not
                if s.is_term:
                    # Match the type of it
                    if type(s) == CargoTomlParser.Identifier:
                        # It's a key/value pair
                        new_kvp = CargoTomlParser.KeyValuePair(typing.cast(CargoTomlParser.Identifier, stack[i]), typing.cast(CargoTomlParser.Value, stack[i + 2]), stack[i].start, stack[i + 2].end)
                        return (stack[:i] + [ new_kvp ], "key-value-pair")

                    else:
                        # No rule (yet)
                        return (stack, None)

                else:
                    # No rule (yet)
                    return (stack, None)

            else:
                raise ValueError(f"Unknown mode '{mode}'; this should never happen!")

        # Nothing to be done
        return (stack, None)


    def parse(self) -> typing.Tuple[typing.List[str], typing.List[Exception]]:
        """
            Parses the internal Cargo.toml file to extract the list of
            dependencies from it.

            Returns a list with the depedency folders of the given Cargo.toml,
            excluding that of the Cargo.toml itself.
        """

        # Parse the tokens using a shift-reduce parser
        errs = []
        stack: typing.List[CargoTomlParser.Symbol] = []
        while True:
            # Get a new token
            token = self._token()

            # Store errors for printing
            if isinstance(token, Exception):
                errs.append(token)
                continue
            if token is None:
                break

            # Push it on the stack (shift)
            stack.append(typing.cast(CargoTomlParser.Symbol, token))
            # print("Shifted")

            # # Print the stack (debug)
            # print('[', end="")
            # for (i, s) in enumerate(stack):
            #     if i > 0: print(" ", end="")
            #     print(f"{s}", end="")
            # print(']\n'); 

            # Now, attempt to (reduce) as much as possible
            while True:
                (stack, rule) = self._reduce(stack)
                if isinstance(rule, Exception):
                    errs.append(rule)
                    continue
                if rule is None:
                    break
                # print(f"Applied rule '{rule}'")

                # # Print the stack (debug)
                # print('[', end="")
                # for (i, s) in enumerate(stack):
                #     if i > 0: print(" ", end="")
                #     print(f"{s}", end="")
                # print(']\n');

        # Now, in the parsed struct, attempt to extract the local crates
        paths = []
        for section in stack:
            # Make sure everything was parsed to a section
            if type(section) != CargoTomlParser.Section:
                errs.append(ValueError(f"Encountered stray symbol '{section}'"))
                continue

            # Ignore any non-dependency section
            if section.header.name != "dependencies" and section.header.name != "build-dependencies": continue

            # Iterate over the pairs
            for dependency in section.pairs:
                # Skip it the value is not a dict
                if type(dependency.value.value) != CargoTomlParser.Dict: continue

                # Search the dict for a 'path' identifier
                for pair in dependency.value.value.pairs:
                    if pair.key.value != "path": continue

                    # Store the found path as a dependency folder
                    paths.append(typing.cast(CargoTomlParser.String, pair.value.value).value)

        # Return the result
        return (paths, errs)



class Arch:
    """
        Defines a wrapper around architecture strings (to handle multiple
        aliases).
    """

    _arch      : str
    _is_given  : bool
    _is_native : bool


    def __init__(self) -> None:
        # Don't reall do anything; just initialize an empty object
        pass

    @staticmethod
    def new(raw: str) -> Arch:
        """
            Constructs a new Arch that is initialize from the given string.
        """

        # Get an empty object
        arch = Arch()

        # Set the given values (casting them to set strings)
        arch._arch = Arch.resolve(raw)

        # Set the properties a priori
        arch._is_given  = True
        arch._is_native = arch._arch == Arch.host()._arch

        # Done!
        return arch

    @staticmethod
    def host() -> Arch:
        """
            Returns a new Arch structure that is equal to the one running on the current machine.

            Uses "uname -m" to detect this.
        """

        # Open the process
        try:
            handle = subprocess.Popen(["uname", "-m"], stdout=subprocess.PIPE, text=True)
            stdout, _ = handle.communicate()
        except FileNotFoundError as e:
            pdebug("Failed to run `uname -m` to detect Architecture; assuming Windows")
            # Read the environment variable to find the architecture
            stdout = os.environ["PROCESSOR_ARCHITECTURE"]

        # Parse the value, put it in an empty Arch object
        arch = Arch()
        arch._arch = Arch.resolve(stdout)

        # Overrride the propreties, then return
        arch._is_given  = False
        arch._is_native = True
        return arch



    def __str__(self) -> str:
        """
            Returns the 'canonical' / human readable version of the Architecture.
        """

        return self._arch



    @staticmethod
    def resolve(text: str) -> str:
        """
            Resolves the given architecture string to a valid Arch internal string.
        """

        # Get a more forgiving version of the string
        arch = text.lower().strip()

        # Cast it to the appropriate type or error
        if arch == "x86_64" or arch == "amd64":
            return "x86_64"
        elif arch == "aarch64" or arch == "arm64":
            return "aarch64"
        else:
            raise ValueError(f"Unknown architecture '{text}'")

    def is_given(self) -> bool:
        """
            Returns whether or not the architecture is given manually or simply the host arch.
        """

        return self._is_given

    def is_native(self) -> bool:
        """
            Returns whether or not the current architecture is native.
        """

        return self._is_native



    def to_rust(self) -> str:
        """
            Returns the architecture in a way that is compatible with Rust.
        """

        return self._arch

    def to_docker(self) -> str:
        """
            Returns the architecture in a way that is compatible with Docker.
        """

        return self._arch

    def to_juicefs(self) -> str:
        """
            Returns the architecture in a way that is compatible with the JuiceFS image.
        """

        if self._arch == "x86_64": return "amd64"
        else: return "arm64"

class Os:
    """
        Defines a wrapper around an OS string.
    """

    _os        : str
    _is_given  : bool
    _is_native : bool


    def __init__(self) -> None:
        """
            Initializes an 'empty' Os object.
        """
        pass

    @staticmethod
    def new(raw: str) -> Os:
        """
            Constructor for the Os object.

            Arguments:
            - `raw`: The raw OS string to parse.
        """

        # Get an empty object
        os = Os()

        # Set the given values (casting them to set strings)
        os._os = Os.resolve(raw)

        # Set the properties a priori
        os._is_given  = True
        os._is_native = os._os == Os.host()._os

        # Done!
        return os

    @staticmethod
    def host() -> Os:
        """
            Returns a new Os structure that is equal to the one running on the current machine.

            Uses "uname -s" to detect this.
        """

        # Open the process that we use to determine the host
        try:
            handle = subprocess.Popen(["uname", "-s"], stdout=subprocess.PIPE, text=True)
            stdout, _ = handle.communicate()
        except FileNotFoundError as e:
            pdebug("Failed to run `uname -s` to detect OS; assuming Windows")
            stdout = "windows"

        # Parse the value, put it in an empty Os object
        os = Os()
        os._os = Os.resolve(stdout)

        # Overrride the propreties, then return
        os._is_given  = False
        os._is_native = True
        return os



    def __str__(self) -> str:
        """
            Returns the 'canonical' / human readable version of the Os.
        """

        return self._os



    @staticmethod
    def resolve(text: str) -> str:
        """
            Resolves the given OS string to a valid Os internal string.
        """

        # Get a more forgiving version of the string
        os = text.lower().strip()

        # Cast it to the appropriate type or error
        if os == "linux":
            return "linux"
        elif os == "darwin" or os == "macos":
            return "darwin"
        elif os == "windows":
            return "windows"
        else:
            raise ValueError(f"Unknown OS '{text}'")

    def is_given(self) -> bool:
        """
            Returns whether or not the OS is given manually or simply the host OS.
        """

        return self._is_given

    def is_native(self) -> bool:
        """
            Returns whether or not the current OS is native.
        """

        return self._is_native



    def to_rust(self) -> str:
        """
            Returns a string representation that makes sense for Rust.
        """

        return self._os



class Match(abc.ABC):
    """
        Baseclass for Match objects, which can express some condition on a string.
    """

    @abc.abstractmethod
    def __init__(self) -> None:
        # Simply init as empty (no parent stuff)
        pass

    @abc.abstractmethod
    def __str__(self) -> str:
        pass

    @abc.abstractmethod
    def match(self, _to_match: str, _args: argparse.Namespace) -> bool:
        """
            Returns whether the given string is matched by this match.
        """
        pass

class LiteralMatch(Match):
    """
        A match that matches a string literal.
    """

    _lit : str

    def __init__(self, literal: str) -> None:
        """
            Constructor for the LiteralMatch.

            Arguments:
            - `literal`: The literal to match.
        """

        # Do the parent thing
        Match.__init__(self)

        # Store the literal to match
        self._lit = literal

    def __str__(self) -> str:
        """
            Returns a string representation of this match.
        """

        return self._lit

    def match(self, to_match: str, _args: argparse.Namespace) -> bool:
        """
            Returns whether the given string is matched by this match.
        """

        # Literal matching is just... literally... matching...
        return to_match == self._lit

class StrippedMatch(Match):
    """
        Matches the given string with a literal, but only after the new string has been stripped from whitespaces.
    """

    # The literal to match.
    _lit : str

    def __init__(self, literal: str) -> None:
        """
            Constructor for the StrippedMatch.

            Arguments:
            - `literal`: The literal to match.
        """

        # Do the parent thing
        Match.__init__(self)

        # Store the literal to match
        self._lit = literal

    def __str__(self) -> str:
        """
            Returns a string representation of this match.
        """

        return self._lit

    def match(self, to_match: str, _args: argparse.Namespace) -> bool:
        """
            Returns whether the given string is matched by this match.
        """

        # Literal matching is just... literally... matching...
        return to_match.strip() == self._lit

class NegatedMatch(Match):
    """
        A match that matches using another match, then negates the result.
    """

    _match : Match

    def __init__(self, match: Match) -> None:
        """
            Constructor for the NegatedMatch.

            Arguments:
            - `match`: The other match to negate.
        """

        # Do the parent thing
        Match.__init__(self)

        # Store the literal to match
        self._match = match

    def __str__(self) -> str:
        """
            Returns a string representation of this match.
        """

        return f"Anything but '{self._match}'"

    def match(self, to_match: str, args: argparse.Namespace) -> bool:
        """
            Returns whether the given string is matched by this match.
        """

        # Match using the nested one, then negate
        return not self._match.match(to_match, args)



class Command(abc.ABC):
    """
        Baseclass for Commands, whether virtual or calling some subprocess.
    """

    @abc.abstractmethod
    def __init__(self) -> None:
        # Simply init as empty (no parent stuff)
        pass

    def serialize(self, _args: argparse.Namespace) -> str:
        """
            Allows the Command to be formatted.
        """
        pass

    @abc.abstractmethod
    def run(self, _args: argparse.Namespace) -> int:
        """
            Runs the command. Returns the 'error code', which may be some wacky
            stuff in the case of abstract commands. In any case, '0' means
            success.
        """
        pass

class ShellCommand(Command):
    """
        Command that runs some shell script.
    """

    _exec        : str
    _args        : typing.List[str]
    _cwd         : str | None
    _env         : dict[str, str | None]
    _description : str | None

    
    def __init__(self, exec: str, *args: str, cwd: str | None = None, env: dict[str, str | None] = {}, description: str | None = None) -> None:
        """
            Constructor for the Command class.

            Arguments:
            - `exec`: The executable to run.
            - `args`: An (initial) list of arguments to pass to the command.
            - `cwd`: The current working directory for the command. Note that '$CWD' still resolves to the script's directory.
            - `env`: The environment variables to set in the command. The values given here will overwrite or extend the default environment variables. To unset one, set it to 'None'.
            - `description`: If given, replaces the description with this. Use '$CMD' to have part of it replaced with the command string.
        """

        # Set the base stuff
        Command.__init__(self)

        # Populate ourselves, ez
        self._exec        = exec
        self._args        = list(args)
        self._cwd         = cwd
        self._env         = env
        self._description = description

    def serialize(self, args: argparse.Namespace) -> str:
        """
            Allows the Command to be formatted.
        """

        # Resolve the CWD
        cwd = resolve_args(self._cwd, args) if self._cwd is not None else os.getcwd()

        # Compute the cmd string
        scmd = self._exec if not " " in self._exec else f"\"{self._exec}\""
        for arg in self._args:
            arg = arg.replace("$CMD_CWD", cwd)
            arg = resolve_args(arg, args)
            scmd += " " + (arg if not " " in arg else f"\"{arg}\"").replace("\\", "\\\\").replace("\"", "\\\"")

        # Compute the env string
        env = os.environ.copy()
        senv = ""
        for (name, value) in self._env.items():
            # Mark all of these, but only the changes
            if value is not None and name in env and env[name] == value: continue
            if value is None and name not in env: continue

            # Possibly replace values
            if value is not None: value = resolve_args(value, args)
            svalue = (value if value is not None else '<unset>').replace("\\", "\\\\").replace("\"", "\\\"")

            # Add it to the string
            if len(senv) > 0: senv += " "
            senv += "{}={}".format(name, svalue if not " " in svalue else f"\"{svalue}\"")

        # If a description, return that instead
        if self._description is not None:
            # Possible replace with the command, though
            description = self._description.replace("$CMD_CWD", cwd)
            description = self._description.replace("$CMD", scmd)
            description = self._description.replace("$ENV", senv)
            return description

        # Otherwise, just return the command
        return "{}{}".format(scmd, f" (with {senv})" if len(senv) > 0 else "")



    def cwd(self, cwd: str | None) -> None:
        """
            Sets or overrides the command's CWD.
        """

        self._cwd = cwd

    def add(self, *args: str) -> None:
        """
            Appends the given (string) arguments to the list of arguments.
        """

        self._args += list(args)

    def add_env(self, *args: typing.Tuple[str, str | None]) -> None:
        """
            Sets the given (string, value) pair as an environment variable for this command.

            Use a value of 'None' to unset a value in the default environment.
        """

        # Add it, overwriting junk if necessary
        for (name, value) in args:
            self._env[name] = value



    def _prepare_run(self, args: argparse.Namespace) -> tuple[list[str], dict[str, str], str]:
        """
            Prepares running the internal command by creating the command, environment dictionary and current working directory, respectively.
        """

        # Resolve the CWD
        cwd = resolve_args(self._cwd, args) if self._cwd is not None else os.getcwd()

        # Construct the final environment
        env = os.environ.copy()
        for (name, value) in self._env.items():
            # Either insert or delete the value
            if value is not None:
                # Possibly replace values
                value = resolve_args(value, args)

                # Done
                env[name] = value
            elif name in env:
                del env[name]

        # Resolve the arguments
        rargs = [ resolve_args(arg, args) for arg in self._args ]

        # We're done
        return ([self._exec] + rargs, env, cwd)

    def run(self, args: argparse.Namespace) -> int:
        """
            Runs the command. Returns the 'error code', which may be some wacky
            stuff in the case of abstract commands. In any case, '0' means
            success.

            Note that this respects the `args.dry_run` variable.
        """

        # Prepare what we need to run
        (cmd, env, cwd) = self._prepare_run(args)

        # Start the process, but only if not dry-running
        if not args.dry_run:
            handle = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr, env=env, cwd=cwd)
            handle.wait()
            return handle.returncode
        else:
            return 0

    def run_with_capture(self, args: argparse.Namespace) -> tuple[int, str, str]:
        """
            Runs the command, returning not only the error code but also a captured stdout and stderr.

            Note that this respects the `args.dry_run` variable.
        """

        # Prepare what we need to run
        (cmd, env, cwd) = self._prepare_run(args)

        # Start the process, but only if not dry-running
        if not args.dry_run:
            handle = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=cwd)
            (stdout, stderr) = handle.communicate()
            return (handle.returncode, stdout.decode("utf-8"), stderr.decode("utf-8"))
        else:
            return (0, "", "")

class ConditionalShellCommand(Command):
    """
        Defines a shell command that is actually two commands, and the second is only executed if the first returns a specific target.
    """

    _cond   : ShellCommand
    _cons   : ShellCommand
    _code   : int
    _stdout : typing.Optional[Match]
    _stderr : typing.Optional[Match]

    def __init__(self, condition: ShellCommand, consequence: ShellCommand, target_code: int = 0, target_stdout: typing.Optional[Match] = None, target_stderr: typing.Optional[Match] = None) -> None:
        """
            Constructor for the ConditionalShellCommand.

            Arguments
            - `condition`: The command to run that determines the condition.
            - `consequence`: The command to run if the `condition` returns the desired code/stdout/stderr.
            - `target_code`: The code to match on the `condition`'s return state. If the `condition` returns anything else, the `consequence` is _not_ executed.
            - `target_stdout`: If not None, then the stdout of the command must match the given string, lest the `consequence` will not be executed. The matching strategy is dictacted by the given Match class.
            - `target_stderr`: If not None, then the stderr of the command must match the given string, lest the `consequence` will not be executed. The matching strategy is dictacted by the given Match class.
        """

        # Set the parent constructor
        Command.__init__(self)

        # Store the other commands
        self._cond   = condition
        self._cons   = consequence
        self._code   = target_code
        self._stdout = target_stdout
        self._stderr = target_stderr

    def serialize(self, args: argparse.Namespace) -> str:
        """
            Allows the Command to be formatted.
        """

        # Write the command we always run
        s = f"Running '{self._cons.serialize(args)}' iff '{self._cond.serialize(args)}' returns exit code {self._code}"
        # Add the stdout & stderr checks
        if self._stdout is not None:
            s += " and writes correct stdout"
        if self._stderr is not None:
            s += " and writes correct stderr"
        # Done
        return s

    def run(self, args: argparse.Namespace) -> int:
        """
            Runs the conditional command, then maybe runs the other command.
        """

        # Run the conditional command first, catching stdout and whatnot
        (code, stdout, stderr) = self._cond.run_with_capture(args)

        # Match it, with useful debug prints
        if code != self._code:
            pdebug(f"Not running consequent ({self._cons.serialize(args)}) because condition ({self._cond.serialize(args)}) did not return exit code {self._code} (got {code})")
            return 0
        if self._stdout is not None and not self._stdout.match(stdout, args):
            pdebug(f"Not running consequent ({self._cons.serialize(args)}) because condition ({self._cond.serialize(args)})'s stdout did not match\n\nExpected:\n{self._stdout}\n\nGot:\n{stdout}\n\n)")
            return 0
        if self._stderr is not None and not self._stderr.match(stderr, args):
            pdebug(f"Not running consequent ({self._cons.serialize(args)}) because condition ({self._cond.serialize(args)})'s stderr did not match\n\nExpected:\n{self._stderr}\n\nGot:\n{stderr}\n\n)")
            return 0

        # Now we can run the real command as usual
        return self._cons.run(args)

class MakeDirCommand(Command):
    """
        A command that runs a platform-independent directory creation.
    """

    _path      : str
    _exists_ok : bool

    def __init__(self, path: str, exists_ok: bool = True) -> None:
        """
            Constructor for the MakeDirCommand class.

            Arguments:
            - `path`: The path to the directory to create. The usual replacements apply.
            - `exists_ok`: If True, then we do not raise an error if the directory already exists.
        """

        # Set the base stuff
        Command.__init__(self)

        # Store our own arguments
        self._path      = path
        self._exists_ok = exists_ok

    def serialize(self, args: argparse.Namespace) -> str:
        """
            Allows the Command to be formatted.
        """

        return f"Creating directory '{self._path}'"

    def run(self, _args: argparse.Namespace) -> int:
        """
            Creates a directory with error catching.
        """

        # Only run if we're not dry running
        if not args.dry_run:
            try:
                os.makedirs(self._path, exist_ok=self._exists_ok)
                return 0
            except IOError as e:
                perror(f"Failed to create directory '{self._path}': {e}")
                return e.errno

class CopyCommand(Command):
    """
        A command that runs a platform-independent file copy.
    """

    _source : str
    _target : str

    def __init__(self, source: str, target: str) -> None:
        """
            Constructor for the CopyCommand.

            Arguments:
            - `source`: The source file to copy from.
            - `target`: The target file to copy to.
        """

        # Set the base stuff
        Command.__init__(self)

        # Store the paths
        self._source = source
        self._target = target

    def serialize(self, _args: argparse.Namespace) -> str:
        """
            Allows the Command to be formatted.
        """

        return f"Copying '{self._source}' to '{self._target}'"

    def run(self, args: argparse.Namespace) -> int:
        """
            Copies the given file with error catching.
        """

        # Only run if we're not dry running
        if not args.dry_run:
            try:
                shutil.copyfile(self._source, self._target)
                return 0
            except IOError as e:
                perror(f"Failed to copy '{self._source}' to '{self._target}': {e}")
                return e.errno

class PseudoCommand(Command):
    """
        A command that actually just runs some Python code when executed.
    """

    _desc : str
    _call : typing.Callable[[], int]


    def __init__(self, description: str, callback: typing.Callable[[], int]) -> None:
        """
            Constructor for the PseudoCommand class.

            Arguments:
            - `description`: The string to print when running this command.
            - `callback`: The code to run when the command is executed.
        """

        # Set the base stuff
        Command.__init__(self)

        # Populate ourselves, ez
        self._desc = description
        setattr(self, "_call", callback)

    def serialize(self, _args: argparse.Namespace) -> str:
        """
            Allows the Command to be formatted.
        """

        return self._desc



    def run(self, _args: argparse.Namespace) -> int:
        """
            Runs the command. Returns the 'error code', which may be some wacky
            stuff in the case of abstract commands. In any case, '0' means
            success.
        """

        # Simply run the callback
        return getattr(self, "_call")()





##### TARGETS #####
class Target(abc.ABC):
    """
        Virtual baseclass for all targets.
    """

    name        : str
    description : str

    _srcs      : typing.List[str]
    _srcs_deps : dict[str, typing.List[str] | None]
    _dsts      : typing.List[str]
    _deps      : typing.List[str]


    @abc.abstractmethod
    def __init__(self, name: str, srcs: typing.List[str], srcs_deps: dict[str, typing.List[str] | None], dsts: typing.List[str], deps: typing.List[str], description: str) -> None:
        """
            Baseclass constructor for the Target.

            # Arguments
            - `name`: The name of the Target.
            - `srcs`: A list of source files which the Target uses. Their state is cached, and any change to these sources will prompt a rebuild of this Target. If the list is empty, then it is assumed this information is unknown, and the Target must always be rebuild.
            - `srcs_deps`: A list of source files that are produced by a dependency. The dictionary maps dependency names to a list of source files for that dependency. If the list is 'None' instead, then we rely on all files built by the dep. Note that dep-specific behaviour may always override and tell its parents to rebuild.
            - `dsts`: A list of destination files which the Target generates. The Target may be rebuild, but any trigger of dependencies down the line is blocked if none of these files changes. If the list is empty, then it is assumed this information is unknown, and future Targets must always be rebuild.
            - `deps`: A list of dependencies for the Target. If any of these strong dependencies needs to be recompiled _any_ incurred changes, then this Target will be rebuild as well.
            - `description`: If a non-empty string, then it's a description of the target s.t. it shows up in the list of all Targets.
        """

        self.name        = name
        self.description = description

        self._srcs      = srcs
        self._srcs_deps = srcs_deps
        self._dsts      = dsts
        self._deps      = deps



    def srcs(self, args: argparse.Namespace) -> typing.List[str]:
        """
            Returns the list of source files upon which this Target relies.

            Child classes may override this method to conditionally return sources.
        """

        return [ resolve_args(s, args) for s in self._srcs ]

    def srcs_deps(self, args: argparse.Namespace) -> dict[str, typing.List[str] | None]:
        """
            Returns a dict that maps dependency-generated source files upon which this Target relies.

            Child classes may override this method to conditionally return sources.
        """

        return { dep: ((resolve_args(s, args) for s in srcs) if srcs is not None else srcs) for (dep, srcs) in self._srcs_deps.items() }

    def dsts(self, args: argparse.Namespace) -> typing.List[str]:
        """
            Returns the list of source files upon which this Target relies.

            Child classes may override this method to conditionally return sources.
        """

        return [ resolve_args(d, args) for d in self._dsts ]

    def deps(self, _args: argparse.Namespace) -> typing.List[str]:
        """
            Returns the dependencies of this Target.

            Child classes may override this method to conditionally return sources.
        """

        return self._deps



    def is_supported(self, _args: argparse.Namespace) -> str | None:
        """
            Returns whether or not the tools and such are there to build this Target.

            If the target is supported, returns None. Otherwise, returns a
            string description why this Target was not supported.
        """

        return None



    def is_outdated(self, args: argparse.Namespace) -> bool:
        """
            Checks if the Target needs to be rebuild according to the common
            changes (due to arguments or sources; dependencies are left to a
            centralized implementation for performance).

            Child classes may overload '_is_outdated()', which determines
            additional reasons for if a Target is outdated.
        """

        # The easiest way to check if a target is outdated is by examining the command-line arguments
        if args.force:
            pdebug(f"Target '{self.name}' is marked as outdated because '--force' was specified")
            return True

        # Examine if any of the sources need to be updated
        for src in self.srcs(args):
            # Resolve it
            src = resolve_args(src, args)
            # Check if it needs to be recompiled
            if cache_outdated(args, src, True):
                pdebug(f"Target '{self.name}' is marked as outdated because source file '{src}' has never been compiled or has changed since last compilation")
                return True

        # If any of the destination files is missing, that's an indication too
        for dst in self.dsts(args):
            # Resolve it
            dst = resolve_args(dst, args)
            # Check if it needs to be recompiled
            if not os.path.exists(dst):
                pdebug(f"Target '{self.name}' is marked as outdated because result file '{dst}' doesn't exist")
                return True

        # Then also check if any of the relevant flags were different
        if flags_changed(args, self.name):
            pdebug(f"Target '{self.name}' is marked as outdated because it has never been compiled before or its previous compilation was with different flags")
            return True

        # Otherwise, it's left to the child-specific implementation
        return self._is_outdated(args)

    def _is_outdated(self, _args: argparse.Namespace) -> bool:
        """
            Checks any child-specific reason for if a Target is outdated.

            If a child does not implement, then it always returns that nothing
            else is needed to check for outdatedness.
        """

        return False



    def had_effect(self, args: argparse.Namespace, files: typing.List[str] | None = None) -> bool:
        """
            Returns whether any of the destination files have changed since last compilation.

            If the given list of files is not None, then we only consider the given files, where an empty list means no files.
        """

        # Get the destination files and use the files list to reduce it
        dsts = self.dsts(args)
        if files is not None:
            new_dsts = []
            for f in files:
                f = resolve_args(f, args)
                if f not in dsts: raise ValueError(f"Target '{self.name}' does not produce file '{f}'\nInstead: {dsts}")
                new_dsts.append(f)
            dsts = new_dsts

        # Examine if any of the remaining destination's cache has become outdated
        for dst in dsts:
            # Resolve it
            dst = resolve_args(dst, args)
            # Check if it was changed
            if cache_outdated(args, dst, True):
                pdebug(f"Rebuild of target '{self.name}' is marked as having an effect because the hash of resulting file '{dst}' has changed")
                return True

        # Otherwise, check the child-dependent implementation
        return self._had_effect(args)

    def _had_effect(self, _args: argparse.Namespace) -> bool:
        """
            Checks any child-specific reason for if a Target had effect after building.

            If a child does not implement, then it always returns that nothing
            else is needed to check for outdatedness.
        """

        return False



    def deps_outdated(self, args: argparse.Namespace) -> bool:
        """
            Determines whether the files on which we depend from a dependency point of view is outdated or not.
        """

        # Simply call had_effect for all deps from which we expect source files
        for (dep_name, srcs) in self.srcs_deps(args).items():
            # Resolve the dependency
            if dep_name not in targets:
                raise ValueError(f"Unknown dependency '{dep_name}'")
            dep = targets[dep_name]

            # If the dependency changed anything of the relevant files, then we consider the deps outdated and thus this needs a rebuild
            if dep.had_effect(args, srcs): return True

        # Otherwise, check child-dependent implementation
        return self._deps_outdated(args)

    def _deps_outdated(self, _args: argparse.Namespace) -> bool:
        """
            Allows children to determine whether the deps on which we depend from a dependency point of view is outdated or not.
        """

        # By default, we assume there is nothing besides the files given
        return False



    def build(self, args: argparse.Namespace):
        """
            Builds the target, and this Target alone.

            Updates caches and such if the Target was successfull.
        """

        # Compute some colour strings
        debug_start = "\033[1m" if supports_color() else ""
        error_start = "\033[31;1m" if supports_color() else ""
        end         = "\033[0m" if supports_color() else ""

        # Get the commands to run to compile this target and execute them one-by-one
        cmds = self._cmds(args)
        for cmd in cmds:
            print(f" > {debug_start}{cmd.serialize(args)}{end}")

            # Run it
            res = cmd.run(args)
            if res != 0:
                print(f"\n{debug_start}Job '{error_start}{cmd.serialize(args)}{end}{debug_start}' failed. See output above.{end}\n", file=sys.stderr)
                exit(1)

        # Now update the sources
        srcs = self.srcs(args)
        for srcs_deps in self.srcs_deps(args).values(): srcs += srcs_deps
        for src in srcs:
            # Resolve it
            src = resolve_args(src, args)
            # Update it
            update_cache(args, src, True)

        # And the flags
        update_flags(args, self.name)

    @abc.abstractmethod
    def _cmds(self, _args: argparse.Namespace) -> typing.List[Command]:
        """
            Returns the commands to run to build the target given the given
            architecture and release mode.

            Will raise errors if it somehow fails to do so.
        """
        pass

class AbstractTarget(Target):
    """
        Defines the baseclass for abstract Targets, which do not build anything
        but instead only trigger dependencies or conditionally evaluate to
        other targets.
    """

    def __init__(self, name: str, deps: typing.List[str], description: str = "") -> None:
        """
            Constructor for the AbstractTarget.

            # Arguments
            - `name`: The name of the Target.
            - `deps`: A list of dependencies for the Target. If any of these strong dependencies needs to be recompiled _any_ incurred changes, then this Target will be rebuild as well.
            - `description`: If a non-empty string, then it's a description of the target s.t. it shows up in the list of all Targets.
        """

        # Simply call the parent constructor
        super().__init__(name, [], {}, [], deps, description)

    @abc.abstractmethod
    def redirect(self, _args: argparse.Namespace) -> Target:
        """
            Redirects this AbstractTarget to a real target that will actually be build.
        """
        pass



    def srcs(self, args: argparse.Namespace) -> typing.List[str]:
        """
            Returns the list of source files upon which this Target relies.

            Child classes may override this method to conditionally return sources.
        """

        # First, resolve this Target to its internal one
        target = self.redirect(args)
        # Run the function on that target instead
        return (target.srcs(args) if self != target else super().srcs(args))

    def srcs_deps(self, _args: argparse.Namespace) -> dict[str, typing.List[str] | None]:
        """
            Returns a dict that maps dependency-generated source files upon which this Target relies.

            Child classes may override this method to conditionally return sources.
        """

        # First, resolve this Target to its internal one
        target = self.redirect(args)
        # Run the function on that target instead
        return (target.srcs_deps(args) if self != target else super().srcs_deps(args))

    def dsts(self, _args: argparse.Namespace) -> typing.List[str]:
        """
            Returns the list of source files upon which this Target relies.

            Child classes may override this method to conditionally return sources.
        """

        # First, resolve this Target to its internal one
        target = self.redirect(args)
        # Run the function on that target instead
        return (target.dsts(args) if self != target else super().dsts(args))

    def deps(self, _args: argparse.Namespace) -> typing.List[str]:
        """
            Returns the dependencies of this Target.

            Child classes may override this method to conditionally return sources.
        """

        # First, resolve this Target to its internal one
        target = self.redirect(args)
        # Run the function on that target instead, but also add our dependencies (after it)
        return (target.deps(args) if self != target else []) + super().deps(args)



    def is_outdated(self, args: argparse.Namespace) -> bool:
        """
            Checks if the Target needs to be rebuild according to the common
            changes (due to arguments or sources; dependencies are left to a
            centralized implementation for performance).

            Child classes may overload '_is_outdated()', which determines
            additional reasons for if a Target is outdated.
        """

        # Redirect the Target
        target = self.redirect(args)
        # Delegate it to it
        return (target.is_outdated(args) if self != target else super().is_outdated(args))



    def deps_outdated(self, args: argparse.Namespace) -> bool:
        """
            Determines whether the files on which we depend from a dependency point of view is outdated or not.
        """

        # Redirect the Target
        target = self.redirect(args)
        # Delegate it to it
        return (target.deps_outdated(args) if self != target else super().deps_outdated(args))



    def had_effect(self, args: argparse.Namespace, files: typing.List[str] | None = None) -> bool:
        """
            Returns whether any of the destination files have changed since last compilation.
        """

        # Redirect the Target
        target = self.redirect(args)
        # Delegate it to it
        return (target.had_effect(args, files) if self != target else super().had_effect(args))



    def build(self, args: argparse.Namespace):
        """
            Builds the target, and this Target alone.

            Updates caches and such if the Target was successfull.
        """

        # Redirect the Target
        target = self.redirect(args)
        # Delegate it to it
        return (target.build(args) if self != target else super().build(args))



class VoidTarget(AbstractTarget):
    """
        A target that does nothing, but can be used to call dependencies.
    """


    def __init__(self, name: str, deps: typing.List[str] = [], description: str = "") -> None:
        """
            Constructor for the AbstractTarget class.

            Arguments:
            - `name`: The name of the target. Only used within the script to reference it later.
            - `deps`: A list of dependencies for the Target. If any of these strong dependencies needs to be recompiled _any_ incurred changes, then this Target will be rebuild as well.
            - `description`: If a non-empty string, then it's a description of the target s.t. it shows up in the list of all Targets.
        """

        # Simply call the parent constructor
        super().__init__(name, deps, description)

    def redirect(self, _args: argparse.Namespace) -> Target:
        """
            Redirects this AbstractTarget to a real target that will actually be build.
        """

        # No redirection needs to happen
        return self



    def _cmds(self, _args: argparse.Namespace) -> typing.List[Command]:
        """
            Returns the commands to run to build the target given the given
            architecture and release mode.

            Will raise errors if it somehow fails to do so.
        """

        # Nothing to do
        return []

class EitherTarget(AbstractTarget):
    """
        Defines a build target that can switch between two different targets based on some runtime property.
    """

    _targets  : dict[typing.Any, Target]
    _opt_name : str


    def __init__(self, name: str, opt_name: str, targets: dict[typing.Any, Target], deps: typing.List[str] = [], description: str = "") -> None:
        """
            Constructor for the EitherTarget class.

            Arguments:
            - `name`: The name of the target. Only used within the script to reference it later.
            - `opt_name`: The name of the argument in the arguments dict to switch on.
            - `targets`: The Value/Target mapping based on the given argument.
            - `deps`: A list of dependencies for the Target. If any of these strong dependencies needs to be recompiled _any_ incurred changes, then this Target will be rebuild as well.
            - `description`: If a non-empty string, then it's a description of the target s.t. it shows up in the list of all Targets.
        """

        # Set the toplevel stuff
        super().__init__(name, deps, description)

        # Set the options
        self._targets  = targets
        self._opt_name = opt_name

    def redirect(self, args: argparse.Namespace) -> Target:
        """
            Redirects this AbstractTarget to a real target that will actually be build.
        """

        # Check which one based on the given set of arguments
        val = getattr(args, self._opt_name)
        if val not in self._targets:
            raise ValueError(f"Value '{val}' is not a possible target for EitherTarget '{self.name}'")

        # No redirection needs to happen
        return self._targets[val]

    def _cmds(self, args: argparse.Namespace) -> typing.List[Command]:
        """
            Returns the commands to run to build the target given the given
            architecture and release mode.

            Will raise errors if it somehow fails to do so.
        """

        # Get the inner target
        target = self.redirect(args)

        # Use that target's `cmds()`
        return target._cmds(args)



class ShellTarget(Target):
    """
        A very simple Target that executed one or more Commands.
    """

    _commands : typing.List[Command]


    def __init__(self, name: str, commands: typing.List[Command], srcs: typing.List[str] = [], srcs_deps: dict[str, typing.List[str] | None] = {}, dsts: typing.List[str] = [], deps: typing.List[str] = [], description: str = "") -> None:
        """
            Baseclass constructor for the ShellTarget.

            # Arguments
            - `name`: The name of the Target.
            - `commands`: A list of Commands that will be executed when this Target runs.
            - `srcs`: A list of source files which the Target uses. Their state is cached, and any change to these sources will prompt a rebuild of this Target. If the list is empty, then it is assumed this information is unknown, and the Target must always be rebuild.
            - `srcs_deps`: A list of source files that are produced by a dependency. The dictionary maps dependency names to a list of source files for that dependency. If the list is 'None' instead, then we rely on all files built by the dep. Note that dep-specific behaviour may always override and tell its parents to rebuild.
            - `dsts`: A list of destination files which the Target generates. The Target may be rebuild, but any trigger of dependencies down the line is blocked if none of these files changes. If the list is empty, then it is assumed this information is unknown, and future Targets must always be rebuild.
            - `deps`: A list of dependencies for the Target. If any of these strong dependencies needs to be recompiled _any_ incurred changes, then this Target will be rebuild as well.
            - `description`: If a non-empty string, then it's a description of the target s.t. it shows up in the list of all Targets.
        """

        # Call the parent constructor for most of it
        super().__init__(name, srcs, srcs_deps, dsts, deps, description)

        # Store the commands too
        self._commands = commands



    def _is_outdated(self, _args: argparse.Namespace) -> bool:
        """
            The ShellTarget is always outdated, since we have no guarantees about what it does
        """
        pdebug(f"Target '{self.name}' is marked as outdated because it executes arbitrary commands and we don't know when to execute them")
        return True

    def _cmds(self, _args: argparse.Namespace) -> typing.List[Command]:
        """
            Returns the commands to run to build the target given the given
            architecture and release mode.

            Will raise errors if it somehow fails to do so.
        """
        
        # Simply return the list
        return self._commands

class CrateTarget(Target):
    """
        Defines a build target that relies on Cargo for build caching.
    """

    _pkgs                       : typing.List[str]
    _target                     : str | None
    _give_target_on_unspecified : bool
    _force_dev                  : bool
    _env                        : dict[str, str | None]
    _support_checker            : typing.Callable[[Target, argparse.Namespace], str | None]


    def __init__(self, name: str, packages: str | typing.List[str], target: str | None = None, give_target_on_unspecified: bool = False, force_dev: bool = False, env: dict[str, str | None] = {}, support_checker: typing.Callable[[Target, argparse.Namespace], str | None] = lambda _this, _args: None, srcs: typing.List[str] = [], srcs_deps: dict[str, typing.List[str] | None] = {}, dsts: typing.List[str] = [], deps: typing.List[str] = [], description: str = "") -> None:
        """
            Constructor for the CrateTarget class.

            Arguments:
            - `name`: The name of the target. Only used within this script to reference it later.
            - `packages`: The list of cargo packages to build for this target. Leave empty to build the default.
            - `target`: An optional target to specify if needed. Should contain '$ARCH' which will be replaced with the desired architecture.
            - `give_target_on_unspecified`: If True, does not specify '--target' in Cargo if the user did not explicitly specified so.
            - `force_dev`: If given, always builds the development binary (i.e., never adds '--release' to the Cargo command).
            - `env`: If given, overrides/adds environment variables for the build command. If set to 'None', then it unsets that environment variable instead.
            - `srcs`: A list of source files which the Target uses. Their state is cached, and any change to these sources will prompt a rebuild of this Target. If the list is empty, then it is assumed this information is unknown, and the Target must always be rebuild.
            - `srcs_deps`: A list of source files that are produced by a dependency. The dictionary maps dependency names to a list of source files for that dependency. If the list is 'None' instead, then we rely on all files built by the dep. Note that dep-specific behaviour may always override and tell its parents to rebuild.
            - `dsts`: A list of destination files which the Target generates. The Target may be rebuild, but any trigger of dependencies down the line is blocked if none of these files changes. If the list is empty, then it is assumed this information is unknown, and future Targets must always be rebuild.
            - `deps`: A list of dependencies for the Target. If any of these strong dependencies needs to be recompiled _any_ incurred changes, then this Target will be rebuild as well.
            - `description`: If a non-empty string, then it's a description of the target s.t. it shows up in the list of all Targets.
        """

        # Resolve the packages to a list (always)
        lpackages = [ packages ] if type(packages) == str else packages

        # Set the toplevel stuff
        super().__init__(name, srcs, srcs_deps, dsts, deps, description)

        # Simply set the others
        self._pkgs                       = lpackages
        self._target                     = target
        self._give_target_on_unspecified = give_target_on_unspecified
        self._force_dev                  = force_dev
        self._env                        = env
        setattr(self, "_support_checker", support_checker)



    def is_supported(self, args: argparse.Namespace) -> str | None:
        # Check if Cargo and Rust are installed
        for (name, exe) in [ ("Cargo", "cargo"), ("Rust compiler", "rustc"), ("Package config", "pkgconf") ]:
            handle = subprocess.Popen([ exe, "--version" ], text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (stdout, stderr) = handle.communicate()
            if handle.returncode != 0:
                return f"{name} ({exe}) cannot be run: {stderr}"

        # Now check for any target-specific options
        return self._support_checker(self, args)



    def _is_outdated(self, _args: argparse.Namespace) -> bool:
        """
            The CrateTarget is always outdated, since we leave it to Cargo
        """
        pdebug(f"Target '{self.name}' is marked as outdated because it relies on Cargo")
        return True

    def _cmds(self, args: argparse.Namespace) -> typing.List[Command]:
        """
            Returns the commands to run to build the target given the given
            architecture and release mode.

            Will raise errors if it somehow fails to do so.
        """

        # Start collecting the arguments for cargo
        cmd = ShellCommand("cargo", "build", env=self._env)
        if self._target is not None and (args.arch.is_given() or self._give_target_on_unspecified):
            cmd.add("--target", resolve_args(self._target, args))
        if not self._force_dev and not args.dev:
            cmd.add("--release")
        for pkg in self._pkgs:
            cmd.add("--package", pkg)

        # Done
        return [ cmd ]

class ImageTarget(Target):
    """
        Target that builds an image according to a Dockerfile.
    """

    _dockerfile  : str
    _context     : str
    _target      : str | None
    _build_args  : dict[str, str]


    def __init__(self, name: str, dockerfile: str, destination: str, context: str = ".", target: str | None = None, build_args: dict[str, str] = {}, srcs: typing.List[str] = [], srcs_deps: dict[str, typing.List[str] | None] = {}, deps: typing.List[str] = [], description: str = ""):
        """
            Constructor for the ImageTarget.

            Arguments:
            - `name`: The name of the target. Only used within this script to reference it later.
            - `dockerfile`: The location of the Dockerfile to build the image for.
            - `destination`: The path of the resulting .tar image file. May contain special strings such as '$ARCH' or '$OS'.
            - `context`: The folder used to resolve relative directories in the Dockerfile.
            - `target`: The Docker target to build in the Dockerfile. Will build the default target if omitted.
            - `build_args`: A list of build arguments to set when building the Dockerfile.
            - `srcs`: A list of source files which the Target uses. Their state is cached, and any change to these sources will prompt a rebuild of this Target. If the list is empty, then it is assumed this information is unknown, and the Target must always be rebuild.
            - `srcs_deps`: A list of source files that are produced by a dependency. The dictionary maps dependency names to a list of source files for that dependency. If the list is 'None' instead, then we rely on all files built by the dep. Note that dep-specific behaviour may always override and tell its parents to rebuild.
            - `deps`: A list of dependencies for the Target. If any of these strong dependencies needs to be recompiled _any_ incurred changes, then this Target will be rebuild as well.
            - `description`: If a non-empty string, then it's a description of the target s.t. it shows up in the list of all Targets.
        """

        # Set the super fields
        super().__init__(name, [ dockerfile ] + srcs, srcs_deps, [ destination ], deps, description)

        # Set the local fields (destination is the only destination file)
        self._dockerfile  = dockerfile
        self._context     = context
        self._target      = target
        self._build_args  = build_args



    def _cmds(self, args: argparse.Namespace) -> typing.List[Command]:
        """
            Returns the commands to run to build the target given the given
            architecture and release mode.

            Will raise errors if it somehow fails to do so.
        """

        # Resolve the destination path
        destination = resolve_args(self._dsts[0], args)

        # Add a command for the output folder
        mkdir = MakeDirCommand(os.path.dirname(destination))

        # Construct the build command
        build = ShellCommand("docker", "build", "--output", f"type=docker,dest={destination}", "-f", self._dockerfile)
        if args.arch.is_given(): build.add("--platform", args.arch.to_docker())
        if self._target is not None: build.add("--target", self._target)
        for (name, value) in self._build_args.items():
            # Resolve the value
            value = resolve_args(value, args)
            # Add it
            build.add("--build-arg", f"{name}={value}")
        build.add(self._context)

        # Return the commands to run
        return [ mkdir, build ]

class InContainerTarget(Target):
    """
        Target that builds something in a container (e.g., OpenSSL).
    """

    _image         : str
    _attach_stdin  : bool
    _attach_stdout : bool
    _attach_stderr : bool
    _keep_alive    : bool
    _volumes       : typing.List[typing.Tuple[str, str]]
    _context       : str
    _command       : typing.List[str]


    def __init__(self, name: str, image: str, attach_stdin: bool = True, attach_stdout: bool = True, attach_stderr: bool = True, keep_alive: bool = False, volumes: typing.List[typing.Tuple[str, str]] = [], context: str = ".", command: typing.List[str] = [], srcs: typing.List[str] = [], srcs_deps: dict[str, typing.List[str] | None] = {}, dsts: typing.List[str] = [], deps: typing.List[str] = [], description: str = "") -> None:
        """
            Constructor for the ImageTarget.

            Arguments:
            - `name`: The name of the target. Only used within this script to reference it later.
            - `image`: The tag of the image to run.
            - `attach_stdin`: Whether or not to attach stdin to the container's stdin.
            - `attach_stdout`: Whether or not to attach stdout to the container's stdout.
            - `attach_stderr`: Whether or not to attach stderr to the container's stderr.
            - `keep_alive`: If given, attempts to use the container as a running server instead (favouring repeated builds).
            - `volumes`: A list of volumes to attach to the container (using '-v', so note that the source path (the first argument) must be absolute. To help, you may use '$CWD'.).
            - `context`: The build context for the docker command.
            - `command`: A command to execute in the container (i.e., what will be put after its ENTRYPOINT if relevant).
            - `srcs`: A list of source files which the Target uses. Their state is cached, and any change to these sources will prompt a rebuild of this Target. If the list is empty, then it is assumed this information is unknown, and the Target must always be rebuild.
            - `srcs_deps`: A list of source files that are produced by a dependency. The dictionary maps dependency names to a list of source files for that dependency. If the list is 'None' instead, then we rely on all files built by the dep. Note that dep-specific behaviour may always override and tell its parents to rebuild.
            - `dsts`: A list of destination files which the Target generates. The Target may be rebuild, but any trigger of dependencies down the line is blocked if none of these files changes. If the list is empty, then it is assumed this information is unknown, and future Targets must always be rebuild.
            - `deps`: A list of dependencies for the Target. If any of these strong dependencies needs to be recompiled _any_ incurred changes, then this Target will be rebuild as well.
            - `description`: If a non-empty string, then it's a description of the target s.t. it shows up in the list of all Targets.
        """

        # Run the parent constructor
        super().__init__(name, srcs, srcs_deps, dsts, deps, description)

        # Add the source and targets
        self._image         = image
        self._attach_stdin  = attach_stdin
        self._attach_stdout = attach_stdout
        self._attach_stderr = attach_stderr
        self._keep_alive    = keep_alive
        self._volumes       = volumes
        self._context       = context
        self._command       = command



    def _cmds(self, args: argparse.Namespace) -> typing.List[Command]:
        """
            Returns the commands to run to build the target given the given
            architecture and release mode.

            Will raise errors if it somehow fails to do so.
        """

        # The user story is different per OS
        if platform.system() != "Windows":
            # Get the current user ID
            handle = subprocess.Popen(["id", "-u"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (stdout, stderr) = handle.communicate()
            if handle.returncode != 0: cancel(f"Failed to get current user ID using 'id -u':\n{stderr}")
            uid = stdout.strip()

            # Get the current group ID
            handle = subprocess.Popen(["id", "-g"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (stdout, stderr) = handle.communicate()
            if handle.returncode != 0: cancel(f"Failed to get current group ID using 'id -u':\n{stderr}")
            gid = stdout.strip()

            # Put it in the global variable
            user = (uid, gid)
        else:
            # We don't need to do any of this on Windows
            user = None



        # Prepare the command
        if self._keep_alive:
            # Prepare the command that actually runs the container
            start = ShellCommand("docker", "run", "--name", f"{self._image}", "-d", "--rm", "--entrypoint", "sleep")
            for (src, dst) in self._volumes:
                # Resolve the src and dst
                src = resolve_args(src, args)
                dst = resolve_args(dst, args)
                # Add
                start.add("-v", f"{src}:{dst}")
            start.add(self._image, "infinity")

            # Wrap it in a conditional command to only run it if the container is not already running (to preserve state)
            start = ConditionalShellCommand(
                # The condition checks if it's already running
                ShellCommand("docker", "ps", "-f", f"name={self._image}", "--format", "{{.Names}}"),
                # The consequent starts the container
                start,
                # We match on the name of the container, which is only given if it already runs
                target_code = 0, target_stdout = NegatedMatch(StrippedMatch(self._image)), target_stderr = None,
            )

            # # Build the start command (OS-dependent)
            # if platform.system() != "Windows":
            #     c = f"[[ $(docker ps -f \"name={self._image}\" --format '{{{{.Names}}}}') == {self._image} ]] || docker run --name {self._image} -d --rm --entrypoint sleep"
            # else:
            #     c = f"for /f \"delims=\" %i in ('docker ps -f \"name={self._image}\" --format \"{{{{.Names}}}}\"') do if \"%i\" == {self._image} docker run --name {self._image} -d --rm --entrypoint sleep"

            # # Attach any volumes to it + the container command itself
            # for (src, dst) in self._volumes:
            #     # Resolve the src and dst
            #     src = resolve_args(src, args)
            #     dst = resolve_args(dst, args)
            #     # Add
            #     c += f" -v {src}:{dst}"
            # c += f" {self._image} infinity"

            # # Start the container in the background if it didn't already
            # if platform.system() != "Windows":
            #     start = ShellCommand("bash", "-c", c)
            # else:
            #     start = ShellCommand("for ")

            # Now prepare to run the actual command within the container
            run = ShellCommand("docker", "exec", "-it", self._image, "/build.sh")
            for c in self._command:
                # Do standard replacements in the command
                c = resolve_args(c, args)
                run.add(c)
            cmds = [ start, run ]

            # If any volumes, add the commands that will restore the permissions
            for (src, _) in self._volumes:
                # Possibly replace the src
                src = resolve_args(src, args)
                # Add the command (OS-dependent)
                if type(user) == tuple:
                    cmds.append(ShellCommand("sudo", "chown", "-R", f"{user[0]}:{user[1]}", src, description=f"Restoring user permissions to '{src}' ($CMD)..."))

            # Return the commands
            return typing.cast(typing.List[Command], cmds)

        else:
            # Do a fire-and-then-remove run of the container
            cmd = ShellCommand("docker", "run", "--name", self._image)
            if self._attach_stdin: cmd.add("--attach", "STDIN")
            if self._attach_stdout: cmd.add("--attach", "STDOUT")
            if self._attach_stderr: cmd.add("--attach", "STDERR")
            for (src, dst) in self._volumes:
                # Resolve the src and dst
                src = resolve_args(src, args)
                dst = resolve_args(dst, args)
                # Add
                cmd.add("-v", f"{src}:{dst}")
            # Add the image
            cmd.add(self._image)
            # Add any commands
            for c in self._command:
                # Do standard replacements in the command
                c = resolve_args(c, args)
                cmd.add(c)
            cmds = [ cmd ]

            # If any volumes, add the command that will restore the permissions
            for (src, _) in self._volumes:
                # Possibly replace the src
                src = resolve_args(src, args)
                # Add the command (OS-dependent)
                if type(user) == tuple:
                    cmds.append(ShellCommand("sudo", "chown", "-R", f"{user[0]}:{user[1]}", src, description=f"Restoring user permissions to '{src}' ($CMD)..."))

            # Done, return it
            return typing.cast(typing.List[Command], cmds)



class InstallTarget(Target):
    """
        Target that installs something (i.e., copies it to a target system folder).
    """


    def __init__(self, name: str, source: str, target: str, dep: str, description: str = "") -> None:
        """
            Constructor for the ImageTarget.

            Arguments:
            - `name`: The name of the target. Only used within this script to reference it later.
            - `source`: The source file to copy to. May contain special parameters such as '$ARCH'.
            - `target`: The target file to copy from. May contain special parameters such as '$ARCH'.
            - `dep`: The dependenciy that will produce the source file.
            - `description`: If a non-empty string, then it's a description of the target s.t. it shows up in the list of all Targets.
        """

        # Run the parent constructor
        super().__init__(name, [], { dep: [ source ] }, [ target ], [ dep ], description)



    def _cmds(self, args: argparse.Namespace) -> typing.List[Command]:
        """
            Returns the commands to run to build the target given the given
            architecture and release mode.

            Will raise errors if it somehow fails to do so.
        """

        # Resolve the source and target paths
        source = resolve_args(typing.cast(typing.List[str], self._srcs_deps[self._deps[0]])[0], args)
        target = resolve_args(self._dsts[0], args)

        # Assert the target directory exists
        mkdir = MakeDirCommand(os.path.dirname(target))
        # Prepare the copy
        copy  = CopyCommand(source, target)

        # Done, return it
        return [ mkdir, copy ]

class InstallImageTarget(Target):
    """
        Target that installs something (i.e., copies it to a target system folder).
    """

    _tag : str


    def __init__(self, name: str, source: str, tag: str, dep: str, description: str = "") -> None:
        """
            Constructor for the ImageTarget.

            Arguments:
            - `name`: The name of the target. Only used within this script to reference it later.
            - `source`: The source location of the file to install. May contain special parameters such as '$ARCH'.
            - `tag`: The tag that will be assigned to the new image.
            - `dep`: The dependenciy that will produce the source image .tar file.
            - `description`: If a non-empty string, then it's a description of the target s.t. it shows up in the list of all Targets.
        """

        # Run the parent constructor
        super().__init__(name, [], { dep: [ source ] }, [], [ dep ], description)

        # Add the target tag (the source is stored in the general _srcs field)
        self._tag = tag



    def _cmds(self, args: argparse.Namespace) -> typing.List[Command]:
        """
            Returns the commands to run to build the target given the given
            architecture and release mode.

            Will raise errors if it somehow fails to do so.
        """

        # Resolve the source path
        source = resolve_args(typing.cast(typing.List[str], self._srcs_deps[self._deps[0]])[0], args)

        # Load the image digest
        digest = get_image_digest(source)

        # Load the image.tar into the Docker engine and tag it
        cmd = ShellCommand("docker", "load", "--input", source)
        tag = ShellCommand("docker", "tag", digest, self._tag)

        # Return them all
        return [ cmd, tag ]





##### GLOBALS #####
# Whether to print debug messages or not
debug: bool = False

# A list of deduced sources
instance_srcs = {
    f"{svc}" : deduce_toml_src_dirs(f"./brane-{svc}/Cargo.toml")
    for svc in CENTRAL_SERVICES + WORKER_SERVICES
}
for svc in instance_srcs:
    if instance_srcs[svc] is None: cancel(f"Could not auto-deduce '{svc}-image' dependencies")

# A list of all targets in the make file.
targets = {
    "test-units"  : ShellTarget("test-units",
        [ ShellCommand("cargo", "test", "--all-targets", "--all-features") ],
        description="Runs tests on the project by running the unit tests.",
    ),
    "test-clippy" : ShellTarget("test-clippy",
        [ ShellCommand("cargo", "clippy", "--all-targets", "--all-features", "--", "--allow", "clippy::manual_range_contains") ],
        description="Runs tests on the project by running the clippy linter.",
    ),
    "test-security" : ShellTarget("test-security",
        [ ShellCommand("cargo", "audit") ],
        description="Runs tests on the project by running the clippy linter.",
    ),
    "test" : VoidTarget("test",
        deps=[ "test-units", "test-clippy" ],
        description="Runs tests on the project by running both the unit tests and the clippy linter.",
    ),



    "build-image" : ImageTarget("build-image",
        "./contrib/images/Dockerfile.build", "./target/debug/build.tar",
        description="Builds the image that can be used to build Brane targets in-container.",
    ),
    "ssl-build-image" : ImageTarget("ssl-build-image",
        "./contrib/images/Dockerfile.ssl", "./target/debug/ssl-build.tar",
        description="Builds the image in which we can build OpenSSL."
    ),
    "openssl" : InContainerTarget("openssl",
        "brane-ssl-build", volumes=[("$CWD", "/build")], command=["--arch", "$ARCH"],
        dsts=OPENSSL_FILES,
        deps=["install-ssl-build-image"],
        description="Builds OpenSSL in a container to compile against when building the instance in development mode."
    ),



    "cli" : EitherTarget("cli",
        "con", {
            True  : InContainerTarget("cli-con",
                "brane-build", volumes=[ ("$CWD", "/build") ], command=["brane-cli", "--arch", "$ARCH"],
                keep_alive=True,
                dsts=["./target/containers/x86_64-unknown-linux-musl/release/brane"],
                deps=["install-build-image"],
            ),
            False : CrateTarget("cli-compiled",
                "brane-cli", target="$ARCH-unknown-linux-musl", give_target_on_unspecified=False
            ),
        },
        description = "Builds the Brane Command-Line Interface (Brane CLI). You may use '--containerized' to build it in a container."
    ),
    "ctl" : EitherTarget("ctl",
        "con", {
            True  : InContainerTarget("ctl-con",
                "brane-build", volumes=[ ("$CWD", "/build") ], command=["brane-ctl", "--arch", "$ARCH"],
                keep_alive=True,
                dsts=["./target/containers/x86_64-unknown-linux-musl/release/branectl"],
                deps=["install-build-image"],
            ),
            False : CrateTarget("ctl-compiled",
                "brane-ctl", target="$ARCH-unknown-linux-musl", give_target_on_unspecified=False,
            )
        },
        description = "Builds the Brane Command-Line Tool (Brane CTL). You may use '--containerized' to build it in a container."
    ),
    "cc" : EitherTarget("cc",
        "con", {
            True  : InContainerTarget("cc-con",
                "brane-build", volumes=[ ("$CWD", "/build") ], command=["brane-cc", "--arch", "$ARCH"],
                keep_alive=True,
                dsts=["./target/containers/x86_64-unknown-linux-musl/release/branec"],
                deps=["install-build-image"],
            ),
            False : CrateTarget("cc-compiled",
                "brane-cc", target="$ARCH-unknown-linux-musl", give_target_on_unspecified=False,
            ),
        },
        description = "Builds the Brane Command-Line Compiler (Brane CC). You may use '--containerized' to build it in a container."
    ),
    "branelet" : EitherTarget("branelet",
        "con", {
            True  : InContainerTarget("branelet-con",
                "brane-build", volumes=[ ("$CWD", "/build") ], command=["brane-let", "--arch", "$ARCH"],
                keep_alive=True,
                dsts=["./target/containers/x86_64-unknown-linux-musl/release/branelet"],
                deps=["install-build-image"],
            ),
            False : CrateTarget("branelet-compiled",
                "brane-let", target="$ARCH-unknown-linux-musl", give_target_on_unspecified=True,
            ),
        },
        description = "Build the Brane in-package executable, for use with the `build --init` command in the CLI. You may use '--containerized' to build it in a container."
    ),
    "instance" : VoidTarget("instance",
        deps=[ f"{svc}-image" for svc in CENTRAL_SERVICES ] + [ f"{svc}-image" for svc in AUX_CENTRAL_SERVICES ],
        description="Builds the container images that comprise a central node in a Brane instance."
    ),
    "worker-instance" : VoidTarget("worker-instance",
        deps=[ f"{svc}-image" for svc in WORKER_SERVICES ] + [ f"{svc}-image" for svc in AUX_WORKER_SERVICES ],
        description="Builds the container images that comprise a worker node in a Brane instance."
    ),



    "install-build-image" : InstallImageTarget("install-build-image",
        "./target/debug/build.tar", "brane-build",
        dep="build-image",
        description="Installs the build image by loading it into the local Docker engine"
    ),
    "install-ssl-build-image" : InstallImageTarget("install-ssl-build-image",
        "./target/debug/ssl-build.tar", "brane-ssl-build",
        dep="ssl-build-image",
        description="Installs the OpenSSL build image by loading it into the local Docker engine"
    ),
    "install-cli" : InstallTarget("install-cli",
        "./target/$RELEASE/brane", "/usr/local/bin/brane",
        dep="cli",
        description="Installs the CLI executable to the '/usr/local/bin' directory."
    ),
    "install-ctl" : InstallTarget("install-ctl",
        "./target/$RELEASE/branectl", "/usr/local/bin/branectl",
        dep="ctl",
        description="Installs the CTL executable to the '/usr/local/bin' directory."
    ),
    "install-cc" : InstallTarget("install-cc",
        "./target/$RELEASE/branec", "/usr/local/bin/branec",
        dep="cc",
        description="Installs the compiler executable to the '/usr/local/bin' directory."
    ),
    "install-instance" : VoidTarget("install-instance",
        deps=[ f"install-{svc}-image" for svc in CENTRAL_SERVICES ] + [ f"install-{svc}-image" for svc in AUX_CENTRAL_SERVICES ],
        description="Installs the central node of a Brane instance by loading the compiled images into the local Docker engine."
    ),
    "install-worker-instance" : VoidTarget("install-worker-instance",
        deps=[ f"install-{svc}-image" for svc in WORKER_SERVICES ] + [ f"install-{svc}-image" for svc in AUX_WORKER_SERVICES ],
        description="Installs a worker node of a Brane instance by loading the compiled images into the local Docker engine."
    ),
}

# Generate some really repetitive entries
for svc in CENTRAL_SERVICES + WORKER_SERVICES:
    # Generate the service binary targets
    targets[f"{svc}-binary-dev"] = CrateTarget(f"{svc}-binary-dev",
        f"brane-{svc}", target="$RUST_ARCH-unknown-linux-musl", give_target_on_unspecified=True, force_dev=True, env={
            "OPENSSL_DIR": "$CWD/" + OPENSSL_DIR, "OPENSSL_LIB_DIR": "$CWD/" + OPENSSL_DIR + "/lib", "RUSTFLAGS": "-C link-arg=-lgcc"
        },
        srcs_deps={ "openssl": OPENSSL_FILES },
        dsts=[ f"./target/$RUST_ARCH-unknown-linux-musl/debug/brane-{svc}" ],
        deps=[ "openssl" ],
        description=f"Builds the brane-{svc} binary in development mode. Useful if you want to run it locally or build to a development image."
    )
    # Generate the matching install target
    targets[f"install-{svc}-binary-dev"] = InstallTarget(f"install-{svc}-binary-dev",
        f"./target/$RUST_ARCH-unknown-linux-musl/debug/brane-{svc}", f"./.container-bins/$ARCH/brane-{svc}",
        dep=f"{svc}-binary-dev",
        description=f"Installs the brane-{svc} debug binary to a separate location in the repo where Docker may access it."
    )

    # Generate the service image build target
    targets[f"{svc}-image"] = EitherTarget(f"{svc}-image-build",
        "dev", {
            False : ImageTarget(f"{svc}-image-release",
                "./Dockerfile.rls", f"./target/release/brane-{svc}.tar", target=f"brane-{svc}",
                srcs=typing.cast(typing.List[str], instance_srcs[svc]),
            ),
            True  : ImageTarget(f"{svc}-image-debug",
                "./Dockerfile.dev", f"./target/debug/brane-{svc}.tar", target=f"brane-{svc}", build_args={ "ARCH": "$ARCH" },
                srcs_deps={ f"install-{svc}-binary-dev": [f"./.container-bins/$ARCH/brane-{svc}"] },
                deps=[f"install-{svc}-binary-dev"],
            ),
        },
        description=f"Builds the container image for the brane-{svc} service to a .tar file. Depending on whether '--dev' is given, it either builds a full release image or a development-optimised debug image (that copies the executable from the './.container-bins' folder instead of building it in-container). The development-optimised image prevents having to rebuild every time, but also creates much larger images."
    )
    # Generate the install targets for the image
    targets[f"install-{svc}-image"] = InstallImageTarget(f"install-{svc}-image",
        f"./target/$RELEASE/brane-{svc}.tar", f"brane-{svc}",
        dep=f"{svc}-image",
        description=f"Installs the brane-{svc} image by loading it into the local Docker engine."
    )

for svc in AUX_CENTRAL_SERVICES + AUX_WORKER_SERVICES:
    # We might do different things
    if svc == "xenon":
        # Generate the service image build target
        targets[f"{svc}-image"] = ImageTarget(f"{svc}-image",
            f"./contrib/images/Dockerfile.xenon", f"./target/$RELEASE/aux-{svc}.tar", build_args={ "JUICEFS_ARCH": "$JUICEFS_ARCH" },
            description=f"Builds the container image for the aux-{svc} auxillary service to a .tar file."
        )

        # Generate the install targets for the image
        targets[f"install-{svc}-image"] = InstallImageTarget(f"install-{svc}-image",
            f"./target/$RELEASE/aux-{svc}.tar", f"aux-{svc}",
            dep=f"{svc}-image",
            description=f"Installs the aux-{svc} image by loading it into the local Docker engine."
        )

    else:
        raise ValueError(f"Unknown auxillary service '{svc}'")





##### MAIN FUNCTIONS #####
def show_targets(args: argparse.Namespace) -> typing.NoReturn:
    """
        Shows a list of all Targets (that have a description) and then quits.
    """

    # Prepare colour strings
    bold  = "\033[1m" if supports_color() else ""
    green = "\033[32;1m" if supports_color() else ""
    red   = "\033[31;1m" if supports_color() else ""
    grey  = "\033[90m" if supports_color() else ""
    end   = "\033[0m" if supports_color() else ""

    # Sort them
    supported   : typing.List[Target] = []
    unsupported : typing.List[typing.Tuple[Target, str]] = []
    for target_name in targets:
        # Get the resolved target
        target = targets[target_name]

        # Only show them if they have a description
        if len(target.description) == 0: continue

        # Next, sort if they are supported by the current environment or not
        reason = target.is_supported(args)
        if reason is None: supported.append(target)
        else: unsupported.append((target, reason))

    # Print them neatly
    if len(supported) > 0:
        print("\nTargets supported by environment:")
        for target in supported:
            print(" - {}{}{}{}".format(green, target.name, end, f"{grey} ({type(target).__name__}){end}" if args.debug else ""))
            print(f"{wrap_description(target.description, 3, 100)}")
        print()
    if len(unsupported) > 0:
        print("\nTargets unsupported by environment:")
        for (target, reason) in unsupported:
            print(" - {}{}{}{}".format(red, target.name, end, f"{grey} ({type(target).__name__}){end}" if args.debug else ""))
            print(f"{wrap_description(target.description, 3, 100)}")
            if args.debug:
                print(f"   {grey}Reason:{end}")
                print(f"{grey}{wrap_description(reason, 3, 100)}{end}")
        print()
    if len(supported) == 0 and len(unsupported) == 0:
        print("\nNo targets found.\n")

    # Done
    exit(0)

def inspect(args: argparse.Namespace) -> typing.NoReturn:
    """
        Shows detailled information about a given target.
    """

    # Prepare colour strings
    bold  = "\033[1m" if supports_color() else ""
    green = "\033[32;1m" if supports_color() else ""
    red   = "\033[31;1m" if supports_color() else ""
    grey  = "\033[90m" if supports_color() else ""
    end   = "\033[0m" if supports_color() else ""

    # Make sure there is exactly one target
    if len(args.target) == 0:
        print(f"Missing target to inspect", file=sys.stderr)
        exit(1)
    elif len(args.target) > 1:
        print(f"Too many targets to inspect; give only one", file=sys.stderr)
        exit(1)

    # Resolve the target
    if args.target[0] not in targets:
        print(f"Unknown target '{args.target[0]}'")
        exit(1)
    target = targets[args.target[0]]

    # Collect targets properties
    srcs = target.srcs(args)
    dsts = target.dsts(args)

    # Print properties
    print()
    print(f"{bold}Target '{end}{green}{target.name}{end}{bold}':{end}")
    print(f" {grey}-{end} Type           {grey}:{end} {bold}{type(target).__name__}{end}")
    print(f" {grey}-{end} Source files   {grey}:{end} {grey}" + (wrap_description(", ".join([ f"{end}{bold}'{resolve_args(s, args)}'{end}{grey}" for s in srcs ]), 20, 100, skip_first_indent=True) if len(srcs) > 0 else "<no sources>") + f"{end}")
    print(f" {grey}-{end} Result files   {grey}:{end} {grey}" + (wrap_description(", ".join([ f"{end}{bold}'{resolve_args(d, args)}'{end}{grey}" for d in dsts ]), 20, 100, skip_first_indent=True) if len(dsts) > 0 else "<no results>") + f"{end}")
    print(f" {grey}-{end} Description    {grey}:{end} {wrap_description(target.description, 20, 100, skip_first_indent=True)}")

    # Print if supported
    reason = target.is_supported(args)
    print(f" {grey}-{end} Supported      {grey}?{end} {f'{green}yes{end}' if reason is None else f'{red}no{end}'}{end}")
    if reason is not None:
        print(f"   {grey}└>{end} Reason{grey}:{end} {wrap_description(reason, 14, 100, skip_first_indent=True)}")

    # Print the dependency tree
    print(f" {grey}-{end} Dependency tree{grey}:{end}")
    to_traverse: typing.List[typing.Tuple[typing.List[str], typing.Tuple[str, typing.List[typing.Any]]]] = [ ([], build_dependency_tree(target.name, args)) ]
    while len(to_traverse) > 0:
        # Pop the last node
        (indents, (name, node)) = to_traverse.pop()
        node.reverse()

        # Print the name with the correct depth
        print(f"   {grey}{''.join(indents[:-1] + ([ '└> ' ] if len(indents) > 0 else []))}{end}{green if name == target.name else ''}{name}{end if name == target.name else ''}")

        # Add the next nodes
        to_traverse += [(indents + [ "|  " if i > 0 else "   " ], n) for (i, n) in enumerate(node)]
    print()

    # Done
    exit(0)

def should_rebuild(args: argparse.Namespace) -> typing.NoReturn:
    """
        Using the returncode, indicates whether the given Target should be rebuild or not.
    """

    # Make sure there is exactly one target
    if len(args.target) == 0:
        print(f"Missing target to analyse rebuild status", file=sys.stderr)
        exit(1)
    elif len(args.target) > 1:
        print(f"Too many targets to analyse rebuild status; give only one", file=sys.stderr)
        exit(1)

    # Get the target
    if args.target[0] not in targets:
        print(f"Unknown target '{args.target[0]}'")
        exit(1)
    target = targets[args.target[0]]

    # Simply call the thing and check if anything needs to be done
    steps = deduce_build_steps(target.name, args)
    if len(steps) > 0:
        exit(0)
    else:
        exit(1)



def build_dependency_tree(target_name: str, args: argparse.Namespace, parent_name: str = "<root>", acyclic: set[str] = set()) -> typing.Tuple[str, typing.List[typing.Any]]:
    """
        Builds the dependency tree of the given target.

        The tree is structered as follows:
        - Every element represents a node, as a (name, branches) tuple
        - An empty branches list means a leaf
    """

    # Resolve the target and get its dependencies in all cases
    if target_name not in targets:
        raise ValueError(f"Unknown dependency '{target_name}' of '{parent_name}'")
    target = targets[target_name]
    deps   = target.deps(args)

    # Add to the list of things we've already seen
    acyclic.add(target_name)

    # Base case: no dependencies
    if len(deps) == 0:
        return (target_name, [])
    else:
        # Make sure there is no cyclic dep
        for dep in deps:
            if dep in acyclic: raise ValueError(f"Cyclic dependency detected: {dep} depends (transitively) on itself")

        # Get the dependencies of the dependencies as elements in the list
        return (target_name, [ build_dependency_tree(dep, args, parent_name=target_name, acyclic=acyclic.copy()) for dep in deps ])



def deduce_build_steps(target_name: str, args: argparse.Namespace) -> typing.List[set[typing.Tuple[Target, bool]]]:
    """
        Builds a list of things to build and the order in which to build them
        based on the target's dependency. This respects whether a Target should
        be rebuilt and whether it had any effect (leaving targets out if
        nothing is to be done).

        The order in which they are build is equal to that given in the list of
        dependencies per target. In this case, every entry may be seen as a
        'timestep', where every dependency adds one time offset (since it needs
        to be build before its parent).

        The resulting list has one entry per 'timestep'. In other words, the
        order of the nested list matters (and must be build front to back), but
        the order within the nested lists may be arbitrary.

        Aside from the list, there is also an extra buffer that may be used to
        deduce whether 

        Finally, note that if the Target itself doesn't have to be rebuild, an
        empty list is returned.
    """

    def recursive_rewrite(name: str, node: typing.List[typing.Any], wip: typing.List[set[str]], parent_name: str = "<root>", depth: int = 0):
        """
            Nested function that performs the recursive rewrite of the
            dependency tree.
        """

        # Go deeper first to add the children first
        for (dname, dnode) in node:
            recursive_rewrite(dname, dnode, wip, depth=depth + 1)

        # Next, add this package in the list with the appropriate depth
        while depth >= len(wip): wip.append(set())
        wip[depth].add(name)



    # Step 1: build a tree of all dependencies involved
    (target_name, dep_tree) = build_dependency_tree(target_name, args)



    # Step 2: rewrite the tree into the names only, separated in sets that may be done in parallel
    build_steps : typing.List[set[str]] = []
    recursive_rewrite(target_name, dep_tree, build_steps)
    build_steps.reverse()



    # Step 3: remove duplicate dependencies, leaving the chain in the oldest timesteps
    building = set()
    for step in build_steps:
        to_remove = []
        for dep in step:
            if dep in building:
                to_remove.append(dep)
            else:
                building.add(dep)
        for dep in to_remove:
            step.remove(dep)



    # Step 4: resolve to Targets and discard those that are not needed to be build
    result: typing.List[set[typing.Tuple[Target, bool]]] = []
    for step in build_steps:
        new_step = set()
        for dep_name in step:
            # Attempt to get the given dependency
            if dep_name not in targets:
                raise ValueError(f"Unknown dependency '{dep_name}'")
            rdep = targets[dep_name]

            # Add it to the new steps, together with if it needs to be rebuild or not
            # (independent of dependencies)
            new_step.add((rdep, rdep.is_outdated(args)))
        result.append(new_step)



    # Step 4: Done, return
    return result



def build_target(target_name, args) -> int:
    """
        Builds a target, returning 0 if everything was succesfull.

        This function acts as the 'main' function of the script.
    """

    # Do a warning
    if args.dry_run:
        pwarning("Simulating build only; no commands are actually run (due to '--dry-run')")

    # Get the to-be-build targets
    todo = deduce_build_steps(target_name, args)
    pdebug("To build: " + (", ".join([", ".join([f"'{target.name}'{'?' if not outdated else ''}" for (target, outdated) in step]) for step in todo]) if len(todo) > 0 else "<nothing>"))
    for step in todo:
        # Build all of these (order doesn't matter, in case we go multi-thread one day)
        for (target, outdated) in step:
            # If the target is not outdated, check if it needs to be rebuild according to its dependencies
            if not outdated and not target.deps_outdated(args): continue
            if not outdated: pdebug(f"Target '{target.name}' is marked as outdated because one of its dependencies was rebuild triggering relevant changes")

            # Otherwise, something wanted us to build it so do it
            target.build(args)

    # Success!
    return 0



# Actual entrypoint
if __name__ == "__main__":
    # Start defining the CLI arguments
    parser = argparse.ArgumentParser()

    # Define general things
    parser.add_argument("--debug", action="store_true", help="If given, whether to print debug messages (including reasons for recompilation or not)")

    # Define 'alternative commands' (i.e., they do a job and then quit)
    parser.add_argument("-t", "--targets", action="store_true", help="If given, shows a list of all supported targets, then quits.")
    parser.add_argument("-i", "--inspect", action="store_true", help="If given, shows detailled information about the given Target and then quits.")
    parser.add_argument("-r", "--should-rebuild", action="store_true", help="If given, returns whether the given Target should be rebuild or not by returning '0' as exit code if it should, and '1' if it shouldn't. Use with '--debug' to get information about what makes the Target outdated.")

    # Define things that influence the compilation mode
    parser.add_argument("target", nargs="*", help="The target to build. Use '--targets' to see a complete list.")
    parser.add_argument("--dev", "--development", action="store_true", help="If given, builds the binaries and images in development mode. This adds debug symbols to binaries, enables extra debug prints and (in the case of the instance) enables an optimized, out-of-image building procedure. Will result in _much_ larger images.")
    parser.add_argument("--con", "--containerized", action="store_true", help=f"If given, will compile (some of) the binaries in a container instead of cross-compiling them.")
    parser.add_argument("-f", "--force", action="store_true", help=f"If given, forces recompilation of all assets (regardless of whether they have been build before or not). Note that this does not clear any Cargo or Docker cache, so they might still consider your source to be cached (run `{sys.argv[0] if len(sys.argv) >= 1 else 'make.py'} clean` to clear those caches).")
    parser.add_argument("-d", "--dry-run", action="store_true", help=f"If given, skips the effects of compiling the assets, only simulating what would be done (implies '--debug').")

    # Define settings
    parser.add_argument("-o", "--os", help=f"Determines the OS for which to compile. Only relevant for the Brane-CLI. By default, will be the host's OS (host OS: '{Os.host()}')")
    parser.add_argument("-a", "--arch", help=f"The target architecture for which to compile. By default, will be the host's architecture (host architecture: '{Arch.host()}')")
    parser.add_argument("-c", "--cache", default="./target/make_cache", help="The location of the cache location for file hashes and such.")

    # Resolve arguments
    args = parser.parse_args()

    # Set the debug flag
    if args.debug:
        debug = True

    # Resolve the OS
    try:
        args.os = Os.new(args.os) if args.os is not None else Os.host()
    except ValueError:
        cancel(f"Unknown OS '{args.os}'")
    # Resolve the architecture
    try:
        args.arch = Arch.new(args.arch) if args.arch is not None else Arch.host()
    except ValueError:
        cancel(f"Unknown architecture '{args.arch}'")

    # Handle any 'alternative commands'
    if args.targets: show_targets(args)
    if args.inspect: inspect(args)
    if args.should_rebuild: should_rebuild(args)

    # Make sure there is at least one target
    if len(args.target) == 0:
        print("No target specified; nothing to do.")
        exit(0)

    # Before we begin, move the current working directory to that of the file itself
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    # Call for the given targets
    for target in args.target:
        res = build_target(target, args)
        if res != 0: exit(res)
    exit(0)
