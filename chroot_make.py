# CHROOT MAKE.py
#   by Lut99
#
# Created:
#   24 Jan 2023, 16:36:23
# Last edited:
#   24 Jan 2023, 17:02:50
# Auto updated?
#   Yes
#
# Description:
#   A script that can compile the binaries (CLI, CTL, CC) against a specific
#   GLIBC version using chroot.
#   
#   This script uses `debootstrap` to locally initialize a new Debian
#   filesystem if this has not yet been done so. Then, it will install the
#   required packages to build the Brane binaries. It will then build against
#   the target GLIBC version to be backwards compatible with previous
#   linux versions.
#   
#   Then, if the environment exists, the program executes a build command and
#   builds the requested binary.
#
#   Note that this operation can take up quite a lot of space, so it is
#   recommended to destroy the environment `./debian_chroot_glibc_<version>`
#   once finished.
#

import argparse
import os
import sys


##### GLOBALS #####
# Whether we are in debug mode or not.
DEBUG = False





##### HELPER FUNCTIONS #####
def tty_supports_colour() -> bool:
    """
        Determines whether `stdout` and `stderr` should add ANSI colour codes.

        From: https://stackoverflow.com/a/22254892

        # Returns
        True if they should, or False if they shouldn't.
    """

    plat = sys.platform
    supported_platform = plat != 'Pocket PC' and (plat != 'win32' or
                                                  'ANSICON' in os.environ)
    # isatty is not always implemented, #6223.
    is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return supported_platform and is_a_tty

def dprint(text: str):
    """
        Logs a debug statement to stdout based on whether `--debug` is given or
        not.

        # Globals
        - `DEBUG`: Reads the variable that determines if we are in debug mode.

        # Arguments
        - `text`: The text to write to the stdout.
    """

    global DEBUG
    if DEBUG:
        # Assign the colours
        start = "\033[90m" if tty_supports_colour() else ""
        end   = "\033[0m" if tty_supports_colour() else ""
        print(f"{start}[debug] {text}{end}")

def wprint(text: str):
    """
        Logs a warning message to stderr.

        # Arguments
        - `text`: The text to write to the stderr.
    """

    # Assign the colours
    start = "\033[93;1m" if tty_supports_colour() else ""
    bold  = "\033[1m" if tty_supports_colour() else ""
    end   = "\033[0m" if tty_supports_colour() else ""
    print(f"{start}[WARNING]{end} {bold}{text}{end}")

def eprint(text: str):
    """
        Logs an error message to stderr.

        # Arguments
        - `text`: The text to write to the stderr.
    """

    # Assign the colours
    start = "\033[91;1m" if tty_supports_colour() else ""
    bold  = "\033[1m" if tty_supports_colour() else ""
    end   = "\033[0m" if tty_supports_colour() else ""
    print(f"{start}[ERROR]{end} {bold}{text}{end}")





##### CHROOT FUNCTIONS #####
def build_chroot(path: str, glibc_version: str, debian_version: str) -> int:
    """
        Builds the chroot environment for the specific GLIBC version.

        # Arguments
        - `path`: The path to write the new environment to.
        - `glibc_version`: The GLIBC version to install in that environment.
        - `debian_version`: The Debian version to install.

        # Returns
        
    """





##### ENTRYPOINT #####
def main(binary: str, path: str, glibc_version: str, debian_version: str, debugging: bool) -> int:
    # Set the debugging mode
    global DEBUG
    DEBUG = debugging

    # Show a header thingy
    print()
    print("### CHROOT MAKE.py for the BRANE PROJECT ###")
    print("(Use '--help' for options)")
    print()
    print(f"Building Brane {binary.upper()} against GLIBC version {glibc_version} in a local {debian_version} filesystem using chroot ({path}).")
    print()

    # Replace the wildcards
    path = path.replace("$GLIBC_VERSION", glibc_version).replace("$DEBIAN_VERSION", debian_version)

    # Check if the given environment exists
    if os.path.exists(path):
        # Check if it is a directory
        if os.path.isdir(path):
            print("Chroot already exists")
            print("(Remove the folder and re-run the script to rebuild it)")
        else:
            # Make sure that the user allows us doing this
            dprint(f"Marking chroot as outdated because '{path}' exists but isn't a folder")
            wprint(f"'{path}' already exists but is not a folder. Overwrite?")
            while True:
                yn = input("(y/n): ")
                if yn == "y": break
                print()
                print("Aborted.")
                print()
                return 0

            # Remove the old file
            print(f"Removing '{path}'...")
            os.remove(path)

            # Build the chroot
            print("Building chroot...")
            build_chroot(glibc_version, debian_version)
    else:
        dprint(f"Marking chroot as outdated because '{path}' does not exist")
        print("Building chroot...")
        build_chroot(glibc_version, debian_version)

    # Hook the Brane source to the chroot environment

    # Enter the environment and run the build

    # Done
    print()
    print("Done.")
    print()
    return 0



# Actual entrypoint
if __name__ == "__main__":
    # Define the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("BINARY", choices=[ "cli", "ctl", "cc" ], help="The binary to build in the chroot. Uses the same naming scheme as the main `make.py` file.")
    parser.add_argument("--debug", action="store_true", help="If given, shows additional debug statements.")
    parser.add_argument("-v", "--glibc-version", default="2.28", help="The GLIBC version to build inside the environment. If you specify a version and no additional building process for GLIBC is triggered, it means that the Debian version ships this by default.")
    parser.add_argument("-d", "--debian-version", default="buster", help="The Debian version to instantiate. Should be one of the version's codenames.")
    parser.add_argument("-p", "--path", default="./$DEBIAN_VERSION_chroot_glibc_$GLIBC_VERSION", help="The location of the new chroot directory. You can use '$GLIBC_VERSION' and '$DEBIAN_VERSION' as wildcards for the specified GLIBC and Debian versions, respectively.")

    # Parse the arguments
    args = parser.parse_args()

    # Run main
    exit(main(args.BINARY, args.path, args.glibc_version, args.debian_version, args.debug))

    # sudo debootstrap --variant=buildd --arch amd64 buster ~/buster_chroot
    # sudo chroot ~/buster_chroot
    # export PATH="/bin:/sbin:/usr/bin:/usr/local/bin:/root/.cargo/bin"
