# Changelog

All notable changes to the Brane framework will be documented in this file.

## [1.0.0] - 2022-11-14
**IMPORTANT NOTICE**: From now on, the framework will stick to [semantic versioning](https://semver.org). Because we are still in development, however, we will consider any API-breaking change to be any change relating to the _usage_ of the program, not to any Rust-API the library provides. However, that will likely change once the framework is more mature.

This release basically sees the release of an entirely rebuilt framework. Expect to find bugs and change of how you worked with it (especially as administrator).

### Added
- Extra example code that implements more advanced filesystem features, which may be used to inspect the shared `/data` partition at runtime.
- `brane data ...` subcommand to manage local datasets.
- `brane-ast` crate, which provides compiler methods for transforming the BraneScript/Bakery AST to the workflow representation (see below).
- `brane-exe` crate, which replaces `brane-bvm` to execute the workflow representation (see below).
- `brane-tsk` crate, which collects much of the logic in `brane-plr` and `brane-job` into a new crate that builds upon `brane-exe` to execute tasks on either offline or distributed backends (see below).
- `brane-reg` service, that is a domain-local registry of datasets (and, in the future, packages).
- TLS to data transfers. This means that setting up a domain is now marginally more complex, since certificates have to be generated.
- `unpack` as a new section in `container.yml` files, which replaces the semantics of the old `install` section (see below).
- `contrib/scripts/create_certs.sh` to generate scripts in the format that Brane wants.
- `start-central-instance.sh` and `start-worker-instance.sh` as alternative startup scripts that don't do compilation but just run already compiled images.
- Lots of BraneScript example/test files, which may be useful for understanding the language. Check `tests/branescript`.

### Changed
- The way that scripts are compiled. Instead of bytecode, the system now compiles to so-called Workflows, which is like bytecode but ordered in such a way that control flow information is preserved.
- The way data is handled. Instead of a shared filesystem, there are now specialized `Data` structs that live on a certain domain and are automatically transferred. There are also `IntermediateResults` that represent results within a workflow.
- `make.sh` into `make.py`, which is completely re-designed to be more managable and complex (especially w.r.t. deciding if recompilation is necessary or not).
- `brane push`, `brane pull` and `brane remove` to accept multiple packages to push, pull or remove respectively.
- `specifications::version::Version` to be able to parse a given `<name>:<version>` pair (which will likely be the default way of entering versions from now on).
- `docker-compose-*.yml` and `make.py` to make an explicit difference between a centralized, general control node and a domain-local worker node.
- `brane-api` now needs to have knowledge about the infrastructure too (i.e., be provided with the `infra.yml` file).
- `brane-job` to now explicitly live on a domain instead of the central node.
- the semantics of the `install` section in `container.yml` files: now, the commands are processed _before_ the workspace is copied over instead of after in order to be much nicer to Docker caching. To emulate the old behaviour, use the new `unpack` section (see above).

### Fixed
- `brane-api` not accepting 'latest' when pulling packages
- The `brane` CLI failing to run a pulled package.
- Keywords in BraneScript being parsed as such when part of an identifier (i.e., 'new_a' would error because of 'new').
- Lockfiles not always being removed during builds (especially things like interruptions).
- Other BraneScript issues.

### Known bugs
- The framework cannot currently connect to domains that are accessed by IP instead of hostname (resulting in TLS errors; check [this issue](https://github.com/seanmonstar/reqwest/issues/1328)).
- The lock file is not _always_ always removed; more work is necessary.

## [0.6.3] - 2022-05-31
### Added
- Tests for various opcodes in the VM. More will follow in due time.
- `brane run` can now run from stdin by passing `-` as filename.

### Changed
- JuiceFS is now downloaded again instead of being compiled for packages & `once-format`.
- `make.sh` now expects releases to put `brane` instance services into an archive.

### Fixed
- Comparisons being the other way around (i.e., `1 < 2` returned `false` and `1 > 2` returned `true`).
- Comparing two strings with the same value (but different strings) still returning false.
- Running any for-loop causing the next statement to fail with 'VM not in a state to accept main function.'
- Any erronous statement causing the next statement to fail with 'VM not in a state to accept main function.'
- Some arrays crashing the VM with 'Could not resolve type of Array', even though it was a valid Array.

## [0.6.2] - 2022-05-23
### Added
- Better documentation to the `hello_world` example.
- `base64` tutorial code (for the [documentation](https://wiki.enablingpersonalizedinterventions.nl/user-guide/software-engineers/base64.html))
- `filesystem` tutorial code (for the [documentation](https://wiki.enablingpersonalizedinterventions.nl/user-guide/software-engineers/filesystem.html))
- `github` tutorial code (for the [documentation](https://wiki.enablingpersonalizedinterventions.nl/user-guide/software-engineers/github.html))
- Support to compile packages for different architectures than the current host using the `--arch` flag. Check the documentation to learn more about dependencies.
  - Note: cross-compilation does not yet work on M1 macs (due to the [multi-arch image](https://github.com/multiarch/qemu-user-static) [not supporting non-x86_64 hosts](https://github.com/multiarch/qemu-user-static#supported-host-architectures))
- Support to compile the framework for different architectures using the `--arch` flag in `make.sh`. Check the documentation to learn more about dependencies.
  - Note: cross-compilation does not yet work on M1 macs (due to the [multi-arch image](https://github.com/multiarch/qemu-user-static) [not supporting non-x86_64 hosts](https://github.com/multiarch/qemu-user-static#supported-host-architectures))
- Support for building the images using pre-compiled binaries, either downloaded from Github or by manually supplying them.

### Changed
- From now on, much more binaries will be tied to each release which the `make.sh` script may download.

### Fixed
- Shared Redis filesystem not working on Kubernetes clusters due to wrong URLs being passed in the `once-format` job.
- clippy failing again.

## [0.6.1] - 2022-05-13
### Added
- The code of the "Hello, world!" example in the documentation.

### Changed
- `brane-drv`, `brane-job` and `brane-plr` services to accept `infra.yml` and `secrets.yml` via a shared folder again.
- `brane test` no longer printing useless 'Please provide input for the chosen function' statement if the function has no inputs.
- The `kube` dependencies in `brane-job` to be pushed to `0.72`, and bumping Kube API version to 1.23.

### Fixed
- An issue with the `brane-cli` dependency checker where it would fail if it cannot read the Docker Buildx version. This is now patched to be a) slightly more free in what it can parse, and b) not error anymore when it sees an invalid version number but throw a warning instead.

## [0.6.0] - 2022-05-08
### Added
- Garbage collection to custom Heap backend.
- `version` command to brane-cli.
- '/version/ path to Brane-API, to query instance version (which is what `brane version` does if logged-in).
- Script to automatically* generate Kubernetes deployment files.
  - *It still requires a few adaptations to make it work, and only works on Linux (not macOS).
- Possibility to deploy the control plane on a Kubernetes cluster.

### Changed
- Branelet, brane-drv, brane-clb and brane-job to allow for much more feedback to reported to the user (when the job returns non-zero exit codes, when branelet fails to launch, ...).
- Opcodes to be an enum, allowing more streamlined conversion to names and changing opcode numbers.
- The 'build' and 'import' subcommands to be much more verbose in errors (especially in referenced files in container.yml).
- The 'build' and 'import' to use '--workdir' instead of '--context', also changing its behaviour to a more intuitive version.
- The organisation of utils.rs in brane-cli (includes commonly used functions from package.rs + its own error enum).
- The Makefile to a Bash script (`./make.sh`) with much of the same functionality, except that is has better rebuild checking and CLI support.
- Code structure of bytecode.rs, frames.rs, objects.rs and stack.rs in brane-bvm.
- Handles in the Heap backend completely, so they can now be used without being passed a Heap object.
- The PackageInfo / ContainerInfo files to now have OpenAPI document / ContainerInfo as user interface, PackageInfo as general backend metadata and LocalContainerInfo as image-local file for branelet.
- The brane-cli directory utilities to not automatically create directories anymore (we have separate functions for that now).
- Some crates to use clap again, as we finally found the issue (missing 'env' feature).
- Merged `docker-compose-svc.yml` and `docker-compose-brn.yml` into one file to properly express dependencies.
- Changed location of some in-container build scripts to `contrib/scripts/`.
- The compilation process to have more overview and achieve better build speeds (especially for release builds).
- Various default service ports to more obscure and (hopefully) unused ones (e.g., registry now has port `50050` instead of `5000`).

### Fixed
- Tests not compiling.
- OP_PARALLEL being disabled; it's now working again as expected.
- The Brane executable making files instead of directories when making standard config directories.
- Docker not refreshing images with the same version after building them or pushing them.
- brane-job not passing the 'debug' flag to branelet.
- small issues that prevented [brane-ide](https://github.com/epi-project/brane) from working.
- brane-drv crashing when receiving out-of-order status update messages.
- `kube` location kind, so it's now working and tested again.

## [0.5.0] - 2022-02-10
### Added
- '/health' path in brane-api to follow tutorial more closely.
- Names for Brane service containers to allow more easy interaction.
- A lot of additional error catching and reporting across the entire project (but still a lot to do).
- VM now properly returning internal errors to the user (when running either locally or remotely).

### Changed
- The project is now being worked on by a new owner (Tim, pleased to meet you).
- Version can now be omitted when pushing, defaulting to the latest version instead.
- Version can now be specified more intuitively when removing a package.
- Streamlined naming of 'ecu' packages; all naming of them as 'code' has been changed to 'ecu'.
- Compiling Brane for development purposes. It's now possible to cross-compile locally on a shared Docker partition (saving a lot of time on macOS), meaning that it doesn't have to rebuild from scratch every time the containers are launched.
- Brane-bvm's heap backend to a custom one, because the old one did not play well with threads and parallelism.
- OP_PARALLEL to be temporarily disabled due to new heap.

### Fixed
- Clamp not compiling anymore; using StructOpt in most cases instead
- Branelet not being able to run OpenAPI package properly due to incorrectly replacing URL values (expected '{' and '}', but actually got '%7B' and '%7D').
- Containers not being able to reach each other due to incorrect IPs (most assumed '127.0.0.1', but this only worked for thing outside of Docker).
- Brane-job causing the Docker engine to connect to '127.0.0.1:5000/127.0.0.1:5000'; removed one of the two hostnames (specifically, the one in brane-job itself).
- Network 'kind' not being found; changed it to 'brane' in the default infra.yml, as this is also the network name used in the Docker Compose files.
- The type of an Array not being resolved properly, causing to error down the line due to incompatible types (while they in fact are).
- VM crashing whenever the job returned no output.

## [0.4.1] - 2021-08-16
### Fixed
- Disable debug logging from within WaitUntil future.
- Always use offset of at least 1 for nested call frames.
- Uniformly handle local and remote jobs.
- Propagate debug, stdout, and stderr output from driver to client.
- Construct package index from graphql endpoint.
- Missing scylla address in docker-compose-brn.yml

## [0.4.0] - 2021-08-11
### Added
- BraneScript, an alternative to Bakery with more a C-like syntax.
- GraphQL endpoint for querying application event logs, including subscriptions.
- Initial support for proxies and bridge functions: `brane-net`.
- Allow checkout folder name to be different than 'brane' (by [romnn](https://github.com/romnn)).
- Automated (daily) audits and multi-platform builds using GitHub actions.
- Optional flag to keep temporary package build files.
- Automatically add `token` and `server` arguments for OAS functions. 

### Changed
- Use seperate service for scheduling functions: `brane-job`.
- Use seperate library for OpenAPI support: `brane-oas`.
- REPL is now based on the `rustyline` library.
- Use gRPC for drivers (REPL and Jupyter kernel).
- Switched from Cassandra to ScyllaDB, and removed PostgreSQL dependency.
- DSL implementation is based on parser combinatorics, with `nom`.
- Switched from `actix` to `warp` as the framework for `brane-api`.

### Fixed
- Minor fixes for the word count quickstart.
- Correctly convert between DSL values and specification values.

## [0.3.0] - 2021-03-03
### Added
- Generate convenience function for CWL workflows with a single required parameter.
- `run` command to run DSL script from files. 
- `import` command to import packages from a GitHub repository.
- JupyterLab-based registry viewer.

## Changed
- The `import` DSL statement accepts multiple packages on the same line.
- Optional properties do not have to be specified while creating an object in the DSL.
- Cell output shows progress indicator and has time statistics.

## [0.2.0] - 2020-12-15
### Added
- Contributing guide, code of conduct, and issue templates (bug & feature).
- LOFAR demonstration
- Session attach/detach mechanism in JupyterLab.
- Custom renderers in JupyterLab.

### Changed
- Docker, HPC (Xenon), and Kubernetes runners are now configurable.
- Removing a package also removes it locally from Docker.
- CWL packages are now also locally testable.

### Fixed
- Various bug fixes and improvements.
- Allow pointers when creating arrays and objects in Bakery.

## [0.1.0] - 2020-06-04
### Added
- Initial implementation.
