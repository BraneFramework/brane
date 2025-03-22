//  LIB.rs
//    by Lut99
//
//  Created:
//    02 Oct 2023, 12:03:47
//  Last edited:
//    02 Oct 2023, 13:39:34
//  Auto updated?
//    Yes
//
//  Description:
//!   Welcome to the Brane code documentation!
//!   
//!   On this page, you can find the auto-generated docs from [Cargo Docs](https://doc.rust-lang.org/cargo/commands/cargo-doc.html).
//!   More high-level documentation can be found at <https://wiki.enablingpersonalizedinterventions.nl>.
//!
//!   The current instance of this documentation is generated for **Linux (x86-64)**, Brane version **3.0.0**.
//!
//!   # Crate structure
//!   The crates part of this project can be found in the sidebar on the left.
//!   
//!   **Documentation-only**:  
//!   - `overview`: This crate, acting as an entrypoint to the documentation only.
//!   
//!   **Binaries**:  
//!   - `brane-cli` (named `brane` in the docs): The `brane` CLI tool, which is used by the end users of the framework (_scientists_ and _software engineers_) to interact with Brane instances.
//!   - `brane-ctl` (named `branectl` in the docs): The `branectl` CTL tool, which is used by system administrators to manage a Brane node.
//!   - `brane-cc` (named `branec` in the docs): The `branec` compiler that can compile BraneScript to the WIR (see the docs).
//!   - `brane-let` (named `branelet` in the docs): The `branelet` delegate executable that runs in Brane containers.
//!
//!   **Shared libraries**:  
//!   - `brane-cli-c`: Provides C/C++ bindings to the Brane-client part of the `brane-cli` crate.
//!
//!   **Services**:  
//!   - `brane-drv`: Implements the _driver_ service in a Brane instance, which acts as the entrypoint and the VM executing WIR-workflows.
//!   - `brane-plr`: Implements the _planner_ service in a Brane instance, which gets incomplete workflows from the driver and turns them into executable _plans_.
//!   - `brane-api`: Implement the _global registry_ service in a Brane instance, which can be used by clients and other services to query global information of the instance.
//!   - `brane-job`: Implements the _worker_ service in a Brane instance, which takes events emitted by the driver and executes them on the local domain where it is running.
//!   - `brane-reg`: Implements the _local registry_ service in a Brane instance, which can be used by other services to query domain-local information of the instance.
//!   - `brane-prx`: Implement the _proxy_ service in a Brane instance, which interface with the [BFC Framework](https://github.com/epi-project/EPIF-Configurations) and can route traffic through proxies as it travels between nodes.
//!   - `brane-log`: Unused, but used to implement a lister on Kafka channels to log events.
//!   
//!   **Libraries**:  
//!   - `brane-tsk`: Implements shared code used by the Brane VM plugins.
//!   - `brane-exe`: Implements the Brane VM that executes WIR workflows.
//!   - `brane-ast`: Defines the WIR and compiles from BraneScript to the WIR.
//!   - `brane-dsl`: Defines the BraneScript AST and a parser/scanner for parsing text to it.
//!   - `brane-cfg`: Defines configuration files (and related helpers) used by the various services and created/manipulated by `brane-ctl`.
//!   - `specifications`: Defines the "Brane interface", i.e., network structs, non-config file layouts (mostly relating to user-facing files) and outward-facing traits and enums. Also contains legacy definitions for the old workflow representation.
//!   - `brane-shr`: Defines common utilities and functions that aren't really covered by `brane-cfg` or `specifications`.
//!   - `brane-oas`: Unused, but used to implement a parser for the [Open API](https://www.openapis.org/) specification language.
//!
//!   **Graveyard**
//!   Brane also has some projects that either did not make it, were abandoned, or were replaced.
//!   Below a non-exhaustive list of those projects and what was the last version in which they
//!   were developed.
//!   - `brane-oas`: An Openapi specification crate for Brane. Removed after v3.0.0
//!
//!   **Removed modules:**
//!   brane-shr:
//!   - kafka
//!   - version
//
