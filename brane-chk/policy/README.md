# `brane-chk` interface policy
This directory contains the base policy that acts as an interface between user-written policy and the system's information.

In particular, it defines common concepts about the system (e.g., workflows, users, etc) such that the checker can automatically inject Facts about the current state in a manner consistent with what the user expects.

The [`main.eflint`](./main.eflint) file defines the entrypoint that collects the other files in the proper order. Start there, and follow `#require`s to find the structure of the base policy.
