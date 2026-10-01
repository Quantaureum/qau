# Encrypted TSS state snapshots

The manager's current snapshot payload starts with `QTSSSTATE02`. The outer
encrypted envelope remains `QTSS01`: scrypt-derived AES-256-GCM with the envelope
identifier authenticated as additional data. Plaintext export remains explicitly
opt-in and must not be used for node persistence.

The payload contains the active threshold, the complete ordered holder list,
the group public key, the locally held active shares, and the locally held
retired shares. A node outside the active committee can persist zero active
shares without reactivating its retired generation. Nodes with only public
state can also persist the holder configuration.

Import accepts both current snapshots and legacy share blobs. Current snapshots
restore the threshold and holder list rather than reconstructing contiguous IDs
from the startup configuration. Legacy blobs do not contain this metadata and
still depend on the supplied configuration. Older binaries cannot read the new
snapshot payload; retain an encrypted backup before testing an upgrade.

Parsing is staged. Invalid input does not erase the current shares or install a
partial replacement. Lengths, participant uniqueness, active-holder membership,
threshold limits, and share decoding are checked before replacement. Retired
shares remain excluded from signing and are cleared by `ZeroizeAllShares`.

The node serializes encrypted persistence, writes a temporary file in the target
directory, syncs and closes it, and renames it over the configured state file.
Successful reshare installation or retirement is persisted before the runner
reports success to consensus. A persistence error prevents that completion
notification. Filesystem power-loss guarantees remain platform-dependent.

An existing state file that cannot be decrypted or decoded aborts startup. It
must not trigger key regeneration or be overwritten by partial-startup cleanup.
A missing state file remains distinct from a corrupt or unreadable file.

## Recovery boundaries

This snapshot is not an epoch-transition journal or a recovery protocol. It does
not contain a canonical epoch binding, the coordinator's holder history,
acknowledgement history, or the random subshares generated for an in-flight
reshare. Loading it alone does not establish that a restarted validator has the
generation required by the current epoch. Replaying an interrupted reshare with
new randomness is not a substitute for retransmitting its original contributions.

Cross-epoch cold recovery and newly admitted validators still require a
generation-bound, authenticated recovery protocol. The existing unsafe
distributed-signing gates remain necessary: persistence and successful signature
verification do not establish confidentiality of the signing protocol.
