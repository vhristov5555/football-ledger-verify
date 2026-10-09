# Mutation notes

Each defect below was written into `verify.py`, the suite was run
(`python3 -m unittest discover -s tests`), and the change was reverted. A
mutation that leaves the suite green is a check the tests do not actually
exercise. Measured 2026-10-09 on Python 3.12.

| id | defect injected into `verify.py` | suite | tests that went red |
| --- | --- | --- | --- |
| V1 | Merkle: odd level padded with `sha256(b"")` instead of duplicating the last node | RED | test_calendar_only_proof_is_undecided, test_day_name_downloads_both_files_and_can_save_them, test_explicit_proof_path, test_explorers_disagreeing_is_undecided, test_garbage_from_an_explorer_is_undecided, test_header_not_hashing_to_the_reported_hash_fails, test_header_without_proof_of_work_fails, test_local_path, test_network_error_is_undecided, test_odd_level_duplicates_the_last_node, test_real_day_is_self_consistent, test_real_day_verifies_with_both_explorers, test_real_erratum_uses_entries_not_leaves, test_skip_bitcoin_says_the_time_is_not_verified_and_stays_offline, test_unknown_attestation_is_kept_not_trusted |
| V2 | proof digest never compared to sha256(file) | RED | test_reforged_record_is_caught_by_the_proof |
| V3 | explorers' answers not compared with each other | RED | test_explorers_disagreeing_is_undecided |
| V4 | Merkle root compared in display (reversed) order | RED | test_day_name_downloads_both_files_and_can_save_them, test_explorers_disagreeing_is_undecided, test_garbage_from_an_explorer_is_undecided, test_header_not_hashing_to_the_reported_hash_fails, test_header_without_proof_of_work_fails, test_local_path, test_network_error_is_undecided, test_real_day_verifies_with_both_explorers |
| V5 | proof-of-work check removed | RED | test_header_without_proof_of_work_fails |
| V6 | header-hash check removed | RED | test_header_not_hashing_to_the_reported_hash_fails |
| V7 | one explorer only | RED | test_explorers_disagreeing_is_undecided, test_real_day_verifies_with_both_explorers |
| V8 | calendar-only proof accepted as verified | RED | test_calendar_only_proof_is_undecided, test_explicit_proof_path, test_unknown_attestation_is_kept_not_trusted |
| V9 | leaf commitment not re-derived | RED | test_changed_leaf_without_new_commitment_fails |
| V10 | record root not compared | RED | test_changed_root_fails |
| V11 | erratum `entries` not read (only `leaves`) | RED | test_real_erratum_uses_entries_not_leaves |
| V12 | header count `n` not compared with the leaves | RED | test_header_count_must_match_the_leaves |
| V13 | block time printed without the approximate wording | RED | test_real_day_verifies_with_both_explorers |

Notes:

- **V1** is caught by a synthetic three-leaf tree and by both real records,
  which have odd levels (`fixtures/2026-10-04.jsonl`, 18 leaves;
  `fixtures/facts-erratum-2026-08-26.jsonl`, 66 entries). An even tree (2, 4,
  8 … leaves) would never catch it.
- **V2** is the one that matters most: a record edited AND re-hashed is
  self-consistent (checks 1–2 pass); only the proof digest rejects it
  (`test_reforged_record_is_caught_by_the_proof`).
- **V4** shows the byte-order trap: explorers print the Merkle root
  reversed; the header stores it in internal order, which is what the proof
  computes. Comparing the reversed value rejects every real block.
- **V13** went green on its first measurement — the suite did not read the
  wording at all; the assertion on "approximate" was added and V13 re-measured red.
- **V11**: a §7.5 erratum names its leaves `entries`; only the real erratum
  fixture (`fixtures/facts-erratum-2026-08-26.jsonl`) can catch a reader that
  looks for `leaves` alone.
- Network access is blocked during the suite: `verify.http_get` is
  replaced by a function that fails the test.
