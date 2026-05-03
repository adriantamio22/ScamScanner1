# Security Specification - ScamScanner

## Data Invariants
1. A Case Record must always be linked to the `uid` of the authenticated user who created it.
2. Case Records are immutable forensic snapshots; they can be created and deleted by the owner, but never updated.
3. Every Case Record must have a valid `ToolType` and `Verdict`.
4. Timestamps must be server-authoritative (`request.time`).

## The "Dirty Dozen" Payloads (Denial Expected)
1. **Identity Spoofing**: Attempt to write a case to another user's path.
2. **Identity Spoofing (Data)**: Attempt to write a case where `data.userId` does not match `request.auth.uid`.
3. **Shadow Field Injection**: Write a case with an unauthorized field (e.g., `isVerified: true`).
4. **Invalid Type Injection**: Write `legitimacyPercentage` as a string.
5. **Boundary Breach**: Write `legitimacyPercentage` as 150.
6. **Verdict Poisoning**: Write a verdict not in the approved enum (e.g., `SAFE`).
7. **Timestamp Spoofing**: Attempt to provide a client-side `createdAt` date instead of `serverTimestamp()`.
8. **Resource Exhaustion**: Use an extremely long string for `input`.
9. **ID Poisoning**: Use a 2KB string as a `caseId`.
10. **State Mutation**: Attempt to `update` an existing case record.
11. **Verification Bypass**: Attempt to write as a non-verified user (except for the admin fallback).
12. **Cross-User Query**: Attempt to `list` cases belonging to a different user.
