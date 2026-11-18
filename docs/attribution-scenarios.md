# Sensitive API Change Attribution Scenarios

How Theo classifies the root cause of sensitive API changes between commits.

> **Note:** Criticality scores in this document are for understanding the classification logic only.
> In Theo's reports, these appear as color-coded badges, not numerical scores.

## Criticality Levels

| Score | Label | Meaning |
|-------|-------|---------|
| 1 | Client Initiated | Client changed the boundary call, API accessed directly |
| 2 | Client Initiated (Indirect) | Client changed the boundary call, API accessed via another dep |
| 3 | Dep Initiated | Boundary stable, direct dep version changed |
| 4 | Indirect Dep Initiated | Boundary stable, direct dep version unchanged |

Higher score = more critical for security review (more silent, less intentional).

## Terminology

- **Boundary pair**: The (clientMethod, depMethod) pair at the client→dep crossing point
- **Direct access**: The dep under analysis reaches the sensitive API through its own code
- **Indirect access**: The path crosses through another dependency before reaching the API
- **Initiator**: Who caused the change — independent from access type

## Decision Algorithm

For each **newly added** sensitive API:

```
1. Was the boundary pair (clientMethod, depMethod) in the previous boundary set?
   
   NO → Client initiated the change
     - DIRECT access  → Criticality 1
     - INDIRECT access → Criticality 2
   
   YES → Boundary is stable, dep side changed
     - Direct dep version changed? 
       YES → Criticality 3 (Dep Initiated)
       NO  → Criticality 4 (Indirect Dep Initiated)
```

Removals are reported for completeness without criticality badges.

## API Addition Scenarios

### Scenario 1: Client changes, no API change — Not scored

```
Before: client A1 → client B1 → client C1 → dep A1 → dep B1 → API 1
After:  client A2 → client B1 → client C1 → dep A1 → dep B1 → API 1
              ^^
```

No change in the sensitive API set. Theo does not report anything.

### Scenario 2: Client adds new dep interaction — Criticality 1
Note that the method body of the D1 may have changed but not the signature.

```
Before: client D1  (does not call dep A1)
After:  client D1 → dep A1 → dep C1 → API 2
```

Boundary `(D1, dep A1)` did not exist before → **client initiated**. Direct access → **criticality 1**.

### Scenario 3: Client + dep change, API replaced — Criticality 2

```
Before: client A1 → client B1 → client C1 → dep A1 → dep* B1 → API 1
After:  client A1 → client B1 → client C2 → dep A1 → dep* B2 → API 2
                                        ^^                  ^^
```

*dep B is from a different artifact (indirect access).*

Boundary changed (client C1→C2). Indirect access → **criticality 2**.

### Scenario 4: Client boundary + dep both change — Criticality 1

```
Before: client D1 → dep A1 → dep B1 → API 1
After:  client D2 → dep A2 → dep B2 → API 1 + API 2
            ^^       ^^        ^^
```

Boundary changed: `(D1, dep A1)` → `(D2, dep A2)`. Direct access → **criticality 1**.

### Scenario 5: Client boundary + indirect dep changes — Criticality 2

```
Before: client A1 → dep A1 → dep* B1 → API 1
After:  client A2 → dep A1 → dep* B2 → API 1 + API 2
            ^^                     ^^
```

*dep B is from a different artifact.*

Boundary changed (client A1→A2). Indirect access → **criticality 2**. The client change might be unrelated to the API addition.

### Scenario 6: Client deep change + dep internals change — Criticality 3 or 4

```
Before: client A1 → client B1 → client C1 → dep A1 → dep* B1 → API 1
After:  client A2 → client B1 → client C1 → dep A1 → dep* B2 → API 1 + API 2
            ^^                                              ^^
```

*dep B is from a different artifact.*

Boundary `(C1, dep A1)` is **stable** — client change (A1→A2) is deeper in the call chain.
- If direct dep version changed → **criticality 3** (dep initiated)
- If direct dep version unchanged → **criticality 4** (indirect dep initiated)

### Scenario 7: Direct dep changed, indirect access — Criticality 3

```
Before: client A1 → client B1 → client C1 → dep A1 → dep* B1 → API 1
After:  client A1 → client B1 → client C1 → dep A2 → dep* B2 → API 1 + API 2
                                                 ^^         ^^
```

*dep B is from a different artifact (indirect access).*

Boundary `(C1, dep A1)` is **stable** — dep A's method signature stayed the same even though its body changed. Direct dep version changed → **criticality 3**. The access is indirect, but the **initiator** is the direct dep.

### Scenario 8: Direct dep changed, new API path — Criticality 3

```
Before: client A1 → client B1 → client C1 → dep A1 → dep B1  (no sensitive API reached)
After:  client A1 → client B1 → client C1 → dep A2 → dep C1 → API 1
                                                 ^^
```

Boundary `(C1, dep A1)` was in the boundary set before. Direct dep version changed → **criticality 3**.

### Scenario 9: Indirect dep changed — Criticality 4

```
Before: client A1 → client B1 → client C1 → dep A1 → dep* B1 → API 1
After:  client A1 → client B1 → client C1 → dep A1 → dep* B2 → API 1 + API 2
                                                           ^^
```

*dep B is from a different artifact.*

Boundary `(C1, dep A1)` stable. Direct dep version unchanged → **criticality 4** (indirect dep initiated).

### Scenario 10: Indirect dep changed, new API path — Criticality 4

```
Before: client A1 → client B1 → client C1 → dep A1 → dep* B1  (no sensitive API reached)
After:  client A1 → client B1 → client C1 → dep A1 → dep* B2 → API 1
                                                           ^^
```

Boundary in set before. Direct dep version unchanged → **criticality 4**.

## API Removal Scenarios

Removals mirror additions. Reported for completeness without criticality badges. Use `--hide-removals` to suppress.

### Scenario 11: Client removes dep interaction

```
Before: client D1 → dep A1 → dep B1 → API 1
After:  client D2  (no longer calls dep A1)
```

### Scenario 12: Dep updated, API path broken

```
Before: client C1 → dep A1 → dep B1 → API 1
After:  client C1 → dep A2 → dep B2  (no longer reaches API 1)
```

### Scenario 13: Indirect dep updated, API removed

```
Before: client C1 → dep A1 → dep* B1 → API 1
After:  client C1 → dep A1 → dep* B2  (no longer reaches API 1)
```

## Whole-Dependency Scenarios

### Scenario 14: New dependency added — Criticality 1

Dep added to pom.xml. All APIs → **client initiated, criticality 1**. Reported with badge.

### Scenario 15: Dependency removed

Dep removed from pom.xml. All APIs removed. Reported without badge.

### Scenario 16: Dep version updated, same API surface — No change

Same APIs reachable via same paths. Nothing to report.

### Scenario 17: Entry point reachability changes — Criticality 1

Client adds a new public method that makes a previously unreachable path reachable. Boundary `(C1, dep A1)` was not in the boundary set before → **client initiated, criticality 1**.

## Summary Table

| # | Boundary | Access | Initiator | Crit |
|---|----------|--------|-----------|------|
| 1 | — | — | No change | — |
| 2 | New | DIRECT | Client | 1 |
| 3 | Changed | INDIRECT | Client | 2 |
| 4 | Changed | DIRECT | Client | 1 |
| 5 | Changed | INDIRECT | Client | 2 |
| 6 | Stable | INDIRECT | Dep or Indirect | 3 or 4 |
| 7 | Stable | INDIRECT | Direct Dep | 3 |
| 8 | Stable | INDIRECT | Direct Dep | 3 |
| 9 | Stable | INDIRECT | Indirect Dep | 4 |
| 10 | Stable | INDIRECT | Indirect Dep | 4 |
| 14 | New dep | DIRECT | Client | 1 |
| 17 | Newly reachable | DIRECT | Client | 1 |
