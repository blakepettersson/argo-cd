---
title: Fine-Grained RBAC for Sync Options (replace/force)
authors:
  - "@blakepettersson"
sponsors:
  - TBD
reviewers:
  - TBD
approvers:
  - TBD

creation-date: 2026-04-06
last-updated: 2026-04-06
---

# Fine-Grained RBAC for Sync Options (replace/force)

## Summary

Today, any user with `sync` permission on an application can use `Replace=true` and `Force=true`
sync options. These are destructive operations -- `replace` deletes and recreates resources instead
of patching, and `force` deletes and recreates resources that fail to apply. The only existing
control is a server-wide `--sync-with-replace-allowed` flag, which is all-or-nothing and not
user/role-scoped. There is no control at all for `force`.

This proposal adds `sync/replace` and `sync/force` sub-actions to the RBAC system, following the
existing sub-action pattern used by `delete/`, `update/`, and `action/`. For backwards
compatibility, `sync` implicitly grants all sync sub-actions. Operators restrict access via explicit
**deny** rules.

## Motivation

Organizations need to limit who can perform destructive sync operations. A junior developer
accidentally syncing with `--force` or `--replace` in production can cause significant downtime by
deleting and recreating resources unnecessarily.

### Goals

- Allow RBAC policies to control `replace` and `force` sync options independently of the base
  `sync` permission.
- Maintain full backwards compatibility -- existing policies that grant `sync` continue to work
  without modification.
- Follow established RBAC patterns in the codebase (sub-actions, Casbin policy model).
- Provide a path to deprecate the server-wide `--sync-with-replace-allowed` flag in favor of the
  more granular RBAC approach.

### Non-Goals

- Controller-side re-validation for declarative sync operations set directly on the Application
  spec.
- UI changes to hide replace/force buttons when the user lacks permission (follow-up work).
- Additional sync sub-actions such as `sync/prune` or `sync/server-side-apply` (easy to add later
  using the same mechanism).
- Unifying the existing `override` action as `sync/override`.

## Proposal

### Use cases

#### Use case 1: Restrict destructive sync options for a team
As a platform admin, I want to allow my development team to sync applications but prevent them from
using `replace` or `force`, so that they cannot accidentally delete and recreate production
resources.

```csv
p, role:developer, applications, sync, */*, allow
p, role:developer, applications, sync/replace, */*, deny
p, role:developer, applications, sync/force, */*, deny
```

#### Use case 2: Restrict only replace but allow force
As a platform admin, I want to block `replace` (which always deletes/recreates) but allow `force`
(which only deletes/recreates on failure), since force is less risky in our environment.

```csv
p, role:deployer, applications, sync, */*, allow
p, role:deployer, applications, sync/replace, */*, deny
```

#### Use case 3: Deny all sync sub-actions with a wildcard
As a platform admin, I want to deny all destructive sync sub-actions with a single rule.

```csv
p, role:readonly-deployer, applications, sync, */*, allow
p, role:readonly-deployer, applications, sync/*, */*, deny
```

### Implementation Details/Notes/Constraints

#### New Sub-Actions

| Sub-Action      | Meaning                                              |
|-----------------|------------------------------------------------------|
| `sync`          | Base sync (apply-based, no destructive options)      |
| `sync/replace`  | Sync with `Replace=true` sync option                 |
| `sync/force`    | Sync with `Force=true` (via SyncStrategy)            |

#### Backwards Compatibility via Policy Expansion

The core challenge is that Casbin's glob matcher treats `sync` and `sync/replace` as distinct action
strings -- `sync` does not match `sync/replace`. We cannot use the existing `delete`/`update`
fallback pattern (check broad action, fall back to specific) because a fallback from a denied
`sync/replace` to an allowed `sync` would **bypass explicit deny rules**.

Instead, this proposal uses **policy expansion** at policy load time. For every policy line that
allows `sync` on `applications`:

```
p, SUBJECT, applications, sync, OBJECT, allow
```

The adapter automatically injects:

```
p, SUBJECT, applications, sync/replace, OBJECT, allow
p, SUBJECT, applications, sync/force, OBJECT, allow
```

This makes Casbin's existing policy effect rule handle everything correctly:

```
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
```

| Scenario                                 | `sync/replace` allow? | `sync/replace` deny? | Result      |
|------------------------------------------|-----------------------|----------------------|-------------|
| Only `sync allow`                        | Injected allow        | No deny              | **Allowed** |
| `sync allow` + `sync/replace deny`       | Injected allow        | Explicit deny        | **Denied**  |
| Only `sync/replace allow` (no base sync) | Explicit allow        | No deny              | **Allowed** |
| No `sync` at all                         | No allow              | No deny              | **Denied**  |

##### Why not the fallback pattern?

The existing fine-grained RBAC for `delete`/`update` uses a fallback: check the specific sub-action
first, then fall back to the base action if denied. This works for its use case (granting access to
specific resources within an app) but fails for deny-based restriction:

1. User has `sync allow` and `sync/replace deny`
2. Enforce `sync/replace` -> denied (explicit deny)
3. Fallback to `sync` -> allowed (explicit allow)
4. Result: **allowed** -- the deny is bypassed

Policy expansion avoids this because both the injected allow and explicit deny are evaluated together
by Casbin in a single enforcement call.

#### Implementation Changes

##### 1. Action Constants -- `util/rbac/rbac.go`

```go
ActionSyncReplace = "sync/replace"
ActionSyncForce   = "sync/force"
```

##### 2. Policy Expansion -- `util/rbac/rbac.go`

Add expansion logic in `argocdAdapter.LoadPolicy()`:

Key details:
- Only expands `allow` rules -- deny rules are never expanded. A `sync deny` should not
  automatically deny sub-actions, since a user might have `sync deny` at one scope but
  `sync/replace allow` explicitly at another.
- Only expands exact `sync`, not `sync/*` or `sync/replace` (no double-expansion).
- Applies to all policy layers: built-in, user-defined, and runtime (project) policies.

##### 3. Enforcement -- `server/application/application.go`

In the `Sync()` handler, after the existing base `sync` check:

```go
// Existing base sync check (unchanged)
if err := s.enf.EnforceErr(ctx.Value("claims"), rbac.ResourceApplications,
    rbac.ActionSync, a.RBACName(s.ns)); err != nil {
    return nil, err
}

// New: sub-action checks. These succeed by default via policy expansion
// unless the operator has added an explicit deny rule.
if syncOptions.HasOption(common.SyncOptionReplace) {
    if err := s.enf.EnforceErr(ctx.Value("claims"), rbac.ResourceApplications,
        rbac.ActionSyncReplace, a.RBACName(s.ns)); err != nil {
        return nil, err
    }
}

if syncReq.Strategy != nil && syncReq.Strategy.Force() {
    if err := s.enf.EnforceErr(ctx.Value("claims"), rbac.ResourceApplications,
        rbac.ActionSyncForce, a.RBACName(s.ns)); err != nil {
        return nil, err
    }
}
```

No fallback logic, no inheritance toggle -- Casbin does all the work with the expanded policies.

##### 4. Built-in Policy -- `assets/builtin-policy.csv`

No changes needed. The existing admin rule:

```csv
p, role:admin, applications, sync, */*, allow
```

is automatically expanded to include `sync/replace` and `sync/force` allows.

##### 5. RBAC Validation -- `cmd/argocd/commands/admin/settings_rbac.go`

Update `applicationsActions` to allow `sync` to have sub-paths:

```go
rbac.ActionSync: rbacTrait{allowPath: true},  // was: rbacTrait{}
```

This allows `argocd admin settings rbac can` to validate sub-action policies.

##### 6. Deprecate `--sync-with-replace-allowed`

The server-wide flag becomes redundant. Deprecation path:

1. **Phase 1** (this proposal): When both the flag and RBAC are in play, the flag takes precedence.
   If `--sync-with-replace-allowed=false`, replace is denied regardless of RBAC. If `true`, defer
   to RBAC.
2. **Phase 2** (future release): Deprecation warning when the flag is explicitly set.
3. **Phase 3** (future release): Remove the flag entirely.

### Security Considerations

- This proposal strictly **adds restrictions** -- it does not grant any new capabilities. Users who
  could not sync before still cannot sync.
- The policy expansion mechanism is deterministic and only generates `allow` rules from existing
  `allow` rules. It cannot create permissions that do not already exist.
- Deny rules are never expanded, preventing unintended permission lockouts.

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Policy expansion adds hidden rules that may confuse operators debugging RBAC | Add logging at debug level when rules are expanded. Document the expansion behavior. `argocd admin settings rbac` should show expanded rules. |
| Future sync sub-actions require updating the expansion list | The expansion function is a single list -- adding new sub-actions is a one-line change. |
| Operators may not realize `sync` implicitly allows `replace`/`force` | This is the current behavior (no change). Documentation should highlight that explicit deny rules are available. |

### Upgrade / Downgrade Strategy

**Upgrade**: No action required. Existing `sync` policies are automatically expanded to include
sub-actions, preserving current behavior. Operators who want to restrict replace/force can add deny
rules at their convenience.

**Downgrade**: If downgrading to a version without this feature, any `sync/replace` or `sync/force`
deny rules in the RBAC policy will be ignored (unrecognized actions are silently skipped by Casbin).
The `--sync-with-replace-allowed` flag remains functional during the deprecation period.

## Drawbacks

- **Implicit policy expansion is non-obvious.** Operators may not realize that a `sync allow` rule
  generates additional `sync/replace` and `sync/force` allow rules. This is mitigated by
  documentation and tooling (`argocd admin settings rbac`).
- **Deny-only restriction model.** Unlike `delete/group/kind/ns/name` where you grant specific
  sub-actions, this model requires granting `sync` broadly and then denying sub-actions. This is a
  trade-off for backwards compatibility.

## Alternatives

### 1. Fallback enforcement (like `delete`/`update`)

Check `sync/replace` first, fall back to `sync` if denied. Simple to implement but **breaks
explicit deny rules** -- a deny on `sync/replace` is bypassed by the fallback to `sync`.

### 2. Custom Casbin matcher

Modify the Casbin matcher function so that `sync` automatically matches `sync/*`. More invasive,
harder to reason about, and risks side effects on other action matching.

### 3. Opt-in model (require explicit `sync/replace` grants)

Require operators to add `sync/replace allow` rules for users who need replace. More secure by
default but **breaks all existing deployments** on upgrade -- every user with `sync` would lose
replace/force access until policies are updated.

### 4. Server-wide flag only (status quo for replace)

Keep `--sync-with-replace-allowed` and add `--sync-with-force-allowed`. Simple but not
user/role-scoped, which is the core problem this proposal solves.