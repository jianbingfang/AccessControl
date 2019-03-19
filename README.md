# AccessControl
A lightweight Role-based-Access-Control python module described in TOML config

This project was inspired by [casbin/casbin](https://github.com/casbin/casbin), but use a single TOML configuration with better understanding for most common RBAC/ACL scenarios.

# Requirements

- Python 3.X
- Dependency: `pip3 install tomlkit` (v0.5.3)

# Config Example

## Most Simple One
```toml
[[rules]]
allow = [
  ['user1', 'resource_a', 'GET'],
  ['user1', 'resource_a', 'PUT'],
  ['user1', 'resource_a', 'POST'],
]
deny = [
  ['user1', 'resource_a', 'DELETE'],
]
```

Every `rule` in `rules` is consist of a `allow` or a `deny` or both.

The `rule` is an list of triples, a triple with structure `[subject, resource, action]` which describes: **who**(`subject`, could be a user name, group name, or role name) **can**(for `allow`) **or cannot**(for `deny`) **do** `action` on **something**(`resource`).

## ACL Config
```toml
[groups]
list = ['user1', 'user2']

[[rules]]
allow = [
  ['list', '*', '*'],
]

[rule_policy]
mismatch_decision = 'deny'   # 'allow' or 'deny' if there is no matched rule, default: 'allow'
```

Only `user1` and `user2` in group `list` has permission do any action on any resource.

## Full Featured RBAC Config
```toml
# user groups (could be nested)
[groups]
g1 = ['user1', 'user2']
g2 = ['user2', 'user3']
g3 = ['g1', 'user5']

g4 = ['g5', 'g1']   # note that g4 and g5 are nested each other, we can handle it properly, user1 will be in g1, g4 and g5
g5 = ['g4']

# role and members (cannot be nested)
[roles]
admin = ['g4', 'user3']
reader = ['g2', 'user5']

# resource groups (could be nested)
[resources]
res1 = ['part_a', 'part_b']
res2 = ['part_a', 'part_c']

# permission rules, all rules defined here will be checked one by one in order
# 'rules' section could be either a map(with a rule name) or list(without rule name)
[rules]
  [rules.r1]  # defined a rule named 'r1'
  allow = [
    ['reader', 'res1', 'GET'],  # means 'reader' can execute 'GET' action on resource 'res1'
    ['admin',  'res1', '*'],    # means 'reader' can execute any action on resource 'res1'
  ]

  [rules.r2]  # defined a rule named 'r2'
  deny = [
    ['reader', 'res1', 'GET'],  # means 'reader' cannot execute 'PUT' action on resource 'res2'
    ['reader', 'res2', 'PUT'],  # means 'reader' cannot execute 'PUT' action on resource 'res2'
    ['reader', 'res2', 'POST'], # means 'reader' cannot execute 'POST' action on resource 'res2'
  ]

[rule_policy]
strategy = 'FIRST_MATCH'    # rule matching strategy, available options:
                            #   'FIRST_MATCH': [default] return the first matched result of rule
                            #   'ALL_ALLOW':   allow only if all matched rules allow
                            #   'ANY_ALLOW':   allow if any matched rule allows
mismatch_decision = 'allow'   # 'allow' or 'deny' if there is no matched rule, default: 'allow'
```

# Usage

```py
from access_control import AccessControl

config = """
  [[rules]]
  allow = [
    ['user1', 'res_a', 'GET'],
  ]
  deny = [
    ['user1', 'res_a', 'POST'],
  ]
"""

ac = AccessControl(config)

is_allowed, reason = ac.check('user1', 'res_a', 'GET')

assert(is_allowed, True)
assert(reason, '[rules.1] "user1" is allowed to do "GET" on "res_a"')

is_allowed, reason = ac.check('user1', 'res_a', 'POST')

assert(is_allowed, False)
assert(reason, '[rules.1] "user1" is not allowed to do "POST" on "res_a"')
```
