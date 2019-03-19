#!/usr/bin/env python3

"""
filename: access_control.py
description: access control module
author: fangjianbing@kuaishou.com
date: 2019-03-15 19:40:00
"""
import tomlkit

class AccessControl:
  """
  Access Control Service

  An example config in TOML:
  ```
  # user groups (could be nested)
  [groups]
  g1 = ['user1', 'user2']
  g2 = ['user2', 'user3']
  g3 = ['g1', 'user5']
  g4 = ['g5', 'g1']
  g5 = ['g4']

  # role and members (could not be nested)
  [roles]
  admin = ['g4', 'user3']
  reader = ['g2', 'user5']

  # resource groups (could be nested)
  [resources]
  res1 = ['part_a', 'part_b']
  res2 = ['part_a', 'part_c']

  # permission rules, all rules defined here will be checked one by one in order
  [rules]
    [rules.r1]  # indents in this block are not required, but helpful for readability
    allow = [
      ['reader', 'res1', 'GET'],  # means 'reader' can execute 'GET' action on resource 'res1'
      ['admin',  'res1', '*'],    # means 'reader' can execute any action on resource 'res1'
    ]

    [rules.r2]
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
  """

  _KEY_USER_GROUPS = "groups"
  _KEY_ROLES = "roles"
  _KEY_RESOURCE_GROUPS = "resources"
  _KEY_RULES = "rules"
  _KEY_RULE_POLICY = "rule_policy"
  _KEY_RULE_POLICY_MISMATCH_DECISION = "mismatch_decision"
  _KEY_RULE_POLICY_STRATEGY = "strategy"
  _KEY_RULE_POLICY_STRATEGY_FIRST_MATCH = "FIRST_MATCH"
  _KEY_RULE_POLICY_STRATEGY_ALL_ALLOW = "ALL_ALLOW"
  _KEY_RULE_POLICY_STRATEGY_ANY_ALLOW = "ANY_ALLOW"

  def __init__(self, *args, **kwargs):
    config_str = None
    if args:
      config_str = args[0]
    if 'config' in kwargs:
      config_str = kwargs.get('config')
    if config_str:
      self.load(config_str, kwargs.get('config_type', 'toml'))

  def load(self, config, config_type='toml'):
    """ load and parse string config """
    if config_type.lower() == 'toml':
      self._config = tomlkit.parse(config)
    else:
      raise Exception('Unsupported config type: ' + config_type)

  def check(self, user, resource, action):
    """
    check whether the [user] is allowed to do [action] on [resource] or not
    Return: (is_allowed, reason)
    """
    roles = self._get_roles(user)
    resources = self._get_groups(resource, self._config.get(self._KEY_RESOURCE_GROUPS, {}))
    rules = self._config.get(self._KEY_RULES, {})
    # convert to dict if rules is a list
    if isinstance(rules, list):
      rules = {k: v for k, v in enumerate(rules, start=1)}
    rule_policy = self._config.get(self._KEY_RULE_POLICY, {})
    strategy = rule_policy.get(self._KEY_RULE_POLICY_STRATEGY, self._KEY_RULE_POLICY_STRATEGY_FIRST_MATCH)

    for name, rule in rules.items():
      for key, items in rule.items():
        if key not in ('allow', 'deny'):
          continue
        for i in items:
          if self._is_role_matched(i[0], roles) and self._is_resource_matched(i[1], resources) \
              and self._is_action_matched(i[2], action):
            # if a rule item is matched
            is_allowed = key == 'allow'
            if strategy == self._KEY_RULE_POLICY_STRATEGY_FIRST_MATCH:
              return is_allowed, '[rules.%s] "%s" is %sallowed to do "%s" on "%s"' % \
                      (name, i[0], '' if is_allowed else 'not ', 'any action' if i[2] == '*' else i[2], i[1])
            if strategy == self._KEY_RULE_POLICY_STRATEGY_ANY_ALLOW and is_allowed:
              return True, '[rules.%s] "%s" is allowed to do "%s" on "%s"' % (name, i[0], i[2], i[1])
            if strategy == self._KEY_RULE_POLICY_STRATEGY_ALL_ALLOW and not is_allowed:
              return False, '[rules.%s] "%s" is not allowed to do "%s" on "%s"' % (name, i[0], i[2], i[1])

    if strategy == self._KEY_RULE_POLICY_STRATEGY_FIRST_MATCH:
      mismatch_decision = rule_policy.get(self._KEY_RULE_POLICY_MISMATCH_DECISION, 'allow') == 'allow'
      return mismatch_decision, 'No matched rule found, use mismatch_decision: %s' % mismatch_decision
    if strategy == self._KEY_RULE_POLICY_STRATEGY_ANY_ALLOW:
      return False, 'All matched rules denied'
    if strategy == self._KEY_RULE_POLICY_STRATEGY_ALL_ALLOW:
      return True, 'All matched rules allowed'
    raise Exception('Unsupported rule_policy strategy: ' + strategy)

  def _get_roles(self, subject):
    """ get the roles of a user or group """
    groups = self._get_groups(subject, self._config.get(self._KEY_USER_GROUPS, {}))
    all_roles = self._config.get(self._KEY_ROLES, {})
    roles = {subject}
    for group in groups:
      roles.update({name for name, members in all_roles.items() if group in members})
    return roles

  def _get_groups(self, subject, all_groups):
    """ get the groups of a subject in all_groups recursively """
    res_groups = {subject}
    def _get_groups_helper(sub):
      new_groups = {name for name, members in all_groups.items() if sub in members}
      diff_groups = new_groups - res_groups
      if not diff_groups:
        return
      res_groups.update(diff_groups)
      for group in diff_groups:
        _get_groups_helper(group)

    _get_groups_helper(subject)
    return res_groups

  def _is_role_matched(self, rule_role, subject_roles):
    return rule_role in subject_roles

  def _is_resource_matched(self, rule_resource, subject_resources):
    return rule_resource == '*' or rule_resource in subject_resources

  def _is_action_matched(self, rule_action, subject_action):
    return rule_action == '*' or rule_action == subject_action
