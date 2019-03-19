#!/usr/bin/env python3

"""
filename: access_control_test.py
description: access control module unit test
author: fangjianbing@kuaishou.com
date: 2019-03-18 11:00:00
"""
import unittest

from access_control import AccessControl

config_base = """
# user groups (could be nested)
[groups]
g1 = ['user1', 'user2']
g2 = ['user2', 'user3']
g3 = ['g1', 'user5']
g4 = ['g5', 'g1']
g5 = ['g4']

# role and members
[roles]
admin = ['g4', 'user3']
reader = ['g2', 'user5']

# resource groups
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
"""

config_first_match = config_base + """
[rule_policy]
strategy = 'FIRST_MATCH'  # return the first matched result of rule
mismatched = 'allow'      # 'allow' or 'deny' if there is no matched rule, default: 'allow'
"""

config_all_allow = config_base + """
[rule_policy]
strategy = 'ALL_ALLOW'  # allow only if all matched rules allow
mismatched = 'allow'    # 'allow' or 'deny' if there is no matched rule, default: 'allow'
"""

config_any_allow = config_base + """
[rule_policy]
strategy = 'ANY_ALLOW'  # allow if any matched rule allows
mismatched = 'allow'    # 'allow' or 'deny' if there is no matched rule, default: 'allow'
"""
class TestAccessControl(unittest.TestCase):

  def test_unknown_user_(self):
    ac = AccessControl(config_first_match)
    is_allowed, reason = ac.check('user0', 'part_a', 'GET')
    self.assertEqual(is_allowed, True)
    self.assertEqual(reason, 'No matched rule found, use mismatch_decision: True')

  def test_unknown_resource_(self):
    ac = AccessControl(config_first_match)
    is_allowed, reason = ac.check('user1', 'part_x', 'GET')
    self.assertEqual(is_allowed, True)
    self.assertEqual(reason, 'No matched rule found, use mismatch_decision: True')

  def test_unknown_action_(self):
    ac = AccessControl(config_first_match)
    is_allowed, reason = ac.check('user5', 'part_c', 'XXX')
    self.assertEqual(is_allowed, True)
    self.assertEqual(reason, 'No matched rule found, use mismatch_decision: True')

  def test_rule_mismatch_(self):
    ac = AccessControl(config_first_match)
    is_allowed, reason = ac.check('user1', 'part_c', 'GET')
    self.assertEqual(is_allowed, True)
    self.assertEqual(reason, 'No matched rule found, use mismatch_decision: True')

  def test_first_match_allow_(self):
    ac = AccessControl(config_first_match)
    is_allowed, reason = ac.check('user1', 'part_b', 'GET')
    self.assertEqual(is_allowed, True)
    self.assertEqual(reason, '[rules.r1] "admin" is allowed to do "any action" on "res1"')

  def test_first_match_deny_(self):
    ac = AccessControl(config_first_match)
    is_allowed, reason = ac.check('user3', 'part_c', 'PUT')
    self.assertEqual(is_allowed, False)
    self.assertEqual(reason, '[rules.r2] "reader" is not allowed to do "PUT" on "res2"')

  def test_all_allow_allow_(self):
    ac = AccessControl(config_all_allow)
    is_allowed, reason = ac.check('user1', 'part_a', 'PUT')
    self.assertEqual(is_allowed, True)
    self.assertEqual(reason, 'All matched rules allowed')

  def test_all_allow_deny_(self):
    ac = AccessControl(config_all_allow)
    is_allowed, reason = ac.check('user5', 'part_a', 'POST')
    self.assertEqual(is_allowed, False)
    self.assertEqual(reason, '[rules.r2] "reader" is not allowed to do "POST" on "res2"')

  def test_any_allow_allow_(self):
    ac = AccessControl(config_any_allow)
    is_allowed, reason = ac.check('user1', 'part_a', 'POST')
    self.assertEqual(is_allowed, True)
    self.assertEqual(reason, '[rules.r1] "admin" is allowed to do "*" on "res1"')

  def test_any_allow_deny_(self):
    ac = AccessControl(config_any_allow)
    is_allowed, reason = ac.check('user5', 'part_c', 'POST')
    self.assertEqual(is_allowed, False)
    self.assertEqual(reason, 'All matched rules denied')

  def test_rules_only_(self):
    config_rules_only = """
      [[rules]]
      allow = [
        ['user1', 'res_a', 'GET'],
      ]
      deny = [
        ['user1', 'res_a', 'POST'],
      ]
    """
    ac = AccessControl(config_rules_only)

    is_allowed, reason = ac.check('user1', 'res_a', 'GET')
    self.assertEqual(is_allowed, True)
    self.assertEqual(reason, '[rules.1] "user1" is allowed to do "GET" on "res_a"')

    is_allowed, reason = ac.check('user1', 'res_a', 'POST')
    self.assertEqual(is_allowed, False)
    self.assertEqual(reason, '[rules.1] "user1" is not allowed to do "POST" on "res_a"')

if __name__ == '__main__':
  unittest.main()
