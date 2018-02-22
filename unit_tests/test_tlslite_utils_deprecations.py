# Copyright (c) 2018, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
    from mock import call
except ImportError:
    import unittest.mock as mock
    from unittest.mock import call

from tlslite.utils.deprecations import deprecated_params


class TestDeprecatedParams(unittest.TestCase):
    def test_no_changes(self):
        @deprecated_params({})
        def method(param_a, param_b):
            """Some doc string."""
            return (param_a, param_b)

        a = mock.Mock()
        b = mock.Mock()

        r = method(param_a=a, param_b=b)

        self.assertIsInstance(r, tuple)
        self.assertEqual(r, (a, b))
        self.assertIs(r[0], a)
        self.assertIs(r[1], b)

        self.assertEqual("Some doc string.", method.__doc__)

    def test_change_param(self):
        @deprecated_params({'param_a': 'old_param'})
        def method(param_a, param_b):
            return (param_a, param_b)

        old = mock.Mock()
        b = mock.Mock()

        with self.assertWarns(DeprecationWarning) as e:
            r = method(old_param=old, param_b=b)

        self.assertIsInstance(r, tuple)
        self.assertEqual(r, (old, b))
        self.assertIs(r[0], old)
        self.assertIs(r[1], b)

        self.assertIn('old_param', str(e.warning))

    def test_both_params(self):
        @deprecated_params({'param_a': 'older_param'})
        def method(param_a, param_b):
            return (param_a, param_b)

        a = mock.Mock()
        b = mock.Mock()
        c = mock.Mock()

        with self.assertRaises(TypeError) as e:
            method(param_a=a, param_b=b, older_param=c)

        self.assertIn('multiple values', str(e.exception))
