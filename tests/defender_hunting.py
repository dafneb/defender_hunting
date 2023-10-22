#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Tests for M365 Defender Advanced hunting files parser plugin."""

import unittest

from plaso.containers import warnings
from plaso.parsers import defender_hunting

from tests.parsers import test_lib

class DefenderAdvancedHuntingParserTest(test_lib.ParserTestCase):
    """Tests for M365 Defender Advanced hunting files parser plugin."""

    def testProcess(self):
        """Tests the Process function."""
        plugin = defender_hunting.DefenderAdvancedHuntingParser()
        #plugin.SetTest(1) # Enabled noisy mode for test - you will get huge amount of informations
        storage_writer = self._ParseFile(['advanced_hunting_test.csv'], plugin)

        number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
            'event_data')
        self.assertEqual(number_of_event_data, 12)

        number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
            'extraction_warning')
        self.assertEqual(number_of_warnings, 14)

        number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
            'recovery_warning')
        self.assertEqual(number_of_warnings, 0)

if __name__ == '__main__':
    unittest.main()
