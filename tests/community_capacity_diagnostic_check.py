#!/usr/bin/env python3
"""Offline deadline classification; no VM, collector, sockets or installed data."""
import importlib.util
from pathlib import Path
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).with_name('community_capacity_diagnostic.py')
spec = importlib.util.spec_from_file_location('capacity_diagnostic_fixture', SOURCE)
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


class DeadlineClassification(unittest.TestCase):
    def observe(self, completion):
        clock = types.SimpleNamespace(value=0.0)
        owner = types.SimpleNamespace()
        if completion == 0:
            owner._diagnostic_finished_monotonic = completion
        state = {'samples': [], 'original_30s_sender_bound_passed': None}

        class Event:
            def is_set(self):
                return completion is not None and clock.value >= completion

            def wait(self, seconds):
                target = clock.value + seconds
                clock.value = min(target, completion) if completion is not None and clock.value < completion else target
                if self.is_set():
                    owner._diagnostic_finished_monotonic = completion
                return self.is_set()

        def sample(_owner, phase):
            state['samples'].append({'phase': phase, 'seconds_after_repair': clock.value})

        with patch.object(diagnostic, 'time', types.SimpleNamespace(monotonic=lambda: clock.value)), \
                patch.object(diagnostic, 'STATE', state), \
                patch.object(diagnostic, 'sample', sample), \
                patch.object(diagnostic, 'save_state', lambda: None):
            finished = diagnostic.diagnostic_wait(owner, Event(), [])
        self.assertLessEqual(clock.value, 120)
        return state, finished

    def test_completion_within_original_bound_passes(self):
        for completion in [0.0, 29.9, 30.0]:
            with self.subTest(completion=completion):
                state, finished = self.observe(completion)
                self.assertTrue(finished)
                self.assertTrue(state['original_30s_sender_bound_passed'])

    def test_late_recovery_never_changes_original_failure_to_pass(self):
        for completion in [30.1, 50.0, 120.0]:
            with self.subTest(completion=completion):
                state, finished = self.observe(completion)
                self.assertTrue(finished)
                self.assertFalse(state['original_30s_sender_bound_passed'])

    def test_unfinished_sender_observation_is_bounded(self):
        state, finished = self.observe(None)
        self.assertFalse(finished)
        self.assertFalse(state['original_30s_sender_bound_passed'])
        self.assertEqual(state['samples'][-1]['seconds_after_repair'], 120)

    def test_sampling_cannot_accept_completion_after_diagnostic_deadline(self):
        clock = types.SimpleNamespace(value=0.0)
        owner = types.SimpleNamespace()
        state = {'samples': [], 'original_30s_sender_bound_passed': None}
        completion = 120.5

        class Event:
            def is_set(self):
                if clock.value >= completion:
                    owner._diagnostic_finished_monotonic = completion
                    return True
                return False

            def wait(self, seconds):
                if clock.value >= 120:
                    raise AssertionError('Wait continued after sampling crossed the deadline')
                clock.value += seconds
                return self.is_set()

        def sample(_owner, phase):
            if clock.value >= 115:
                clock.value += 6
            state['samples'].append({'phase': phase, 'seconds_after_repair': clock.value})

        with patch.object(diagnostic, 'time', types.SimpleNamespace(monotonic=lambda: clock.value)), \
                patch.object(diagnostic, 'STATE', state), \
                patch.object(diagnostic, 'sample', sample), \
                patch.object(diagnostic, 'save_state', lambda: None):
            finished = diagnostic.diagnostic_wait(owner, Event(), [])
        self.assertFalse(finished)
        self.assertFalse(state['original_30s_sender_bound_passed'])
        self.assertEqual(state['sender_finished_after_repair_s'], completion)
        self.assertEqual(clock.value, 121)


if __name__ == '__main__':
    unittest.main()
