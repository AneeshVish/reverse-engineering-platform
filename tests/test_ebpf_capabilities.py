"""Capability probe tests for eBPF gating."""

import sys

from src.core import capabilities


def test_probe_ebpf_false_off_linux():
    if sys.platform != "linux":
        assert capabilities.probe_ebpf_support() is False


def test_ebpf_package_registered():
    assert "bcc" in capabilities.OPTIONAL_PACKAGES
