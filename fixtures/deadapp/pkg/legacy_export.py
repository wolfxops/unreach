"""Orphan module with a risky pattern: judged remove_first by the security lens."""

import pickle


def load_blob(raw: bytes):
    return pickle.loads(raw)  # unsafe deserialization in dead code
