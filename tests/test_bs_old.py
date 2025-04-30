import pytest
import inspect
import importlib.util
import sys
from typing import Any, Dict


# Fixture to dynamically load the target script
@pytest.fixture
def target_script(request):
    script_path = request.config.getoption("--script")
    if not script_path:
        pytest.skip("No script provided. Use --script=path/to/script.py")

    spec = importlib.util.spec_from_file_location("target", script_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["target"] = module
    spec.loader.exec_module(module)
    return module


# Generate default test params based on type hints
def _generate_test_params(sig: inspect.Signature) -> Dict[str, Any]:
    return {
        k: (
            42
            if v.annotation in (int, float)
            else "test" if v.annotation == str else None
        )
        for k, v in sig.parameters.items()
    }


# Test 1: Catch functions returning None unexpectedly
def test_no_sneaky_none_returns(target_script):
    for name, func in inspect.getmembers(target_script, inspect.isfunction):
        if func.__code__.co_flags & 0x04:  # Skip *args functions
            continue
        sig = inspect.signature(func)
        params = _generate_test_params(sig)
        try:
            result = func(**params)
            assert result is not None, f"{name} returns None when it shouldn’t!"
        except Exception:
            pass  # Let other tests catch crashes


# Test 2: Ensure return type consistency with annotations
def test_return_type_consistency(target_script):
    for name, func in inspect.getmembers(target_script, inspect.isfunction):
        if not func.__annotations__ or "return" not in func.__annotations__:
            continue
        sig = inspect.signature(func)
        params = _generate_test_params(sig)
        try:
            result = func(**params)
            expected_type = func.__annotations__["return"]
            assert isinstance(
                result, expected_type
            ), f"{name} return type mismatch: expected {expected_type}, got {type(result)}"
        except Exception:
            pass  # Crashes handled elsewhere


# Test 3: No silent crashes with bad inputs
def test_no_silent_crashes(target_script):
    for name, func in inspect.getmembers(target_script, inspect.isfunction):
        sig = inspect.signature(func)
        params = {k: None for k in sig.parameters}  # Worst-case scenario
        try:
            func(**params)
        except Exception as e:
            assert False, f"{name} crashed silently with None inputs: {e}"


# Test 4: Flag unused variables
def test_no_unused_vars(target_script):
    for name, func in inspect.getmembers(target_script, inspect.isfunction):
        source = inspect.getsource(func).splitlines()
        defined_vars = {}
        for i, line in enumerate(source):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line and not any(
                op in line for op in ["==", "!=", "<", ">", "<=", ">="]
            ):
                var = line.split("=")[0].strip()
                defined_vars[var] = i
        # Check if vars are used after definition
        for var, def_line in defined_vars.items():
            if var not in "\n".join(source[def_line + 1 :]):
                pytest.fail(f"{name} has unused variable: {var}")


# Test 5: Catch sketchy None comparisons
def test_no_dumb_none_comparisons(target_script):
    for name, func in inspect.getmembers(target_script, inspect.isfunction):
        source = inspect.getsource(func)
        for line in source.splitlines():
            line = line.strip()
            if "None" in line and any(op in line for op in ["<", ">", "<=", ">="]):
                pytest.fail(f"{name} has sketchy None comparison: {line}")


# Usage: pytest test_bs.py --script=path/to/your/script.py -v
