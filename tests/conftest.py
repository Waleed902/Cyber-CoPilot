import asyncio
import inspect
import sys
import types

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "asyncio: run async test functions")


@pytest.fixture(autouse=True)
def clear_tool_cache():
    try:
        from src.sdk.cache import get_tool_cache

        get_tool_cache().clear()
    except Exception:
        pass


@pytest.fixture
def fake_exploit_craft(mocker):
    module = types.ModuleType("src.tools.exploit_craft")
    module.generate_exploit_code = mocker.Mock()
    module.generate_exploit_code.invoke = mocker.AsyncMock(return_value="generated")
    mocker.patch.dict(sys.modules, {"src.tools.exploit_craft": module})
    return module.generate_exploit_code


def pytest_pyfunc_call(pyfuncitem):
    test_func = pyfuncitem.obj
    if not inspect.iscoroutinefunction(test_func):
        return None

    kwargs = {
        name: pyfuncitem.funcargs[name]
        for name in pyfuncitem._fixtureinfo.argnames
    }
    asyncio.run(test_func(**kwargs))
    return True
