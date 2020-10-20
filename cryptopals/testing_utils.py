import random

import pytest


@pytest.yield_fixture
def reproducible_randomness():
    """
    Tests using this fixture will produce consistent "random" values
    """
    some_previous_randomness = random.random()
    random.seed('make things predictable')
    yield
    # return unpredictability again
    random.seed(some_previous_randomness)

def param_by_functions(arg_name, functions):
    return pytest.mark.parametrize(
        arg_name,
        functions,
        ids=[func.__name__ for func in functions])
