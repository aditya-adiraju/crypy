import pytest
from crypy.arith import *


@pytest.mark.parametrize('nums,expected', [
    ((0, 2), 2),
    ((97, 100), 1),
    ((6, 9, 12), 3),
    ((2, 4, 6, 8), 2),
    ((-6, 9), 3),
    ((0, 5), 5),
    ((2**64 - 1, 2**32 - 1), 2**32 - 1),
])
def test_igcd(nums, expected):
    assert igcd(*nums) == expected

def test_igcdex():
    assert igcdex(2, 3) == (1, -1, 1)
    assert igcdex(10, 12) == (2, -1, 1)
    assert igcdex(100, 2004) == (4, -20, 1)

def test_ilcm():
    assert ilcm(0, 2) == 0
    assert ilcm(97, 100) == 9700
    assert ilcm(-3, -5) == 15
    assert ilcm(1, 2, 3, 4, 5) == 60

def test_iroot():
    assert iroot(0, 1) == 0
    assert iroot(1, 1) == 1
    assert iroot(16, 2) == 4
    assert iroot(26, 2) == 5
    assert iroot(83, 4) == 3

def test_icrt():
    assert icrt((1, 2), (3, 4)) == (3, 4)
    assert icrt((2, 3), (3, 5)) == (8, 15)
    assert icrt((10, 30), (30, 50)) == (130, 150)

    with pytest.raises(ValueError):
        icrt((0, 2), (1, 4))
    with pytest.raises(ValueError):
        icrt((1, 4), (2, 6))
