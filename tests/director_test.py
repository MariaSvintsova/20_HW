from unittest.mock import MagicMock

import pytest as pytest

from dao.director import DirectorDAO
from dao.model.director import Director
from service.director import DirectorService


"""Фикстура с мокированием DirectorDAO"""

@pytest.fixture()
def director_dao():
    di = DirectorDAO(None)
    d1 = Director(id=1, name='Ivan')
    d2 = Director(id=2, name='Peter')
    d3 = Director(id=3, name='Nikolai')
    di.get_one = MagicMock(return_value=d1)
    di.get_all = MagicMock(return_value=[d1, d2, d3])
    di.delete = MagicMock()
    di.create = MagicMock()
    di.update = MagicMock()
    return di

"""Класс с тестами для DirectorService"""
class TestDirectorService:
    
    @pytest.fixture()
    def director_service(self, director_dao):
        ds = DirectorService(dao=director_dao)
        return ds
    def test_get_one(self, director_service):
        assert director_service.get_one(1)['name'] == 'Ivan'

    def test_get_all(self, director_service):
        assert director_service.get_all()[1]['name'] == 'Peter'

    def test_delete(self, director_service):
        assert director_service.delete(3) != None

    def test_update(self, director_service):
        assert director_service.update(7) != None

    def test_create(self, director_service):
        assert director_service.create(5) != None


