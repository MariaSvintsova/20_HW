from unittest.mock import MagicMock

import pytest


from dao.genre import GenreDAO
from dao.model.genre import Genre
from service.genre import GenreService

"""Фикстура с мокированием GenreDAO"""
@pytest.fixture()
def genre_dao():
    genre = GenreDAO(None)
    genre1 = Genre(id=1, name='Ivan')
    genre2 = Genre(id=2, name='Peter')
    genre3 = Genre(id=3, name='Nikolai')
    genre.get_one = MagicMock(return_value=genre1)
    genre.get_all = MagicMock(return_value=[genre1, genre2, genre3])
    genre.delete = MagicMock()
    genre.create = MagicMock()
    genre.update = MagicMock()
    return genre


"""Класс с тестами для GenreService"""
class TestGenreService:
    
    @pytest.fixture()
    def genre_service(self, genre_dao):
        gs = GenreService(dao=genre_dao)
        return gs
    def test_get_one(self, genre_service):
        assert genre_service.get_one(1)['name'] == 'Ivan'

    def test_get_all(self, genre_service):
        assert genre_service.get_all()[1]['name'] == 'Peter'

    def test_delete(self, genre_service):
        assert genre_service.delete(3) != None

    def test_update(self, genre_service):
        assert genre_service.update(7) != None

    def test_create(self, genre_service):
        assert genre_service.create(5) != None
