from unittest.mock import MagicMock

import pytest

from dao.model.movie import Movie
from dao.movie import MovieDAO
from service.movie import MovieService


"""Фикстура с мокированием MovieDAO"""
@pytest.fixture()
def mock_movie_dao():
    movie = MovieDAO(None)
    movie1 = Movie(id=1, title='XXXX', description='good', trailer='н', year=1000, rating=12.3, genre_id=3, director_id=1)
    movie2 = Movie(id=2, title='YYYY', description='good', trailer='н', year=1000, rating=12.3, genre_id=3, director_id=1)
    movie3 = Movie(id=3, title='ZZZZ', description='good', trailer='н', year=1000, rating=12.3, genre_id=3, director_id=1)
    movie.get_one = MagicMock(return_value=movie1)
    movie.get_all = MagicMock(return_value=[movie1, movie2, movie3])
    movie.delete = MagicMock()
    movie.create = MagicMock()
    movie.update = MagicMock()
    movie.get_by_director_id = MagicMock(return_value=movie1)
    movie.get_by_year = MagicMock(return_value=movie1)
    movie.get_by_genre_id = MagicMock(return_value=movie2)
    return movie

"""Класс с тестами для MovieService"""
class TestsMovieService:
    @pytest.fixture()
    def movie_service(self, mock_movie_dao):
        ms = MovieService(dao=mock_movie_dao)
        return ms
        
    def test_get_one(self, movie_service):
        assert movie_service.get_one(1).title == 'XXXX'

    def test_get_all(self, movie_service):
        assert movie_service.get_all({})[1].title == 'YYYY'

    # def test___(self, movie_service):
    #     assert len(movie_service.get_all({'director_id': 1})) == 3

    def test_delete(self, movie_service):
        assert movie_service.delete(3) is None

    def test_update(self, movie_service):
        assert movie_service.update(7) != None

    def test_create(self, movie_service):
        assert movie_service.create(5) != None

    # def test_by_director(self, movie_service):
    #     assert movie_service.get_by_director_id(1) != None
    #
    # def test_get_by_genre_id(self, movie_service):
    #     assert movie_service.get_by_genre_id(3) != None
    #
    # def test_get_by_year(self, movie_service):
    #     assert movie_service.get_by_year(1000) != None