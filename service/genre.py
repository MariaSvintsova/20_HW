from dao.genre import GenreDAO
from dao.model.genre import GenreSchema

genre_schema = GenreSchema()
genres_schema = GenreSchema(many=True)
class GenreService:
    def __init__(self, dao: GenreDAO):
        self.dao = dao

    def get_one(self, bid):
        return genre_schema.dump(self.dao.get_one(bid))

    def get_all(self):
        return genres_schema.dump(self.dao.get_all())

    def create(self, genre_d):
        return genre_schema.dump(self.dao.create(genre_d))

    def update(self, genre_d):
        self.dao.update(genre_d)
        return ''

    def delete(self, rid):
        self.dao.delete(rid)
        return ''
