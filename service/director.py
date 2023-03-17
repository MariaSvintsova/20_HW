from dao.director import DirectorDAO
from dao.model.director import DirectorSchema


director_schema = DirectorSchema()
directors_schema = DirectorSchema(many=True)


class DirectorService:
    def __init__(self, dao: DirectorDAO):
        self.dao = dao

    def get_one(self, bid):
        return director_schema.dump(self.dao.get_one(bid))

    def get_all(self):
        return directors_schema.dump(self.dao.get_all())

    def create(self, director_d):
        return director_schema.dump(self.dao.create(director_d))

    def update(self, director_d):
        self.dao.update(director_d)
        return ''

    def delete(self, rid):
        self.dao.delete(rid)
        return ''