from flask_restx import Resource, Namespace
from implemented import genre_service
from flask import request
from views.auth import auth_reqiured, admin_required

genres_ns = Namespace('genres')

@genres_ns.route('/')
class GenreView(Resource):
    @auth_reqiured
    def get(self):
        genres = genre_service.get_all()
        return genres, 200

    @admin_required
    def post(self):
        data = request.json
        genre = genre_service.create(data)
        return genre, 201

@genres_ns.route('/<gid>')
class GenreView(Resource):
    @auth_reqiured
    def get(self, gid):
        gen = genre_service.get_one(gid)
        return gen, 201

    @admin_required
    def put(self, gid):
        data = request.json
        genre_service.update(data)
        return '', 201

    @admin_required
    def delete(self, gid):
        print(1)
        genre_service.delete(gid)
        return '', 204