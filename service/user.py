import base64
import hashlib

from dao.model.user import UserSchema
from dao.user import UserDAO
from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS

user_schema = UserSchema()
users_schema = UserSchema(many=True)
class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return user_schema.dump(self.dao.get_one(uid))

    def get_all(self):
        return users_schema.dump(self.dao.get_all())

    def create(self, user_d):
        passw = user_d.get('password')
        new_pass = self.get_hash(passw)
        user_d['password'] = new_pass

        return user_schema.dump(self.dao.create(user_d))

    def update(self, user_d):
        self.dao.update(user_d)
        return ''

    def delete(self, uid):
        self.dao.delete(uid)
        return ''

    def get_hash(self, password):
        digest = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        )
        return base64.b64encode(digest)


