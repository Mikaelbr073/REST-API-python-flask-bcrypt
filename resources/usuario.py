from flask_restful import Resource, reqparse
from models.usuario import UserModel
from flask_jwt_extended import create_access_token, jwt_required, get_jwt
from blacklist import BLACKLIST
import bcrypt

atributos = reqparse.RequestParser()
atributos.add_argument('login', type=str, required=True, help="The field 'login' cannot be left blank")
atributos.add_argument('senha', type=str, required=True, help="The field 'login' cannot be left blank")

class User(Resource):

    def get(self, user_id):
        user = UserModel.find_user(user_id)
        if user:
            return user.json()
        return {'menssage': 'user not found.'}, 404
        
    @jwt_required()
    def delete(self, user_id):
       user = UserModel.find_user(user_id)
       if user:
            user.delete_user()
            return {'menssage': 'User deleted'}, 200 
       return {'menssage': 'Hotel not found'}, 404
 
class UserRegister(Resource):

    def post(self):
        dados = atributos.parse_args()
        if UserModel.find_by_login(dados['login']):
            return{"messege": "The login {} already exists".format(dados['login'])}
        password = dados['senha'].encode('utf-8')
        hash = bcrypt.hashpw(password, bcrypt.gensalt())
        user = UserModel(dados['login'], hash)
        user.save_user()
        return {'menssage': 'User created successfully!'}, 201

class UserLogin(Resource):
    @classmethod
    def post(cls):
        dados = atributos.parse_args()
        user = UserModel.find_by_login(dados['login'])
        userPassword = dados['senha'].encode('utf-8')
        if user and bcrypt.checkpw(userPassword, user.senha):
            token_acesso = create_access_token(identity=user.user_id)
            return {'access_token': token_acesso}, 200
        return {'message': 'The username or pasword is incorrect.'}, 401 

class UserLogout(Resource):
    @jwt_required()
    def post(self):
        jwt_id = get_jwt()['jti'] #JWT Token Indetifier
        BLACKLIST.add(jwt_id)
        return {'message': 'logged out successfully'}, 200







