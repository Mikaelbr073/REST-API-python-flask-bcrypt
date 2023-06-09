from flask_restful import Resource, reqparse
from models.hotel import HotelModel
from flask_jwt_extended import jwt_required
import sqlite3
from resources.filtros import normalize_path_params, consulta_com_cidade, consulta_sem_cidade

path_params = reqparse.RequestParser()
path_params.add_argument('cidade', type=str, location='args')
path_params.add_argument('estrelas_min', type=float)
path_params.add_argument('estrelas_max', type=float)
path_params.add_argument('diaria_min', type=float)
path_params.add_argument('diaria_max', type=float)
path_params.add_argument('limit', type=float)
path_params.add_argument('offset', type=float)

class Hoteis(Resource):
    def get(self):
        connection = sqlite3.connect('banco.db')
        cursor = connection.cursor()

        dados = path_params.parse_args()
        dados_validos = {chave:dados[chave] for chave in dados if dados[chave] is not None}
        parametros = normalize_path_params(**dados_validos)

        if not parametros.get('cidade'):
            tupla = tuple([parametros[chave] for chave in parametros])
            resultado = cursor.execute(consulta_sem_cidade, tupla)
        else:
            tupla = tuple([parametros[chave] for chave in parametros])
            resultado = cursor.execute(consulta_com_cidade, tupla)

        hoteis = []
        for linha in resultado:
            hoteis.append({
            'hotel_id': linha[0],
            'nome': linha[1],
            'estrelas': linha[2],
            'diaria': linha[3],
            'cidade': linha[4]
            })

        print(hoteis)

        return {'hoteis': hoteis} # SELECT * FROM hoteis

class Hotel(Resource):

    argumentos = reqparse.RequestParser()
    nomes_argumentos = ['nome', 'estrelas', 'diaria', 'cidade']

    for nome_argumento in nomes_argumentos:
        argumentos.add_argument(nome_argumento, type=str, required=True, help="the fields cannot left be blank")

    
    def get(self, hotel_id):
        hotel = HotelModel.find_hotel(hotel_id)
        if hotel:
            return hotel.json()
        return {'menssage': 'Hotel not found.'}, 404

    @jwt_required()
    def post(self, hotel_id):

        if HotelModel.find_hotel(hotel_id):
            return {'message': 'Hotel id {} already exist'.format(hotel_id)}, 400 #bad 
        
        dados = Hotel.argumentos.parse_args()
        hotel = HotelModel(hotel_id, **dados)
        try:
            hotel.save_hotel()
        except:
            return {'menssage': 'An internal erro ocurred trying to save'}, 500
        return hotel.json()

    @jwt_required()
    def put(self, hotel_id):
        dados = Hotel.argumentos.parse_args()

        hotel_encontrado = HotelModel.find_hotel(hotel_id)
        
        if hotel_encontrado:
            hotel_encontrado.update_hotel(**dados)
            hotel_encontrado.save_hotel()
            return hotel_encontrado.json(), 200 #OK
            
        hotel = HotelModel(hotel_id, **dados)
        try:
            hotel.save_hotel()
        except:
            return {'menssage': 'An internal erro ocurred trying to save'}, 500
        return hotel.json(), 201 #create
    @jwt_required()
    def delete(self, hotel_id):
       hotel = HotelModel.find_hotel(hotel_id)
       if hotel:
            try:
                hotel.delete_hotel()
            except:
                return {'menssage': 'An error ocurred trying to delete'}
            return {'menssage': 'Hotel deleted'}, 200 
       return {'menssage': 'Hotel not found'}, 404
 
        