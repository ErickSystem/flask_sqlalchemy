from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.mysql import BOOLEAN
from sqlalchemy import Column, Integer, String
from connect import Connection
import uuid
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisissecret'
Base = declarative_base() 
 
class Users(Base):
    __tablename__ = 'users'
 
    id = Column(Integer, primary_key=True)
    public_id = Column(String(50), unique=True)
    name = Column(String(50), nullable=False)
    password = Column(String(80), nullable=False)
    admin = Column(BOOLEAN)
 
    def __init__(self, public_id, name, password, admin):
        self.public_id = public_id
        self.name = name
        self.password = password
        self.admin = admin

class Conteudo(Base):
    __tablename__ = 'conteudo'

    id = Column(Integer, primary_key=True)
    texto = Column(String(50))
    complete = Column(BOOLEAN) 
    user_id = Column(Integer)

    def __init__(self, id, texto, complete, user_id):
        self.id = id
        self.texto = texto
        self.complete = complete
        self.user_id = user_id

connection = Connection.session()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'access-token' in request.headers:
            token = request.headers['access-token']
        if not token:
            return jsonify({'mensagem' : 'Está faltando informar o token'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = connection.query(Users).filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'mensagem' : 'Token é inválido ou expirou!'}), 401
    
        return f(create_user, *args, **kwargs)

    return decorated
                                                                                           
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    #if current_user.admin == False:
       # return jsonify({'mensagem' : 'Você não tem permissão para acessar essa função'})

    all_users = connection.query(Users).all()
    output = []

    for user in all_users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_on_user(current_user,public_id):
    user = connection.query(Users).filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'mensagem' : 'Usuário não encontrado!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    #cria o public_id utilizando ramdon e o password criptografado com hash
    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    connection.add(new_user)
    connection.commit()

    return jsonify({'mensagem' : 'Novo usuário criado!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
    user = connection.query(Users).filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'mensagem' : 'Usuário não encontrado!'})
    
    user.admin = True
    connection.commit()

    return jsonify({'mensagem' : 'Usuário foi promovido para Admin!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):
    user = connection.query(Users).filter_by(public_id=public_id).first()

    if not user:
       return jsonify({'mensagem' : 'Usuário não encontrado!'})

    connection.delete(user)
    connection.commit()

    return jsonify({'mensagem' : 'Usuário foi deletado com sucesso!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Não pode verificar', 401, {'WWW-Authenticate' : 'Basic realm="Login requerido!"'})

    user = connection.query(Users).filter_by(name=auth.username).first()
    if not user:
        return make_response('Não pode verificar', 401, {'WWW-Authenticate' : 'Basic realm="Login requerido!"'})
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Não pode verificar', 401, {'WWW-Authenticate' : 'Basic realm="Login requerido!"'})

@app.route('/conteudo', methods=['GET'])
@token_required
def get_all_conteudo(current_user):
    all_conteudo = connection.query(Conteudo).all()
    output = []

    for conteudo in all_conteudo:
        conteudo_data = {}
        conteudo_data['id'] = conteudo.id
        conteudo_data['texto'] = conteudo.texto
        conteudo_data['complete'] = conteudo.complete
        conteudo_data['user_id'] = conteudo.user_id
        output.append(conteudo_data)

    return jsonify({'conteudos' : output})

@app.route('/conteudo/<id>', methods=['GET'])
@token_required
def get_one_conteudo(current_user,id):

    conteudo = connection.query(Conteudo).filter_by(id=id).first()

    if not conteudo:
        return jsonify({'mensagem' : 'Conteudo não encontrado!'})

    conteudo_data = {}
    conteudo_data['id'] = conteudo.id
    conteudo_data['texto'] = conteudo.texto
    conteudo_data['complete'] = conteudo.complete
    conteudo_data['user_id'] = conteudo.user_id
    
    return jsonify({'conteudo' : conteudo_data})

@app.route('/conteudo', methods=['POST'])
@token_required
def create_conteudo(current_user):
    data = request.get_json()

    new_conteudo = Conteudo(texto=data['texto'], complete=False, user_id=data['user_id'])
    connection.add(new_conteudo)
    connection.commit()

    return jsonify({'mensagem' : 'Conteudo criado!'})

@app.route('/conteudo/<id>', methods=['PUT'])
@token_required
def complete_conteudo(create_user,id):
    conteudo = connection.query(Conteudo).filter_by(id=id).first()

    if not conteudo:
        return jsonify({'mensagem' : 'Conteudo não encontrado!'})
    
    conteudo.complete = True
    connection.commit()

    return jsonify({'mensagem' : 'Complete atualizado!'})

@app.route('/conteudo/<id>', methods=['DELETE'])
@token_required
def delete_conteudo(create_user,id):
    conteudo = connection.query(Conteudo).filter_by(id=id).first()

    if not conteudo:
        return jsonify({'mensagem' : 'Conteudo não encontrado!'})

    connection.delete(conteudo)
    connection.commit()

    return jsonify({'mensagem' : 'Conteudo excluído com sucesso!'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
