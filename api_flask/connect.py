from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

class Connection:
 
    def session():
 
        try:
            connection_string = 'mysql+pymysql://%s:%s@%s:%s/%s' % (
            "root", #nome do seu usuário no banco
            "abc123", #senha do banco
            "127.0.0.1", #ip/host que seu banco está hospedado, no meu caso aqui ele está local
            "3306", #porta
            "api_study" #nome do seu database
            )
             # echo = True, ativa debug
            engine = create_engine(connection_string, echo=False)
            Session = sessionmaker(bind=engine)
 
            return Session()

        except:
            print("Não foi possível se conectar a base de dados")
 
        