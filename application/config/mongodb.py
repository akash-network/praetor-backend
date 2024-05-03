from pymongo import MongoClient
from application.config.config import Config

# mongo client to connect with the db
mongo_client = MongoClient(Config.MONGO_DB_CONNECTION_STRING)

# mongo db connection
praetor_db = mongo_client[f"{Config.MONGO_DB_NAME}"]

# connection with respective collections
providers_collection = praetor_db["providers"]
sessions_collection = praetor_db["sessions"]
system_collection = praetor_db["system"]
