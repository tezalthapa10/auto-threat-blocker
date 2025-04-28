from pymongo import MongoClient
import yaml
import os

# Load config
config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'config.yml')
with open(config_path, 'r') as file:
    config = yaml.safe_load(file)

mongo_conf = config['mongodb']

# MongoDB connection string with authentication
uri = f"mongodb://{mongo_conf['admin']}:{mongo_conf['hello12']}@{mongo_conf['host']}:{mongo_conf['port']}/"

# Connect to MongoDB
client = MongoClient(uri)

# Access the database
db = client[mongo_conf['database']]
