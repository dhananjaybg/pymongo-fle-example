import os
from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.encryption import Algorithm, ClientEncryption
import base64
from bson.codec_options import CodecOptions
from bson.binary import STANDARD, UUID
from pprint import pprint
from collections import OrderedDict


class BuildEncryption:
    def __init__(self, master_file_path):
        self.client = MongoClient("mongodb://localhost:27017")
        self.db = 'encryption'
        self.collection = '__keyVault'
        self.key_vault_namespace = f"{self.db}.{self.collection}"
        self.master_file_path = master_file_path

    def create_kms_provider(self):
        file_bytes = os.urandom(96)

        with open(self.master_file_path, "wb") as f:
            f.write(file_bytes)

        with open(self.master_file_path, "rb") as f:
            local_master_key = f.read()

            kms_providers = {
                "local": {
                    "key": local_master_key  # local_master_key variable from the previous step
                }
            }

            return kms_providers

    def create_data_encryption_key(self, kms_providers):
        client_encryption = ClientEncryption(
            # pass in the kms_providers variable from the previous step
            kms_providers,
            self.key_vault_namespace,
            self.client,
            CodecOptions(uuid_representation=STANDARD)
        )

        data_key_id = client_encryption.create_data_key("local")
        uuid_data_key_id = UUID(bytes=data_key_id)
        base_64_data_key_id = base64.b64encode(data_key_id)
        return data_key_id

    def test(self, data_key_id):
        key_vault = self.client[self.db][self.collection]
        # Pass in the data_key_id created in previous section
        key = key_vault.find_one({"_id": data_key_id})
        pprint(key)

    def create_schema(self, data_key_id):
        db = self.client.test
        collection = 'persons'
        user_schema = {
            "ssn": {
                "encrypt": {
                    "keyId": [data_key_id],
                    "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                    "bsonType": "string"
                }
            }
        }

        validator = {
            '$jsonSchema': {
                'bsonType': 'object',
                'properties': user_schema
            }
        }

        query = [('collMod', collection), ('validator', validator)]
        db.command(OrderedDict(query))
        return user_schema


class EncryptedConnection:
    def __init__(self, kms, schema):
        key_vault_namespace = "encryption.__keyVault"

        extra_options = {}

        fle_opts = AutoEncryptionOpts(
            kms,
            key_vault_namespace,
            schema_map=schema,
            **extra_options
        )
        self.client = MongoClient(
            "mongodb://localhost:27017", auto_encryption_opts=fle_opts)
        self.collection = self.client['test']['persons']

    def insert(self, name, ssn):
        user = {
            'name': name,
            'ssn': ssn
        }
        self.collection.insert_one(user)


if __name__ == '__main__':
    path = 'key.txt'
    encrypt = BuildEncryption(master_file_path=path)

    kms = encrypt.create_kms_provider()
    data_key_id = encrypt.create_data_encryption_key(kms_providers=kms)

    encrypt.test(data_key_id=data_key_id)
    schema = encrypt.create_schema(data_key_id=data_key_id)

    client = EncryptedConnection(kms=kms, schema=schema)
    client.insert(name="John", ssn="123")
