import os
from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.encryption import Algorithm, ClientEncryption
import base64
from bson.codec_options import CodecOptions
from bson.binary import STANDARD, UUID
from collections import OrderedDict

mongo_url = "mongodb://localhost:27017"
db = "medicalRecords"
collection = "patients"


class BuildEncryption:
    def __init__(self, master_file_path):
        self.client = MongoClient(mongo_url)
        self.db = 'encryption'
        self.collection = '__keyVault'
        self.key_vault_namespace = f"{self.db}.{self.collection}"
        self.master_file_path = master_file_path

    def create_kms_provider(self):
        file_bytes = os.urandom(96)
        # create master key
        with open(self.master_file_path, "wb") as f:
            f.write(file_bytes)
            print(f'master key created: {self.master_file_path} \n')
        # read master key and build KMS dict
        with open(self.master_file_path, "rb") as f:
            local_master_key = f.read()

            kms_providers = {
                "local": {
                    "key": local_master_key  # local_master_key variable from the previous step
                }
            }
            print(f'KMS provider created using local master key: {kms_providers} \n')

            return kms_providers

    def create_data_encryption_key(self, kms_providers):
        # create data encryption key and store in DB
        client_encryption = ClientEncryption(
            # pass in the kms_providers variable from the previous step
            kms_providers,
            self.key_vault_namespace,
            self.client,
            CodecOptions(uuid_representation=STANDARD)
        )
        data_key_id = client_encryption.create_data_key("local")
        uuid_data_key_id = UUID(bytes=data_key_id)
        print(f'data key created using KMS provider: {uuid_data_key_id} \n')

        base_64_data_key_id = base64.b64encode(data_key_id)
        return data_key_id

    def test(self, data_key_id):
        key_vault = self.client[self.db][self.collection]
        # grab the data encryption key
        key = key_vault.find_one({"_id": data_key_id})
        print(f'data encryption key: {key} \n')

    def create_schema(self, data_key_id):
        user_schema = {
            "ssn": {
                "encrypt": {
                    "keyId": [data_key_id],
                    "algorithm": Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic,
                    "bsonType": "string"
                }
            },
            "blood_type": {
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
        print(f'validator created: {validator} \n')

        query = [('collMod', collection), ('validator', validator)]
        self.client[db].command(OrderedDict(query))
        return user_schema


class EncryptedConnection:
    def __init__(self, kms, schema):
        key_vault_namespace = "encryption.__keyVault"

        fle_opts = AutoEncryptionOpts(
            kms,
            key_vault_namespace,
            schema_map=schema,
            **{}
        )
        self.client = MongoClient(mongo_url, auto_encryption_opts=fle_opts)
        self.collection = self.client[db][collection]
        print(f'encrypted connection initiated. \n')

    def insert(self, **kwargs):
        self.collection.insert_one(kwargs)
        print(f'user inserted: {kwargs} \n')

    def find(self, **kwargs):
        return self.collection.find_one(kwargs)


if __name__ == '__main__':
    path = 'key.txt'
    # instatiate encryption class with the path to local key file
    encrypt = BuildEncryption(master_file_path=path)
    # create KMS provider using a randomly generated master key
    kms = encrypt.create_kms_provider()
    # generate data key and push to mongo __keyVault
    data_key_id = encrypt.create_data_encryption_key(kms_providers=kms)
    # test encryption key
    encrypt.test(data_key_id=data_key_id)
    # create schema validator for individual fields
    schema = encrypt.create_schema(data_key_id=data_key_id)
    # open an encrypted connection with schema
    client = EncryptedConnection(kms=kms, schema=schema)

    patient_object = {
        "name": "John",
        "blood_type": "O Negative",
        "ssn": "123"
    }

    client.insert(**patient_object)

    result = client.find(ssn=patient_object['ssn'])
    print(f'thru the wire, encrypted result: {result}')
