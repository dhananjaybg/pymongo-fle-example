import os
from pymongo import MongoClient
from pymongo.encryption_options import AutoEncryptionOpts
from pymongo.encryption import ClientEncryption
import base64
from bson.codec_options import CodecOptions
from bson.binary import STANDARD, UUID
from pprint import pprint


class BuildEncryption:
    def __init__(self, master_file_path):
        self.client = MongoClient("mongodb://localhost:27017")
        self.db = 'encryption'
        self.collection = '__keyVault'
        self.key_vault_namespace = f"{self.db}.{self.collection}"
        self.master_file_path = master_file_path

    def create_master_key(self):
        file_bytes = os.urandom(96)
        with open(self.master_file_path, "wb") as f:
            f.write(file_bytes)


    def create_kms_provider(self):
        with open(self.master_file_path, "rb") as f:
            local_master_key = f.read()

        kms_providers = {
            "local": {
            "key": local_master_key # local_master_key variable from the previous step
            }
        }

        return kms_providers


    def create_data_encryption_key(self):
        client_encryption = ClientEncryption(
            self.create_kms_provider(), # pass in the kms_providers variable from the previous step
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


if __name__ == '__main__':
    encrypt = BuildEncryption(master_file_path="key.txt")

    encrypt.create_master_key()

    data_key_id = encrypt.create_data_encryption_key()

    encrypt.test(data_key_id=data_key_id)
