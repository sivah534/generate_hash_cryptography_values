from cryptography.hazmat.primitives import hashes
import os

# Replace below path with your path, where your files resides
files_path = "C:\\Users\\sam\\Downloads\\samba_files"
files: list = os.listdir(files_path)
print(f"Files:: \n {files}")


def md5_hash(file):
    """
    Function used to generate MD5 hash
    :param file: Give the file name to generate the hash
    :return: md5 hash
    """
    md5_hash = hashes.Hash(hashes.MD5())
    md5_hash.update(file)
    md5_out = md5_hash.finalize()
    return md5_out


def sha256_hash(file):
    """
    Function used to generate SHA256 Hash
    :param file: Give the file name to generate the hash
    :return: SHA256 Hash
    """
    sha256_hash = hashes.Hash(hashes.SHA256())
    sha256_hash.update(file)
    sha256_hash_out = sha256_hash.finalize()
    return sha256_hash_out


def sha3_224_hash(file):
    """
    Function used to generate the SHA2 224 hash
    :param file: Give the file name to generate the hash
    :return: SHA3 224 hash
    """
    SHA3_224_hash = hashes.Hash(hashes.SHA3_224())
    SHA3_224_hash.update(file)
    SHA3_224hash_out = SHA3_224_hash.finalize()
    return SHA3_224hash_out


def generate_hashes():
    hashes_report = list()
    for i in files:
        with open(f'{files_path}\{i}', "rb") as f:
            bfile = f.read()
            md5 = md5_hash(bfile)
            sha256 = sha256_hash(bfile)
            sha3 = sha3_224_hash(bfile)
            hashes_report.append([i, sha256, sha3, md5])
    return hashes_report


if __name__ == "__main__":
    with open('hashes.txt', 'w') as f:
        for i in generate_hashes():
            f.write(f"{i}\n")
