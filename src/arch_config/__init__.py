import datetime
import logging
import os
import pathlib
import re
import shutil
import subprocess

BASE_DIR = pathlib.Path(__file__).parent.parent.parent.resolve()
SYSTEM_DIR = BASE_DIR / "system"
USER_DIR = BASE_DIR / "user"

logger = logging.getLogger(__name__)

class User:

    def __init__(self):
        self.home_dir = pathlib.Path.home()
        self._init_xdg_base()
        self.copy_xdg_user_dirs()
        self._init_xdg_user()

    def _init_xdg_base(self):
        defaults = {
            "CACHE": [".cache"],
            "CONFIG": [".config"],
            "DATA": [".local", "share"],
            "STATE": [".local", "state"],
        }

        self.xdg_base = {}
        for key in defaults.keys():
            var =  f"XDG_{key}_HOME"
            if var in os.environ:
                self.xdg_base[key] = pathlib.Path(os.environ[var])
            else:
                self.xdg_base[key] = self.home_dir.joinpath(*defaults[key])

    def copy_config_file(self, parts):
        repo_file = USER_DIR.joinpath("XDG_CONFIG_HOME", *parts)
        local_file = self.xdg_base["CONFIG"].joinpath(*parts)
        shutil.copyfile(repo_file, local_file)

    def copy_xdg_user_dirs(self):
        self.copy_config_file(["user-dirs.dirs"])
        self.copy_config_file(["user-dirs.locale"])

    def _init_xdg_user(self):
        defaults = {
            "DESKTOP": ["Desktop"],
            "DOCUMENTS": ["Documents"],
            "DOWNLOAD": ["Downloads"],
            "MUSIC": ["Music"],
            "PICTURES": ["Pictures"],
            "PUBLICSHARE": ["Public"],
            "TEMPLATES": ["Templates"],
            "VIDEOS": ["Videos"],
        }

        with open(self.xdg_base["CONFIG"] / "user-dirs.locale", "r") as f:
            if f.read().strip() != "C":
                logger.error("Only support C locale")
                exit(1)

        self.xdg_user = {}
        with open(self.xdg_base["CONFIG"] / "user-dirs.dirs", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#"):
                    continue
                m = re.match(r"XDG_([A-Z]+)_DIR=\"(\$HOME)?/(.*)\"", line)
                if not m:
                    logger.error(f"Invalid line: {line}")
                    exit(1)
                key = m.group(1)
                if key not in defaults:
                    logger.error(f"Invalid key: {key}")
                    exit(1)
                home = m.group(2)
                path = m.group(3)
                if home:
                    self.xdg_user[key] = self.home_dir / path
                else:
                    self.xdg_user[key] = pathlib.Path("/") / path

        for key in defaults.keys():
            if key not in self.xdg_user:
                logger.error(f"Missing key: {key}")
                exit(1)

    def copy_systemd_environment(self):
        self.copy_config_file(["environment.d", "00-xdg-base.conf"])

    def check_gpg_sec(self, fields):
        assert fields[0] == "sec"
        validity = fields[1]
        key_length = fields[2]
        public_key_algorithm = int(fields[3])
        key_id = fields[4]
        creation_date = int(fields[5])
        expiration_date = int(fields[6])
        owner_trust = fields[8]
        key_capabilities = fields[11]
        serial_number = fields[14]
        curve_name = fields[16]
        origin = fields[19]

        for i, field in enumerate(fields):
            if i in [0, 1, 2, 3, 4, 5, 6, 8, 11, 14, 16, 19]:
                continue
            assert field == ""

        print("# Primary Key")
        if validity == "u":
            print("  Validity: Ultimate")
        else:
            raise NotImplementedError
        print("  Key Length:", key_length)
        if public_key_algorithm == 22:
            print("  Public Key Algorithm: EdDSA")
        else:
            raise NotImplementedError
        print("  Key ID:", key_id)
        print("  Created:", datetime.datetime.utcfromtimestamp(creation_date).isoformat())
        print("  Expires:", datetime.datetime.utcfromtimestamp(expiration_date).isoformat())
        if owner_trust == "u":
            print("  Owner Trust: Ultimate")
        else:
            raise NotImplementedError
        print("  Key Capabilities:", key_capabilities)
        print("  Serial Number:", serial_number)
        print("  Curve Name:", curve_name)
        print("  Origin:", origin)

    def check_gpg_ssb(self, fields):
        assert fields[0] == "ssb"
        validity = fields[1]
        key_length = fields[2]
        public_key_algorithm = int(fields[3])
        key_id = fields[4]
        creation_date = int(fields[5])
        expiration_date = int(fields[6])
        key_capabilities = fields[11]
        serial_number = fields[14]
        curve_name = fields[16]

        for i, field in enumerate(fields):
            if i in [0, 1, 2, 3, 4, 5, 6, 11, 14, 16]:
                continue
            assert field == ""

        print("# Subkey")
        if validity == "u":
            print("  Validity: Ultimate")
        else:
            raise NotImplementedError
        print("  Key Length:", key_length)
        if public_key_algorithm == 18:
            print("  Public Key Algorithm: ECDH")
        elif public_key_algorithm == 22:
            print("  Public Key Algorithm: EdDSA")
        else:
            raise NotImplementedError
        print("  Key ID:", key_id)
        print("  Created:", datetime.datetime.utcfromtimestamp(creation_date).isoformat())
        print("  Expires:", datetime.datetime.utcfromtimestamp(expiration_date).isoformat())
        print("  Key Capabilities:", key_capabilities)
        print("  Serial Number:", serial_number)
        print("  Curve Name:", curve_name)

    def check_gpg_uid(self, fields):
        assert fields[0] == "uid"
        validity = fields[1]
        creation_date = int(fields[5])
        user_id_hash = fields[7]
        user_id = fields[9]
        origin = fields[19]

        for i, field in enumerate(fields):
            if i in [0, 1, 5, 7, 9, 19]:
                continue
            assert field == ""

        print("# User ID:")
        if validity == "u":
            print("  Validity: Ultimate")
        else:
            raise NotImplementedError
        print("  Created:", datetime.datetime.utcfromtimestamp(creation_date).isoformat())
        print("  User ID Hash:", user_id_hash)
        print("  User ID:", user_id)
        print("  Origin:", origin)

    def check_gpg_sig(self, fields):
        assert fields[0] == "sig"
        public_key_algorithm = int(fields[3])
        key_id = fields[4]
        creation_date = int(fields[5])
        user_id = fields[9]
        signature_class = fields[10]
        issuer_fingerprint = fields[12]
        hash_algorithm = int(fields[15])

        for i, field in enumerate(fields):
            if i in [0, 3, 4, 5, 9, 10, 12, 15]:
                continue
            assert field == ""

        assert key_id == issuer_fingerprint[-16:]

        # https://datatracker.ietf.org/doc/html/rfc4880
        assert len(signature_class) == 3
        signature_type = int(signature_class[0:2], base=16)
        assert signature_type in [0x13, 0x18]
        assert signature_class[2] == "x"

        print("# Signature")
        if public_key_algorithm == 22:
            print("  Public Key Algorithm: EdDSA")
        else:
            raise NotImplementedError
        print("  Key ID:", key_id)
        print("  Created:", datetime.datetime.utcfromtimestamp(creation_date).isoformat())
        print("  User ID:", user_id)
        if signature_type == 0x13:
            print("  Type: Positive Certification")
        elif signature_type == 0x18:
            print("  Type: Subkey Binding Signature") 
        print("  Issuer Fingerprint:", issuer_fingerprint)
        if hash_algorithm == 10:
            print("  Hash Algorithm: SHA512")
        else:
            raise NotImplementedError

    def check_gpg_fpr(self, fields):
        assert fields[0] == "fpr"
        fingerprint = fields[9]

        for i, field in enumerate(fields):
            if i in [0, 9]:
                continue
            assert field == ""

        print("Fingerprint:", fingerprint)

    def check_gpg_grp(self, fields):
        assert fields[0] == "grp"
        keygrip = fields[9]

        for i, field in enumerate(fields):
            if i in [0, 9]:
                continue
            assert field == ""

        print("Keygrip:", keygrip)

    def check_gpg(self):
        p = subprocess.run(
            ["gpg", "--batch", "--list-secret-keys", "--with-colons", "--with-sig-list"],
            capture_output=True, check=True, text=True
        )
        # https://github.com/gpg/gnupg/blob/master/doc/DETAILS
        for line in p.stdout.splitlines():
            fields = line.split(":")
            record_type = fields[0]
            if record_type == "sec":
                self.check_gpg_sec(fields)
            elif record_type == "ssb":
                self.check_gpg_ssb(fields)
            elif record_type == "uid":
                self.check_gpg_uid(fields)
            elif record_type == "sig":
                self.check_gpg_sig(fields)
            elif record_type == "fpr":
                self.check_gpg_fpr(fields)
            elif record_type == "grp":
                self.check_gpg_grp(fields)
            else:
                raise NotImplementedError

    def check(self):
        ignored_dirs = set()
        ignored_dirs.add(self.home_dir / 'developer')
        ignored_dirs.add(self.home_dir / '.mozilla')
        for xdg_base_dir in self.xdg_base.values():
            ignored_dirs.add(xdg_base_dir)
        for xdg_user_dir in self.xdg_user.values():
            ignored_dirs.add(xdg_user_dir)

        count = 0
        for root, dirs, files in os.walk(self.home_dir, topdown=True):
            for d in dirs[:]:
                p = pathlib.Path(root) / d
                if p in ignored_dirs:
                    dirs.remove(d)
            for f in files:
                p = pathlib.Path(root) / f
                print(p.relative_to(self.home_dir))
                count += 1
        message = f'{count} unknown files'
        print('-' * len(message))
        print(message)

def main():
    user = User()
    user.check()
    user.copy_systemd_environment()
    user.check_gpg()
    return 0
