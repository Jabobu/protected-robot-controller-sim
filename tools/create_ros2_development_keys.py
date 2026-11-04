"""Create separate disposable local development identities; never use in TA."""
import argparse
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('directory')
args = p.parse_args()
directory = Path(args.directory)
directory.mkdir(mode=0o700, parents=True, exist_ok=False)
server, client = directory / 'server', directory / 'client'
server.mkdir(mode=0o700)
client.mkdir(mode=0o700)
for role, private_dir, public_dir in (('authority', client, server), ('evidence', server, client)):
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    descriptor = os.open(private_dir / (role + '.pem'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(private)
    (public_dir / (role + '.der')).write_bytes(public)
print('Created separate disposable development keys in', directory)
