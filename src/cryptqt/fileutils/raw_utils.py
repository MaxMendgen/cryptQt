#this piece of shit breaks encryption format (text me for more info)

import base64
def file_to_string(filename: str) -> str:
    with open(filename, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")
