def makefile(text: str, filename: str) -> None:
    """
    makefile takes a string and turns it into a utf-8 file

    :param text: string to be turned into a file
    :param filename: name of the file to be written to
    :return: None, output is written to a file
    """   
    with open(filename, "w", encoding="utf-8") as f:
        f.write(text)

def txtToString(filename: str) -> str:
    """
    fileToString takes a utf-8 file and turns it into a str

    :param filename: name of the file to be read
    :return: str of the read content
    """ 
    with open(filename, "r", encoding="utf8") as f:
        content = f.read()
        return content
