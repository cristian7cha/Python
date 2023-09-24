import tkinter

def read_file(file):
    """Lee un archivo de texto y devuelve una lista con sus lineas"""
    lista = []
    with open(file) as procfile:
      for line in procfile:
        lista.append(line.strip())
    return list

read_file("Recomendacione.txt")
