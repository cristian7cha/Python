import subprocess

def abrir_editor_directivas_grupo_local():
    try:
        subprocess.Popen("gpedit.msc", shell=True)
        return "Editor de Directivas de Grupo Local abierto."
    except Exception as e:
        return f"Error al abrir el Editor de Directivas de Grupo Local: {str(e)}"

if __name__ == "__main__":
    resultado = abrir_editor_directivas_grupo_local()
    print(resultado)