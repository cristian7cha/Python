import subprocess

def obtener_configuracion_complejidad_contraseña():
    try:
        # Ejecutar el comando secedit para consultar la configuración de seguridad
        resultado = subprocess.check_output("secedit /export /cfg C:\\temp\\security.cfg", shell=True)
        
        # Leer el archivo de configuración exportado
        with open('C:\\temp\\security.cfg', 'r') as archivo_cfg:
            lineas = archivo_cfg.readlines()
            for linea in lineas:
                if "PasswordComplexity" in linea:
                    return linea.strip()
        
        return "No se encontró la configuración de contraseña de complejidad."

    except subprocess.CalledProcessError as e:
        return f"Error al obtener la configuración: {e}"

if __name__ == "__main__":
    configuracion = obtener_configuracion_complejidad_contraseña()
    print(configuracion)
