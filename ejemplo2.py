#este codigo exporta el archivo security.cfgpara probar con el archivo security,cfg 
#tiene las recomendaciones del 1 al 10 esta en ese archivo security.cfg 
import subprocess
import re

def obtener_valor_historial_contraseñas(variable_a_comparar,valor_a_comparar):
    try:
        # Ejecutar el comando secedit para consultar la configuración de seguridad y esto  guarda el archivo security.cfg en la carpeta designada
        resultado = subprocess.check_output("C:\\Windows\\System32\\secedit /export /cfg C:\\Users\\crist\\OneDrive\\Desktop\\TG\\Python\\security.cfg", shell=True)
        
        # Leer el archivo de configuración exportado
        archivo_cfg = "security.cfg"
        archivo_txt = "security.txt"
        #valor_a_comparar = 1
        #variable_a_comparar = "MinimumPasswordAge"

        with open(archivo_cfg, 'r') as entrada:
            with open(archivo_txt, 'w') as salida:
                # Lee el contenido del archivo cfg y limpia los caracteres especiales
                for linea in entrada:
                    # Utiliza una expresión regular para eliminar caracteres especiales, excepto el "="
                    linea_limpia = re.sub(r'[^a-zA-Z0-9\s=]', '', linea)
                    # Divide la línea en palabras usando el signo "=" como separador
                    palabras = linea_limpia.split('=')
                    # Si hay al menos dos palabras (nombre de variable y valor)
                    if len(palabras) >= 2:
                        nombre_variable = palabras[0].strip()
                        valor_variable = palabras[1].strip()
                        salida.write(f"{nombre_variable} = {valor_variable}\n")
                        
                        # Compara el valor con el valor_a_comparar
                        if nombre_variable == variable_a_comparar:
                            valor_variable = int(valor_variable)
                            if valor_variable == valor_a_comparar:
                                return valor_a_comparar
                            else: return False
        return "No se encontró la configuración de historial de contraseñas."

    except subprocess.CalledProcessError as e:
        return f"Error al obtener la configuración: {e}"

if __name__ == "__main__":
    print(obtener_valor_historial_contraseñas("MaximumPasswordAge",24))
   