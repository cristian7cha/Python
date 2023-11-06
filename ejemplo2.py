import subprocess

# Ruta de la política que deseas verificar
ruta_politica = "MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr"

# Comando para obtener el valor de la política
comando = f'secedit /export /cfg c:\secedit.cfg && findstr /C:"{ruta_politica}" c:\secedit.cfg'

# Ejecutar el comando y capturar la salida
try:
    salida = subprocess.check_output(comando, shell=True)
    salida_decodificada = salida.decode('utf-8')
    lineas = salida_decodificada.splitlines()
    
    # Verificar si la política existe en la salida
    if lineas:
        # Obtener el valor de la política
        valor_politica = lineas[0].split('=')[1].strip()
        
        # Comparar el valor de la política con otro valor (por ejemplo, "1" para habilitado)
        valor_comparacion = "1"  # Cambia esto según tu necesidad
        
        if valor_politica == valor_comparacion:
            print(f'La política {ruta_politica} está configurada como {valor_politica}')
        else:
            print(f'La política {ruta_politica} está configurada como {valor_politica}, que es diferente de {valor_comparacion}')
    else:
        print(f'La política {ruta_politica} no fue encontrada en la configuración.')

except subprocess.CalledProcessError as e:
    print(f'Error al ejecutar el comando: {e}')

# Eliminar el archivo temporal secedit.cfg
subprocess.run('del c:\secedit.cfg', shell=True)
