#este codigo funciona para la 6 regla
import winreg

def verificar_valor_registro(key_path, valor_deseado, valor_a_comparar):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            try:
                value, _ = winreg.QueryValueEx(key, valor_deseado)
                if value == valor_a_comparar:
                    return True
                else:
                    return False
            except FileNotFoundError:
                print(f"El valor '{valor_deseado}' no se encontró en la clave del registro.")
                return False
    except PermissionError:
        print("Se requieren permisos de administrador para acceder al registro.")
        return False
    except Exception as e:
        print(f"Error al acceder al registro: {str(e)}")
        return False

# Ejemplo de uso:
ruta_registro = r"SYSTEM\CurrentControlSet\Control\SAM"
nombre_valor = "RelaxMinimumPasswordLengthLimits"
valor_comparar = 1  # Reemplaza con el valor que deseas comparar

resultado = verificar_valor_registro(ruta_registro, nombre_valor, valor_comparar)
if resultado is not None:
    if resultado:
        print(f"El valor de la clave del registro es igual a {valor_comparar}.")
    else:
        print(f"El valor de la clave del registro no es igual a {valor_comparar}.")
