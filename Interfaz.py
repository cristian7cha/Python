from tkinter import * 
from tkinter import ttk
import tkinter as tk,random,subprocess,re
from PIL import ImageTk, Image

def obtener_valor_historial_contraseñas(variable_a_comparar,valor_a_comparar):
    try:
        # Ejecutar el comando secedit para consultar la configuración de seguridad y esto  guarda el archivo security.cfg en la carpeta designada
        resultado = subprocess.check_output("C:\\Windows\\System32\\secedit /export /cfg C:\\Windows\\Temp\\security.cfg", shell=True)
        
        # Leer el archivo de configuración exportado
        archivo_cfg = "C:\\Windows\\Temp\\security.cfg"
        archivo_txt = "C:\\Windows\\Temp\\security.txt"
        
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
                            if nombre_variable == "MaximumPasswordAge" or nombre_variable == "LockoutBadCount":
                                if valor_variable <= valor_a_comparar and valor_variable > 0:
                                    return valor_a_comparar
                                else: return False
                            elif valor_variable >= valor_a_comparar:
                                return valor_a_comparar
                            else: return False
        return "No se encontró la configuración de historial de contraseñas."

    except subprocess.CalledProcessError as e:
        return f"Error al obtener la configuración: {e}"

def informacion(ev):
    newWindow = tk.Toplevel(ventana)
    current_item = tree.focus()
    index = current_item[2:4]
    Label(newWindow).pack()
    indexString = str(index)
    imagenL = ImageTk.PhotoImage(Image.open('imagenes/'+indexString+'.jpg')) #selecciono la imagen de acuerdo al index 
    Label(newWindow, image = imagenL).pack()
    newWindow.mainloop()

def Auditar():
    def Nrandom():
        r = random.randint(0, 1)
        if r == 1 : 
            #icon = tk.PhotoImage(file="imagenes/chulo.png")
            icon ="✔"
        else: icon ="X"
        return icon
    
    #limpiar el arbol
    for item in tree.get_children():
        tree.delete(item)
    
    def funcion(variable,numero,lugar):    
        recomen = obtener_valor_historial_contraseñas(variable,numero)
        if recomen is False:
            tree.insert('', 'end', text=""+str(lugar)+"",values=(''+listR[lugar]+'',''"X"''),tags=(''+"X"+''))
        elif isinstance(recomen, (int, float, complex)):
            tree.insert('', 'end', text=""+str(lugar)+"",values=(''+listR[lugar]+'',''"✔"''),tags=(''+"✔"+''))
        else:
            print(f"{lugar} La variable no es False ni un número.")
    
    funcion("PasswordHistorySize",24,0)
    funcion("MaximumPasswordAge",365,1)
    funcion("MinimumPasswordAge",1,2)
    funcion("MinimumPasswordLength",14,3)
    funcion("PasswordComplexity",1,4)
    funcion("PasswordComplexity",1,5)
    funcion("ClearTextPassword",1,6)
    funcion("LockoutDuration",15,7)
    funcion("LockoutBadCount",5,8)
    funcion("ResetLockoutCount",15,9)
        
    for l in range(10,40):
        n=Nrandom()
        tree.insert('', 'end', text=""+str(l)+"",values=(''+listR[l]+'',''+n+''),tags=(''+n+''))
    tree.tag_configure('✔', background='#88dc65')
    tree.tag_configure('X', background='#f0394d')



if __name__ == "__main__":
    
    ventana=Tk()
    ventana.title("SeeHarden")
    ventana.resizable(0,0) #(0,0) no se puede redireccionar la ventana
    ventana.iconbitmap("imagenes/Logo.ico")
    ventana.geometry("720x640") #tamaño de ventana
    ventana.config(bg="white") #color de fondo
    fondo = ImageTk.PhotoImage(Image.open('imagenes/fondo.jpg'))
    background = Label(image=fondo)
    background.place(x = 0, y = 0, relwidth = 1, relheight = 1)
    logo = ImageTk.PhotoImage(Image.open('imagenes/logoL.png'))
    logol = Label(image=logo).pack(pady=10)

    btn = Button(ventana, text='Auditar   ', command=Auditar, anchor="center", bitmap="hourglass", compound="right").pack(pady=30)

    listR=[]

    with open("recomendaciones.txt", 'r', encoding='utf-8') as procfile:
        for line in procfile:
            listR.append(line)
           
        tree = ttk.Treeview(ventana, column=("col1","col2"), show='headings', height=15)
        tree.heading("col1", text="Politica")
        tree.column("col1",anchor=CENTER, width=500)
        tree.heading("col2", text="Estado")
        tree.column("col2",anchor=CENTER, width=50)
        tree.bind("<Double-1>", informacion)
        tree.pack()
        
    ventana.mainloop()