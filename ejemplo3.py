from tkinter import * 
from tkinter import ttk
import tkinter as tk,random,subprocess,re
from PIL import ImageTk, Image

def obtener_valor_historial_contraseñas():
    try:
        # Ejecutar el comando secedit para consultar la configuración de seguridad y esto  guarda el archivo security.cfg en la carpeta designada
        resultado = subprocess.check_output("C:\\Windows\\System32\\secedit /export /cfg C:\\Users\\crist\\OneDrive\\Desktop\\TG\\Python\\security.cfg", shell=True)
        
        # Leer el archivo de configuración exportado
        archivo_cfg = "security.cfg"
        archivo_txt = "security.txt"
        
        def quitar_simbolos_especiales(linea):
            caracteres_permitidos = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=_\n "
            return ''.join(caracter for caracter in linea if caracter in caracteres_permitidos)

        # Procesar el archivo de entrada y escribir en el archivo de salida
        with open(archivo_cfg, 'r') as entrada, open(archivo_txt, 'w') as archivo_salida:
            for linea in entrada:
                linea_limpia = quitar_simbolos_especiales(linea)
                archivo_salida.write(linea_limpia)
        
        with open(archivo_txt, 'r') as archivo:
            for linea in archivo:
                palabras = linea.strip().split('=')
                if len(palabras) == 2:
                    nombre_variable = palabras[0].strip()
                    valor_variable = palabras[1].strip()
                        
                    num_aux = 0  
                    if nombre_variable == "PasswordHistorySize" and int(valor_variable) >= 24:
                        tree.insert('', 'end', text=""+str(0)+"",values=(''+listR[0]+'',''"✔"''),tags=(''+"✔"+''))
                        num_aux = num_aux + 1
                    elif nombre_variable == "MaximumPasswordAge" and int(valor_variable) <= 365 and int(valor_variable) > 0:
                        tree.insert('', 'end', text=""+str(1)+"",values=(''+listR[1]+'',''"✔"''),tags=(''+"✔"+''))
                        num_aux = num_aux + 1
                    elif nombre_variable == "MinimumPasswordAge" and int(valor_variable) >= 14:
                        tree.insert('', 'end', text=""+str(2)+"",values=(''+listR[2]+'',''"✔"''),tags=(''+"✔"+''))
                        num_aux = num_aux + 1
                    elif nombre_variable == "MinimumPasswordLength" and int(valor_variable) >= 24:
                        tree.insert('', 'end', text=""+str(3)+"",values=(''+listR[3]+'',''"✔"''),tags=(''+"✔"+''))
                        num_aux = num_aux + 1
                    elif nombre_variable == "PasswordComplexity" and int(valor_variable) == 1:
                        tree.insert('', 'end', text=""+str(4)+"",values=(''+listR[4]+'',''"✔"''),tags=(''+"✔"+''))
                        num_aux = num_aux + 1
                    elif nombre_variable == "falta" and int(valor_variable) >= 24:
                        tree.insert('', 'end', text=""+str(5)+"",values=(''+listR[5]+'',''"✔"''),tags=(''+"✔"+''))
                        num_aux = num_aux + 1
                    elif nombre_variable == "ClearTextPassword" and int(valor_variable) == 0:
                        tree.insert('', 'end', text=""+str(6)+"",values=(''+listR[6]+'',''"✔"''),tags=(''+"✔"+''))
                        num_aux = num_aux + 1
                    elif nombre_variable == "LockoutDuration" and int(valor_variable) >= 15:
                        tree.insert('', 'end', text=""+str(7)+"",values=(''+listR[7]+'',''"✔"''),tags=(''+"✔"+''))
                        num_aux = num_aux + 1
                    elif nombre_variable == "LockoutBadCount" and int(valor_variable) <= 5:
                        tree.insert('', 'end', text=""+str(8)+"",values=(''+listR[8]+'',''"✔"''),tags=(''+"✔"+''))
                        num_aux = num_aux + 1
                    elif nombre_variable == "ResetLockoutCount" and int(valor_variable) >= 15:
                        tree.insert('', 'end', text=""+str(9)+"",values=(''+listR[9]+'',''"✔"''),tags=(''+"✔"+''))
                        num_aux = num_aux + 1
                    else:
                        tree.insert('', 'end', text=""+str(num_aux)+"",values=(''+listR[num_aux]+'',''"X"''),tags=(''+"X"+''))

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
    
    obtener_valor_historial_contraseñas()
    
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