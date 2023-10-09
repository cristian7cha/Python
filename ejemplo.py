from tkinter import *
import tkinter,random
from PIL import ImageTk, Image

def informacion(ev):
    newWindow = tkinter.Toplevel(ventana)
    listbox = ev.widget
    index = listbox.curselection()
    value = listbox.get(index[0])
    Label(newWindow, text=value).pack()
    indexString = str(index[0])

    imagenL = ImageTk.PhotoImage(Image.open('imagenes/'+indexString+'.jpg')) #selecciono la imagen de acuerdo al index 

    Label(newWindow, image = imagenL).pack()
    newWindow.mainloop()

def Auditar():
    def color():
        r = random.randint(0, 1)
        if r == 1 : 
            x= "green" 
        else: x= "red"
        return x

    for l in range(40):
        lista_recomendaciones.itemconfigure(l, bg=color() , fg="#fff")

if __name__ == "__main__":
    ventana=Tk()
    ventana.title("SeeHarden")
    ventana.resizable(0,0) #(0,0) no se puede redireccionar la ventana
    ventana.iconbitmap("imagenes/Logo.ico")
    ventana.geometry("720x640") #tamaño de ventana
    ventana.config(bg="white") #color de fondo
    logo = ImageTk.PhotoImage(Image.open('imagenes/fondo.jpg'))
    background = Label(image=logo)
    background.place(x = 0, y = 0, relwidth = 1, relheight = 1)

    btn = Button(ventana, text='Auditar   ', command=Auditar, anchor="center", bitmap="hourglass", compound="right").pack(pady=30)
    lista_recomendaciones=Listbox(ventana,width=85,height=20)
    lista_recomendaciones.bind('<Double-Button-1>', informacion)

    # Abre el archivo en modo lectura
    with open("recomendaciones.txt", 'r', encoding='utf-8') as archivo:
        # Lee el contenido del archivo línea por línea
        lineas = archivo.readlines()
        # Borra cualquier contenido previo en el Listbox
        lista_recomendaciones.delete(0, END)
        # Agrega cada línea al Listbox
        for linea in lineas:
            lista_recomendaciones.insert(END, linea.strip())  # strip() elimina los caracteres de nueva línea y espacios en blanco

    lista_recomendaciones.place(x=50,y=80)
    ventana.mainloop()