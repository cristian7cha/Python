from tkinter import *
import tkinter,random
from PIL import ImageTk, Image

def informacion(ev):
    newWindow = tkinter.Toplevel(ventana)
    listbox = ev.widget
    index = listbox.curselection()
    value = listbox.get(index[0])
    Label(newWindow, text=value).pack()

    if index[0] == 0:
        imagenL = ImageTk.PhotoImage(Image.open('imagenes/0.jpg'))
    elif index[0] == 1:
        imagenL = ImageTk.PhotoImage(Image.open('imagenes/1.jpg'))
    elif index[0] == 2:
        imagenL = ImageTk.PhotoImage(Image.open('imagenes/0.jpg'))
    elif index[0] == 3:
        imagenL = ImageTk.PhotoImage(Image.open('imagenes/1.jpg'))
    else:
        imagenL = ImageTk.PhotoImage(Image.open('imagenes/0.jpg'))

    Label(newWindow, image = imagenL).pack()
    newWindow.mainloop()

        
    
def Auditar():
    
    def color():
        r = random.randint(0, 1)
        if r == 1 : 
            x= "green" 
        else: x= "red"
        return x

    lista_recomendaciones.itemconfigure(0, bg=color() , fg="#fff")
    lista_recomendaciones.itemconfigure(1, bg=color() , fg="#fff")
    lista_recomendaciones.itemconfigure(2, bg=color() , fg="#fff")
    lista_recomendaciones.itemconfigure(3, bg=color() , fg="#fff")
    lista_recomendaciones.itemconfigure(4, bg=color() , fg="#fff")

ventana=Tk()

ventana.title("SeeHarden")

ventana.resizable(0,0) #(0,0) no se puede redireccionar la ventana

ventana.iconbitmap("imagenes/Logo.ico")
ventana.geometry("720x640") #tamaño de ventana
ventana.config(bg="black") #color de fondo

btn = Button(ventana, text='Auditar', command=Auditar)
btn.place(x=300, y=50)

lista_recomendaciones=Listbox(ventana,width=90)
lista_recomendaciones.bind('<Double-Button-1>', informacion)
lista_recomendaciones.insert(0,"'Hacer cumplir el historial de contraseñas' esté configurado en '24 o más contraseñas'")
lista_recomendaciones.insert(1,"La 'Edad máxima de la contraseña' esté configurada en '365 días o menos, pero no 0'")
lista_recomendaciones.insert(2,"'Edad mínima de la contraseña' esté establecida en '1 o más días'")
lista_recomendaciones.insert(3,"la 'Longitud mínima de la contraseña' esté configurada en '14 o más carácter(es)'")
lista_recomendaciones.insert(4,"'La contraseña debe cumplir con los requisitos de complejidad' esté configurado en 'Habilitado'")
lista_recomendaciones.place(x=50,y=80)


ventana.mainloop()