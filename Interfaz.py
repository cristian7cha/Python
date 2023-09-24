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

    for l in range(40):
        lista_recomendaciones.itemconfigure(l, bg=color() , fg="#fff")


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

with open("Recomendacione.txt") as procfile:
    for line in procfile:
        a=0
        lista_recomendaciones.insert(a,line.strip())
        a=a+1


lista_recomendaciones.place(x=50,y=80)


ventana.mainloop()