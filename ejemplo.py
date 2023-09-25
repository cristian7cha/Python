from tkinter import * 
from tkinter import ttk
import tkinter as tk,random
from PIL import ImageTk, Image


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
    def funcion():
        r = random.randint(0, 1)
        if r == 1 : 
            #icon = tk.PhotoImage(file="imagenes/chulo.png")
            icon ="✔"
        else: icon ="X"
        return icon
    for l in range(40):
        tree.insert('', 'end', text=""+str(l)+"",values=(''+listR[l]+'',''+funcion()+''))


ventana=Tk()
ventana.title("SeeHarden")
ventana.resizable(0,0) #(0,0) no se puede redireccionar la ventana
ventana.iconbitmap("imagenes/Logo.ico")
ventana.geometry("720x640") #tamaño de ventana
ventana.config(bg="white") #color de fondo
fondo = ImageTk.PhotoImage(Image.open('imagenes/fondo.jpg'))
background = Label(image=fondo)
background.place(x = 0, y = 0, relwidth = 1, relheight = 1)

btn = Button(ventana, text='Auditar   ', command=Auditar, anchor="center", bitmap="hourglass", compound="right").pack(pady=30)

listR=[]

with open("Recomendacione.txt") as procfile:
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