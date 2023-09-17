from tkinter import*
from PIL import ImageTk, Image

ventana = Tk()
ventana.geometry("700x600+0+0")
ventana.config(bg = "red")
ventana.title("Ejemplo de imagenes")
#imagenL = PhotoImage(file = "img.jpg")
imagenL = ImageTk.PhotoImage(Image.open('1.jpg'))
lblImagen = Label(ventana, image = imagenL).place(x = 50,y = 50)

ventana.mainloop()