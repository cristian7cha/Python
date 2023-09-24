import tkinter
from tkinter import messagebox as MessageBox

top = tkinter.Tk()
#flat, groove, raised, ridge, solid o sunken

def helloCallBack():
   MessageBox.showinfo( "Hello Python", "Hello World")

A = tkinter.Button(top, text ="Hello", command = helloCallBack, relief = "flat").pack()

B = tkinter.Button(top, text ="Hello", command = helloCallBack, relief = "groove").pack()

C = tkinter.Button(top, text ="Hello", command = helloCallBack, relief = "raised").pack()

D = tkinter.Button(top, text ="Hello", command = helloCallBack, relief = "ridge").pack()

E = tkinter.Button(top, text ="Hello", command = helloCallBack, relief = "solid").pack()

F = tkinter.Button(top, text ="Hello", command = helloCallBack, relief = "sunken").pack()
top.mainloop()