from tkinter import *
from ejemplo2 import MultiListbox

tk = Tk()
Label(tk, text='Prueba clase MLb').pack()
mlb = MultiListbox(tk, (('Asunto', 40), ('Remite', 20), ('Fecha', 10)))
for i in range(100):
    mlb.insert(END, ('Mensaje importante: %d' % (i+1), 'Avelino Cascarrio', '29/10/%04d' % (1900+i)))
 
mlb.pack(expand=YES,fill=BOTH)
tk.mainloop()