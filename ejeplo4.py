# Import the required libraries
from tkinter import *
from tkinter import ttk

# Create an instance of tkinter frame
win = Tk()

# Set the size of the tkinter window
win.geometry("700x350")

s = ttk.Style()
s.theme_use('clam')

# Add a Treeview widget
tree = ttk.Treeview(win, column=("c1", "c2", "c3"), show='headings', height=5)

tree.column("# 1", anchor=CENTER)
tree.heading("# 1", text="ID")
tree.column("# 2", anchor=CENTER)
tree.heading("# 2", text="FName")
tree.column("# 3", anchor=CENTER)
tree.heading("# 3", text="LName")

# Insert the data in Treeview widget
tree.insert('', 'end', text="1", values=('1', 'Joe', 'Nash'))
tree.insert('', 'end', text="2", values=('2', 'Emily', 'Mackmohan'))
tree.insert('', 'end', text="3", values=('3', 'Estilla', 'Roffe'))
tree.insert('', 'end', text="4", values=('4', 'Percy', 'Andrews'))
tree.insert('', 'end', text="5", values=('5', 'Stephan', 'Heyward'))

tree.pack()

win.mainloop()