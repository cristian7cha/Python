import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt

# Función para contar elementos con etiquetas "x" y "✔" y crear un gráfico de torta
def contar_y_graficar():
    etiqueta_x = 0
    etiqueta_check = 0

    # Recorre los elementos del TreeView
    for item in tree.get_children():
        etiquetas = tree.item(item, 'values')
        if "x" in etiquetas:
            etiqueta_x += 1
        if "✔" in etiquetas:
            etiqueta_check += 1

    # Crear datos para el gráfico de torta
    etiquetas = ['Etiqueta X', 'Etiqueta ✔']
    valores = [etiqueta_x, etiqueta_check]

    # Crear un gráfico de torta
    plt.pie(valores, labels=etiquetas, autopct='%1.1f%%')
    plt.title('Gráfico de Torta')

    # Mostrar el gráfico
    plt.show()

# Crear la ventana principal
root = tk.Tk()
root.title("Contador y Gráfico de Torta")

# Crear un TreeView
tree = ttk.Treeview(root, columns=("Etiquetas"))
tree.heading("#1", text="Etiquetas")
tree.pack()

# Agregar algunos elementos al TreeView con etiquetas "x" y "✔"
tree.insert("", "end", values=("x"))
tree.insert("", "end", values=("✔"))
tree.insert("", "end", values=("✔"))
tree.insert("", "end", values=("x"))
tree.insert("", "end", values=("✔"))

# Botón para contar y crear el gráfico de torta
contar_button = tk.Button(root, text="Contar y Graficar", command=contar_y_graficar)
contar_button.pack()

root.mainloop()
