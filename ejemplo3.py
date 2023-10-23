#grafica de torta 

import tkinter as tk
from tkinter import ttk
import matplotlib.pyplot as plt

def generar_grafica():
    # Obtener las etiquetas del TreeView
    etiquetas = [tree.item(item, "text") for item in tree.get_children()]

    if len(etiquetas) != 2:
        print("La gráfica de pastel requiere exactamente dos etiquetas en el TreeView.")
    else:
        # Valores de ejemplo para la gráfica de pastel
        valores = [30, 70]  # Porcentajes para dos etiquetas

        # Crear la gráfica de pastel
        plt.pie(valores, labels=etiquetas, autopct='%1.1f%%')
        plt.title("Gráfica de Pastel de ejemplo")
        plt.show()

# Crear la ventana principal
root = tk.Tk()
root.title("Generar Gráfica de Pastel desde TreeView")

# Crear un TreeView con dos etiquetas de ejemplo
tree = ttk.Treeview(root)
tree.pack()
tree.insert("", "end", text="Etiqueta 1")
tree.insert("", "end", text="Etiqueta 2")

# Botón para generar la gráfica
generar_grafica_button = tk.Button(root, text="Generar Gráfica de Pastel", command=generar_grafica)
generar_grafica_button.pack()

root.mainloop()
