import tkinter as tk

# Descripción predefinida en el código
descripcion_predeterminada = """
Este es un programa de ejemplo.
Aquí puedes colocar la descripción del programa.
"""

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Descripción del Programa")

# Crear un widget Label para mostrar la descripción
etiqueta_descripcion = tk.Label(ventana, text=descripcion_predeterminada, justify="left", wraplength=400)
etiqueta_descripcion.pack(padx=10, pady=10)

# Iniciar la aplicación
ventana.mainloop()
