from tkinter import * 
from tkinter import ttk
import tkinter as tk,subprocess,re,winreg,threading
from PIL import ImageTk, Image
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def politicas_1_10(variable_a_comparar, valor_a_comparar):
    try:
        # Ejecutar el comando secedit para consultar la configuración de seguridad y esto guarda el archivo security.cfg en la carpeta designada
        resultado = subprocess.check_output("C:\\Windows\\System32\\secedit /export /cfg C:\\Windows\\Temp\\security.cfg", shell=True)
        
        # Leer el archivo de configuración exportado
        archivo_cfg = "C:\\Windows\\Temp\\security.cfg"
        archivo_txt = "C:\\Windows\\Temp\\security.txt"
        
        with open(archivo_cfg, 'r') as entrada:
            with open(archivo_txt, 'w') as salida:
                # Lee el contenido del archivo cfg y limpia los caracteres especiales
                for linea in entrada:
                    # Utiliza una expresión regular para eliminar caracteres especiales, excepto el "="
                    linea_limpia = re.sub(r'[^a-zA-Z0-9\s=]', '', linea)
                    # Divide la línea en palabras usando el signo "=" como separador
                    palabras = linea_limpia.split('=')
                    # Si hay al menos dos palabras (nombre de variable y valor)
                    if len(palabras) >= 2:
                        nombre_variable = palabras[0].strip()
                        valor_variable = palabras[1].strip()
                        salida.write(f"{nombre_variable} = {valor_variable}\n")
                        
                        # Compara el valor con el valor_a_comparar
                        if nombre_variable == variable_a_comparar:
                            valor_variable = int(valor_variable)
                            if nombre_variable == "MaximumPasswordAge" or nombre_variable == "LockoutBadCount":
                                if valor_variable <= valor_a_comparar and valor_variable > 0:
                                    return valor_a_comparar
                                else: return False
                            elif valor_variable >= valor_a_comparar:
                                return valor_a_comparar
                            else: return False
        return "No se encontró la configuración de historial de contraseñas."

    except subprocess.CalledProcessError as e:
        return f"Error al obtener la configuración: {e}"

def politicas_20_40(ruta_registro, nombre_valor, valor_a_comparar):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ruta_registro) as key:
            try:
                value, _ = winreg.QueryValueEx(key, nombre_valor)
                if value == valor_a_comparar:
                    return valor_a_comparar
                else:
                    return False
            except FileNotFoundError:
                return False
    except Exception as e:
        return False

def informacion(ev):
    newWindow = tk.Toplevel(ventana)
    current_item = tree.focus()
    index = current_item[2:4]
    Label(newWindow).pack()
    indexString = str(index)
    imagenL = ImageTk.PhotoImage(Image.open('imagenes/'+indexString+'.jpg')) #selecciono la imagen de acuerdo al index 
    Label(newWindow, image = imagenL).pack()
    newWindow.mainloop()

def mostrar_resultados():
    ventana.geometry("900x800")  # Ajusta el tamaño de la ventana al mostrar resultados
    notebook.pack(expand=1, fill='both')

    # Muestra el contenido específico de la pestaña actual
    if notebook.index(notebook.select()) == 0:
        frame_tree.pack(fill='both', expand=True)
        frame_grafico.pack_forget()
        contar_y_graficar()
    else:
        frame_grafico.pack(fill='both', expand=True)
        frame_tree.pack_forget()
        contar_y_graficar()

def ocultar_resultados():
    ventana.geometry("720x800")  # Ajusta el tamaño de la ventana al ocultar resultados
    notebook.pack_forget()

def Auditar():
    ocultar_resultados()
    progress = ttk.Progressbar(ventana, orient="horizontal", length=300, mode="indeterminate")
    progress.pack(padx=20, pady=20)
    progress.start()

    def ejecutar_auditoria(progress_bar):
        for item in tree.get_children():
            tree.delete(item)


    progress = ttk.Progressbar(ventana, orient="horizontal", length=300, mode="indeterminate")
    progress.pack(padx=20, pady=20)
    progress.start()  # Iniciar la barra de progreso

    # Función para ejecutar la auditoría en un hilo
    def ejecutar_auditoria(progress_bar):
    
        #limpiar el arbol
        for item in tree.get_children():
            tree.delete(item)
        
        def funcion(variable,valor_desedao,lugar):    
            recomen = politicas_1_10(variable,valor_desedao)
            if recomen is False:
                tree.insert('', 'end', text=""+str(lugar)+"",values=(''+listR[lugar]+'',''"X"''),tags=(''+"X"+''))
            elif isinstance(recomen, (int, float, complex)):
                tree.insert('', 'end', text=""+str(lugar)+"",values=(''+listR[lugar]+'',''"✔"''),tags=(''+"✔"+''))
            else:
                tree.insert('', 'end', text=""+str(lugar)+"",values=(''+listR[lugar]+'',''"X"''),tags=(''+"X"+''))
                
        def funcion2(ruta,variable,valor_desedao,lugar):    
            recomen = politicas_20_40(ruta,variable,valor_desedao)
            if recomen is False:
                tree.insert('', 'end', text=""+str(lugar)+"",values=(''+listR[lugar]+'',''"X"''),tags=(''+"X"+''))
            elif isinstance(recomen, (int, float, complex)):
                tree.insert('', 'end', text=""+str(lugar)+"",values=(''+listR[lugar]+'',''"✔"''),tags=(''+"✔"+''))
            else:
                tree.insert('', 'end', text=""+str(lugar)+"",values=(''+listR[lugar]+'',''"X"''),tags=(''+"X"+''))
        
        funcion("PasswordHistorySize",24,0)
        funcion("MaximumPasswordAge",365,1)
        funcion("MinimumPasswordAge",1,2)
        funcion("MinimumPasswordLength",14,3)
        funcion("PasswordComplexity",1,4)
        funcion2( r"SYSTEM\CurrentControlSet\Control\SAM","RelaxMinimumPasswordLengthLimits",1,5)
        funcion("ClearTextPassword",0,6)
        funcion("LockoutDuration",15,7)
        funcion("LockoutBadCount",5,8)
        funcion("ResetLockoutCount",15,9)
        
        funcion2( r"SYSTEM\CurrentControlSet\Control\Lsa","LimitBlankPasswordUse",1,10)
        funcion2( r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile","DefaultOutboundAction",0,11)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\Device Metadata","PreventDeviceMetadataFromNetwork",1,12)
        funcion2( r"SOFTWARE\Policies\Microsoft\Control Panel\International","BlockUserInputMethodsForSignIn",1,13)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\Explorer","NoAutoplayfornonVolume",1,14)
        funcion2( r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer","NoAutorun",1,15)
        funcion2( r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer","NoDriveTypeAutoRun",255,16)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection","DisallowExploitProtectionOverride",1,17)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection","DisallowExploitProtectionOverride",1,18)

        funcion2( r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile","EnableFirewall",1,19)
        funcion2( r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile","DefaultInboundAction",1,20)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard","EnableVirtualizationBasedSecurity",1,21)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\System","BlockUserFromShowingAccountDetailsOnSignin",1,22)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\System","DisableLockScreenAppNotifications",1,23)
        funcion2( r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51","DCSettingIndex",1,24)
        funcion2( r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51","ACSettingIndex",1,25)
        funcion2( r"SOFTWARE\Policies\Microsoft\windows Defender\Windows Defender Exploit Guard\Network Protection","EnableNetworkProtection",1,26)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection","DisableIOAVProtection",0,27)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection","DisableRealtimeMonitoring",0,28)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection","DisableBehaviorMonitoring",0,29)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection","DisableOnAccessProtection",0,30)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan","DisableRemovableDriveScanning",0,31)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan","DisableEmailScanning",0,32)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender","PUAProtection",1,33)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender","DisableAntiSpyware",0,34)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\System","EnableSmartScreen",1,35)
        funcion2( r"SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter","EnabledV9",1,36)
        funcion2( r"SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter","PreventOverride",1,37)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU","NoAutoUpdate",0,38)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU","ScheduledInstallDay",0,39)
            
        tree.tag_configure('✔', background='#88dc65')
        tree.tag_configure('X', background='#f0394d')

        # Detener la barra de progreso al finalizar
        progress.stop()
        # Destruir la barra de progreso
        progress.destroy()

        contar_y_graficar()

    thread = threading.Thread(target=ejecutar_auditoria, args=(progress,))
    thread.start()



def contar_y_graficar():
    if hasattr(contar_y_graficar, 'canvas'):
        contar_y_graficar.canvas.get_tk_widget().destroy()

    etiqueta_x = 0
    etiqueta_check = 0

    for item in tree.get_children():
        etiquetas = tree.item(item, 'tags')
        if "X" in etiquetas:
            etiqueta_x += 1
        if "✔" in etiquetas:
            etiqueta_check += 1

    etiquetas = ['Etiqueta X', 'Etiqueta ✔']
    valores = [etiqueta_x, etiqueta_check]

    fig = Figure(figsize=(8, 8))
    ax = fig.add_subplot(111)
    ax.pie(valores, labels=etiquetas, autopct='%1.1f%%', colors=['red', 'green'])
    ax.set_title('Gráfico de Nivel de seguridad')

    contar_y_graficar.canvas = FigureCanvasTkAgg(fig, ventana)
    contar_y_graficar.canvas.get_tk_widget().pack(side='bottom', fill='both', expand=True)

if __name__ == "__main__":
    ventana = Tk()
    ventana.title("SeeHarden")
    ventana.resizable(0, 0)
    ventana.geometry("720x640")
    ventana.config(bg="white")

    fondo = ImageTk.PhotoImage(Image.open('imagenes/fondo.jpg'))
    background = Label(image=fondo)
    background.place(x=0, y=0, relwidth=1, relheight=1)

    logo = ImageTk.PhotoImage(Image.open('imagenes/logoL.png'))
    logol = Label(image=logo).pack(pady=10)

    btn_auditar = Button(ventana, text='Auditar', command=Auditar, anchor="center", bitmap="hourglass", compound="right")
    btn_auditar.pack(pady=30)

    progress = ttk.Progressbar(ventana, orient="horizontal", length=300, mode="indeterminate")

    listR = []
    with open("archivos/recomendaciones.txt", 'r', encoding='utf-8') as procfile:
        for line in procfile:
            listR.append(line)

    frame_tree = Frame(ventana)
    frame_tree.pack(fill='both', expand=True)

    tree = ttk.Treeview(frame_tree, column=("col1", "col2"), show='headings', height=15)
    tree.heading("col1", text="Política")
    tree.column("col1", anchor=CENTER, width=500)
    tree.heading("col2", text="Estado")
    tree.column("col2", anchor=CENTER, width=50)
    tree.bind("<Double-1>", informacion)
    tree.pack(fill='both', expand=True)

    canvas_tree = Frame(frame_tree)
    canvas_tree.pack(fill='both', expand=True)

    frame_grafico = Frame(ventana)
    frame_grafico.pack(fill='both', expand=True)

    canvas_grafico = Frame(frame_grafico)
    canvas_grafico.pack(fill='both', expand=True)

    notebook = ttk.Notebook(ventana)
    notebook.add(frame_tree, text='TreeView')
    notebook.add(frame_grafico, text='Gráfico')
    notebook.pack(expand=1, fill='both')

    ventana.mainloop()