#SeeHarden.py
from tkinter import *
from tkinter import ttk
import tkinter as tk,subprocess,re,winreg,threading
from PIL import ImageTk, Image
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

etiqueta_resultado = None
barra_progreso_visible = False # Variable booleana para controlar la visibilidad de la barra de progreso
progress = None

def politicas_1_10(variable_a_comparar,valor_a_comparar):
    try:
        # Ejecutar el comando secedit para consultar la configuración de seguridad y guarda el archivo security.cfg en la carpeta designada
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

def politicas_10_40(ruta_registro, nombre_variable, valor_a_comparar):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ruta_registro) as key:
            try:
                value, _ = winreg.QueryValueEx(key, nombre_variable)
                if value == valor_a_comparar:
                    return valor_a_comparar
                else:
                    return False
            except FileNotFoundError:
                return False
    except Exception as e:
        return False

def informacion(ev):
    # Obtener el item seleccionado en el Treeview
    current_item = tree.focus()
    # Obtener el valor de la columna "col0" del item seleccionado
    numero_politica = tree.item(current_item, 'values')[0]
    # Obtener el valor de la columna "col1" del item seleccionado
    politica_valor = tree.item(current_item, 'values')[1]

    # Destruir el widget de Text existente, si existe
    if hasattr(informacion, 'text_detalles'):
        informacion.text_detalles.destroy()

    # Crear un nuevo widget de Text en la pestaña de Detalles
    informacion.text_detalles = tk.Text(
        frame_detalles,
        wrap="word",  # Opción para envolver palabras
        font=("Arial", 10),
        height=10,
        width=80
    )

    # Verificar el estado de la política y configurar el fondo
    if "X" in tree.item(current_item, 'tags'):
        informacion.text_detalles.configure(bg='#f0394d')  # Fondo rojo para "X"
        estado_politica = "Configurada incorrectamente"
    elif "✔" in tree.item(current_item, 'tags'):
        informacion.text_detalles.configure(bg='#88dc65')  # Fondo verde para "✔"
        estado_politica = "Configurada correctamente"

    # Insertar el contenido en el widget de Text
    contenido_texto = f"{estado_politica}\n\n Política {numero_politica}: {politica_valor}\nJustificación: {obtener_mensaje_segun_indice(int(numero_politica))}"
    informacion.text_detalles.tag_configure("center", justify='center')
    informacion.text_detalles.insert(tk.END, contenido_texto, "center")

    # Mostrar el widget de Text
    informacion.text_detalles.pack(pady=20)

def obtener_mensaje_segun_indice(indice):
    # Puedes personalizar los mensajes según tus necesidades
    mensajes = {
        0: "Cuanto más tiempo utilice un usuario la misma contraseña, mayor será la posibilidad de que un atacante pueda determinarla mediante ataques de fuerza bruta. Además, cualquier cuenta que pueda haber sido comprometida seguirá siendo explotable mientras no se cambie la contraseña. Si se requieren cambios de contraseña, pero no se previene la reutilización de contraseñas, o si los usuarios reutilizan continuamente un pequeño número de contraseñas, la efectividad de una buena política de contraseñas se reduce enormemente.",
        1:"Cuanto más tiempo exista una contraseña, mayor será la probabilidad de que se vea comprometida por un ataque de fuerza bruta, por un atacante que obtenga conocimientos generales sobre el usuario o por el usuario que comparte la contraseña. Configurar la edad máxima de la contraseña a 0 para que los usuarios nunca tengan que cambiar sus contraseñas es un riesgo de seguridad importante porque permite que una contraseña comprometida sea utilizada por el usuario malicioso mientras el usuario válido tenga acceso autorizado.",
        2:"Los usuarios pueden tener contraseñas favoritas que les gusta usar porque son fáciles de recordar y creen que su elección de contraseña es segura contra el compromiso. Desafortunadamente, las contraseñas se ven comprometidas y si un atacante tiene como objetivo la cuenta de usuario de un individuo específico, con conocimiento previo de los datos sobre ese usuario, la reutilización de contraseñas antiguas puede causar una brecha de seguridad.",
        3:"Los tipos de ataques a las contraseñas incluyen ataques de diccionario (que intentan utilizar palabras y frases comunes) y ataques de fuerza bruta (que prueban todas las combinaciones posibles de caracteres). Además, los atacantes a veces intentan obtener la base de datos de cuentas para poder utilizar herramientas que les permitan descubrir las cuentas y las contraseñas.",
        4:"Las contraseñas que sólo contienen caracteres alfanuméricos son extremadamente fáciles de descubrir con varias herramientas disponibles públicamente.",
        5:"Esta configuración permitirá la aplicación de contraseñas o frases de contraseña más largas y generalmente más seguras.",
        6:"La activación de esta configuración de directiva permite que el sistema operativo almacene las contraseñas en un formato más débil que es mucho más susceptible de ser comprometido y debilita la seguridad del sistema.",
        7:"Se puede crear una condición de denegación de servicio (DoS) si un atacante abusa del umbral de Bloqueo de cuenta e intenta iniciar sesión repetidamente con una cuenta específica. Una vez configurado el umbral de bloqueo de cuenta, la cuenta se bloqueará tras el número especificado de intentos fallidos.",
        8:"Establecer un umbral de bloqueo de cuenta reduce la probabilidad de que un ataque de fuerza bruta de contraseña en línea tenga éxito. Establecer un umbral de bloqueo de cuentas demasiado bajo introduce el riesgo de que aumenten los bloqueos accidentales y/o de que un actor malintencionado bloquee cuentas intencionadamente.",
        9:"Los usuarios pueden bloquearse accidentalmente de sus cuentas si escriben mal su contraseña varias veces. Para reducir la posibilidad de bloqueos accidentales, la opción Restablecer contador de bloqueos de cuenta después determina el número de minutos que deben transcurrir antes de que el contador que realiza el seguimiento de los intentos fallidos de inicio de sesión y desencadena bloqueos se restablezca a 0.",
        10:"Las contraseñas en blanco son una grave amenaza para la seguridad informática y deben prohibirse tanto a través de políticas organizativas como de medidas técnicas adecuadas.",
        11:"Si el cortafuegos está desactivado, todo el tráfico podrá acceder al sistema y un atacante podrá explotar más fácilmente de forma remota una debilidad en un servicio de red.",
        12:"Si el cortafuegos permite que todo el tráfico acceda al sistema, es más fácil que un atacante pueda explotar remotamente un punto débil en un servicio de red.",
        13:"Algunas personas creen que es prudente bloquear todas las conexiones salientes excepto las aprobadas específicamente por el usuario o el administrador. Microsoft no está de acuerdo con esta opinión, ya que bloquear las conexiones salientes por defecto obligará a los usuarios a lidiar con un gran número de cuadros de diálogo pidiéndoles que autoricen o bloqueen aplicaciones como su navegador web o software de mensajería instantánea. Además, bloquear el tráfico saliente tiene poco valor porque si un atacante ha comprometido el sistema puede reconfigurar el cortafuegos de todos modos.",
        14:"Si no se registran los eventos puede ser difícil o imposible determinar la causa raíz de los problemas del sistema o las actividades no autorizadas de usuarios malintencionados.",
        15:"Kerberos, NTLM y Credential manager aíslan los secretos utilizando seguridad basada en virtualización.",
        16:"Permitir la instalación automática de software de terceros en el contexto de la cuenta SYSTEM puede permitir el acceso no autorizado a través de puertas traseras o errores en el software de instalación.",
        17:"Esta es una forma de aumentar la seguridad de la cuenta del sistema.",
        18:"Un atacante con acceso a la consola (por ejemplo, alguien con acceso físico o alguien que pueda conectarse a la estación de trabajo a través de Servicios de Escritorio Remoto) podría ver el nombre del último usuario que inició sesión en el servidor. El atacante podría entonces intentar adivinar la contraseña, utilizar un diccionario o un ataque de fuerza bruta para intentar iniciar sesión.",
        19:"Las notificaciones de aplicaciones pueden mostrar datos empresariales o personales confidenciales.",
        20:"Activar esta configuración garantiza que cualquier persona que despierte un equipo desatendido del estado de suspensión tendrá que proporcionar credenciales de inicio de sesión antes de poder acceder al sistema.",
        21:"Activar esta configuración garantiza que cualquier persona que despierte un equipo desatendido del estado de suspensión tendrá que proporcionar credenciales de inicio de sesión antes de poder acceder al sistema.",
        22:"Un atacante podría utilizar esta función para iniciar un programa y dañar un equipo cliente o los datos del equipo.",
        23:"Si el sistema se ejecuta automáticamente, esto crea un problema de seguridad importante, ya que el código puede ejecutarse sin el conocimiento del usuario.",
        24:"Un atacante podría utilizar esta función para iniciar un programa con el fin de dañar un equipo cliente o los datos del equipo.",
        25:"Esta configuración puede ayudar a evitar que los usuarios utilicen cualquier aplicación para acceder a dominios peligrosos que puedan alojar estafas de suplantación de identidad, sitios de alojamiento de exploits y otros contenidos malintencionados en Internet.",
        26:"Cuando se ejecuta una solución antivirus como Microsoft Defender Antivirus, es importante asegurarse de que está configurada para supervisar heurísticamente en tiempo real la actividad sospechosa y maliciosa conocida.",
        27:"Cuando se ejecuta una solución antivirus como Microsoft Defender Antivirus, es importante asegurarse de que está configurada para supervisar heurísticamente en tiempo real la actividad maliciosa sospechosa y conocida.",
        28:"Cuando se ejecuta una solución antivirus como Microsoft Defender Antivirus, es importante asegurarse de que está configurada para supervisar heurísticamente en tiempo real la actividad sospechosa y maliciosa conocida.",
        29:"Es importante asegurarse de que todas las unidades extraíbles presentes se incluyan siempre en cualquier tipo de análisis, ya que es más probable que las unidades extraíbles contengan software malintencionado.",
        30:"Los correos electrónicos entrantes deben analizarse con una solución antivirus como Microsoft Defender Antivirus, ya que los archivos adjuntos a los correos electrónicos son un vector de ataque muy utilizado para infiltrarse en los ordenadores con software malicioso.",
        31:"Las aplicaciones potencialmente no deseadas pueden aumentar el riesgo de que su red se infecte con malware, hacer que las infecciones de malware sean más difíciles de identificar. Se debe bloquear su instalación.",
        32:"Es importante asegurarse de que un producto antivirus actual y actualizado analiza cada equipo en busca de actividad de archivos maliciosos. Microsoft proporciona una solución competente en Microsoft Defender Antivirus.",
        33:"Para evitar que se obtenga información confidencial para usos malintencionados, los sitios que no sean de confianza dentro del contenedor de Microsoft Defender Application Guard no deben acceder al micrófono ni a la cámara del equipo.",
        34:"Microsoft Defender Application Guard utiliza Windows Hipervisor para crear un entorno virtualizado para las aplicaciones que están configuradas para utilizar el aislamiento de seguridad basado en la virtualización. Mientras están aisladas, las interacciones inadecuadas de los usuarios y las vulnerabilidades de las aplicaciones no pueden poner en peligro el kernel ni ninguna otra aplicación que se ejecute fuera del entorno virtualizado.",
        35:"Windows Defender SmartScreen ayuda a mantener los PC más seguros advirtiendo a los usuarios antes de ejecutar programas no reconocidos descargados de Internet.",
        36:"SmartScreen tiene un propósito importante ya que ayuda a advertir a los usuarios de posibles sitios y archivos maliciosos. Permitir a los usuarios desactivar esta configuración puede hacer que el navegador sea más vulnerable a los ataques.",
        37:"SmartScreen advertirá a un usuario si un sitio web es potencialmente malicioso. Habilitar esta configuración evita que se omitan estas advertencias.",
        38:"Aunque cada versión de Windows se prueba exhaustivamente antes de su lanzamiento, es posible que se descubran problemas después de que se distribuyan los productos. La configuración de Actualizaciones automáticas puede ayudarle a garantizar que los equipos de su entorno siempre tengan instaladas las actualizaciones críticas más recientes del sistema operativo y los Service Packs.",
        39:"Aunque cada versión de Windows se prueba exhaustivamente antes de su lanzamiento, es posible que se descubran problemas después de que los productos se hayan enviado. La opción Configurar actualizaciones automáticas puede ayudarle a garantizar que los equipos de su entorno tengan siempre instaladas las actualizaciones críticas más recientes del sistema operativo y los Service Packs."
    }
    return mensajes.get(indice, "Mensaje predeterminado")

def mostrar_barra_progreso():
    global progress
    if progress:
        # Destruir la barra de progreso anterior
        progress.destroy()
    style = ttk.Style()
    style.configure("TProgressbar", thickness=15, troughcolor="white", background="#76ff03")
    # Crear una nueva barra de progreso
    progress = ttk.Progressbar(frame_principal, orient="horizontal", length=500, mode="indeterminate",style="TProgressbar")
    # Configurar el espaciado debajo del botón "Auditar" y colocar la barra de progreso en la ventana
    progress.pack(pady=(0,40), side=BOTTOM, in_=frame_principal)
    # Iniciar la barra de progreso
    progress.start()

def Auditar():
    # Crear una barra de progreso
    global progress
    # Limpiar el árbol
    for item in tree.get_children():
        tree.delete(item)

    # Función para ejecutar la auditoría en un hilo
    def ejecutar_auditoria(progress_bar):

        # Deshabilitar las otras pestañas durante la auditoría
        notebook.tab(1, state="disabled")
        notebook.tab(2, state="disabled")

        mostrar_barra_progreso()

        def funcion(variable, valor_deseado, lugar):
            recomen = politicas_1_10(variable, valor_deseado)
            if isinstance(recomen, (int, float, complex)) and recomen is not False:
                tree.insert('', 'end', values=(lugar, lista_recomendaciones[lugar], "✔"), tags=("✔",))
            else:
                tree.insert('', 'end', values=(lugar, lista_recomendaciones[lugar], "X"), tags=("X",))

        def funcion2(ruta, variable, valor_deseado, lugar):
            recomen = politicas_10_40(ruta, variable, valor_deseado)
            if isinstance(recomen, (int, float, complex)) and recomen is not False:
                tree.insert('', 'end', values=(lugar, lista_recomendaciones[lugar], "✔"), tags=("✔",))
            else:
                tree.insert('', 'end', values=(lugar, lista_recomendaciones[lugar], "X"), tags=("X",))

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
        funcion2( r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile","EnableFirewall",1,11)
        funcion2( r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile","DefaultInboundAction",1,12)
        funcion2( r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile","DefaultOutboundAction",0,13)
        funcion2( r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging","LogDroppedPackets",1,14)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard","EnableVirtualizationBasedSecurity",1,15)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\Device Metadata","PreventDeviceMetadataFromNetwork",1,16)
        funcion2( r"SOFTWARE\Policies\Microsoft\Control Panel\International","BlockUserInputMethodsForSignIn",1,17)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\System","BlockUserFromShowingAccountDetailsOnSignin",1,18)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\System","DisableLockScreenAppNotifications",1,19)
        funcion2( r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51","DCSettingIndex",1,20)
        funcion2( r"SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51","ACSettingIndex",1,21)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\Explorer","NoAutoplayfornonVolume",1,22)
        funcion2( r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer","NoAutorun",1,23)
        funcion2( r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer","NoDriveTypeAutoRun",255,24)
        funcion2( r"SOFTWARE\Policies\Microsoft\windows Defender\Windows Defender Exploit Guard\Network Protection","EnableNetworkProtection",1,25)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection","DisableIOAVProtection",0,26)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection","DisableRealtimeMonitoring",0,27)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection","DisableBehaviorMonitoring",0,28)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan","DisableRemovableDriveScanning",0,29)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender\Scan","DisableEmailScanning",0,30)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender","PUAProtection",1,31)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows Defender","DisableAntiSpyware",0,32)
        funcion2( r"SOFTWARE\Policies\Microsoft\AppHVSI","AllowCameraMicrophoneRedirection",0,33)
        funcion2( r"SOFTWARE\Policies\Microsoft\AppHVSI","AllowAppHVSI_ProviderSet",1,34)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\System","EnableSmartScreen",1,35)
        funcion2( r"SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter","EnabledV9",1,36)
        funcion2( r"SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter","PreventOverride",1,37)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU","NoAutoUpdate",0,38)
        funcion2( r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU","ScheduledInstallDay",0,39)

        # Pone el color dependiendo del simbolo
        tree.tag_configure('✔', background='#88dc65')
        tree.tag_configure('X', background='#f0394d')

        # Detener la barra de progreso al finalizar
        progress.stop()
        # Destruir la barra de progreso
        progress.destroy()

        # Habilitar las otras pestañas después de la auditoría
        notebook.tab(1, state="normal")
        notebook.tab(2, state="normal")

        contar_y_graficar()
    # Crear un hilo para la auditoría y pasar la barra de progreso como argumento
    thread = threading.Thread(target=ejecutar_auditoria, args=(progress,))
    thread.start()

def contar_y_graficar():
    global etiqueta_resultado
    # Verificar si ya existe un widget de gráfico
    if hasattr(contar_y_graficar, 'canvas'):
        # Destruir el widget existente
        contar_y_graficar.canvas.get_tk_widget().destroy()

    # Destruir la etiqueta existente
    if etiqueta_resultado:
        etiqueta_resultado.destroy()

    etiqueta_x = 0
    etiqueta_check = 0

    etiquetas_mal = []  # Almacenar números de etiquetas mal configuradas
    etiquetas_bien = []  # Almacenar números de etiquetas bien configuradas

    # Recorre los elementos del TreeView
    for i, item in enumerate(tree.get_children()):
        etiquetas = tree.item(item, 'tags')
        if "X" in etiquetas:
            etiqueta_x += 1
            etiquetas_mal.append(i)
        if "✔" in etiquetas:
            etiqueta_check += 1
            etiquetas_bien.append(i)

    # Crear datos para el gráfico de torta
    etiquetas = ['Configuradas incorrectamente', 'Configuradas correctamente']
    valores = [etiqueta_x, etiqueta_check]

    fig = Figure(figsize=(4, 4))  # Ajusta el tamaño del gráfico
    ax = fig.add_subplot(111)
    pie = ax.pie(valores, labels=etiquetas, autopct='%1.1f%%', colors=['red', 'green'])

    # Colocar la etiqueta debajo del gráfico
    ax.legend(pie[0], etiquetas, bbox_to_anchor=(0.1, 0.1), loc="upper right")  # Ajusta la posición de la etiqueta

    ax.set_title('Gráfico de nivel de seguridad')

    # Crear un widget de gráfico de Tkinter y mantener una referencia a él
    contar_y_graficar.canvas = FigureCanvasTkAgg(fig, frame_grafico)
    contar_y_graficar.canvas.get_tk_widget().pack(fill='both', expand=False)

    # Crear etiqueta de resultado debajo del gráfico
    porcentaje_correcto = (etiqueta_check / (etiqueta_x + etiqueta_check)) * 100
    porcentaje_incorrecto = 100 - porcentaje_correcto
    # Mostrar "Todas bien" si todas las etiquetas están bien configuradas
    if etiqueta_check == 40:
        resultado_texto = "¡Todas las 40 estan configuradas correctamente!"
    # Mostrar "Todas mal" si todas las etiquetas están mal configuradas
    elif etiqueta_x == 40:
        resultado_texto = "¡Todas las 40 estan configuradas incorrectamente!"
    else:
        resultado_texto = (
            f"{porcentaje_correcto:.2f}% de las recomendaciones están correctamente configuradas y \n"
            f"{porcentaje_incorrecto:.2f}% están incorrectamente configuradas.\n\n"
            f"De las 40 recomendaciones, {etiqueta_check} estan configuradas correctamente.\n\n"
            f"De las 40 recomendaciones, {etiqueta_x} estan configuradas incorrectamente.\n Lista de las reomendaciones que estan configuradas incorrectamente:\n {etiquetas_mal}"
        )

    etiqueta_resultado = tk.Label(frame_grafico, text=resultado_texto, font=("Arial", 12))  # Ajusta el tamaño de la fuente
    etiqueta_resultado.pack(pady=10, in_=frame_grafico)

def crear_boton_auditar():
    # Cargar la imagen del botón (ajusta la ruta según la ubicación de tu imagen)
    imagen_path = "auditar.png"
    imagen = Image.open(imagen_path)
    imagen = imagen.resize((300, 75))
    imagen_tk = ImageTk.PhotoImage(imagen)

    # Crear el botón con la imagen como fondo
    boton_auditar = tk.Button(
        frame_principal, image=imagen_tk,
        command=Auditar, borderwidth=0,
        relief="raised"
    )
    boton_auditar.imagen_tk = imagen_tk
    # Empacar el botón
    boton_auditar.pack(pady=20)
    # Configurar eventos de ratón
    def mostrar_etiqueta(event):
        etiqueta.config(text="¡Hacer clic para auditar!")
    def ocultar_etiqueta(event):
        etiqueta.config(text="")
    etiqueta = tk.Label(frame_principal, text="", font=("Arial", 15))
    etiqueta.pack(pady=10)
    boton_auditar.bind("<Enter>", mostrar_etiqueta)
    boton_auditar.bind("<Leave>", ocultar_etiqueta)
    return boton_auditar


# Crear la ventana principal
ventana = Tk()
ventana.title("SeeHarden")
ventana.resizable(0, 0)
ventana.iconbitmap("Logo.ico")
ventana.geometry("720x640")
ventana.config(bg="white")

# Crear una pestaña principal
notebook = ttk.Notebook(ventana)

# Pestaña 1: Principal
frame_principal = ttk.Frame(notebook)
frame_principal.pack(fill="both", expand=True)
notebook.add(frame_principal, text="Principal")

fondo = ImageTk.PhotoImage(Image.open('fondo.jpg'))
background = Label(frame_principal, image=fondo)
background.place(x=0, y=0, relwidth=1, relheight=1)

logo = ImageTk.PhotoImage(Image.open('logoL.png'))
logol = Label(frame_principal, image=logo).pack(pady=10)
# Label on la descripcion del programa
descripcion_predeterminada = "SeeHarden es una herramienta que te permite dar seguimiento de la correcta configuración de tu sistema operativo Windows 10, al presionar el botón esta mostrara el listado de las configuraciones, en las cuales se detallara si está configurada de manera correcta o no según el estándar dado por la organización para el internet seguro CIS."
etiqueta_descripcion = tk.Label(frame_principal, text=descripcion_predeterminada, justify="center", wraplength=400)
etiqueta_descripcion.pack(padx=10, pady=10)
# Crear el botón "Auditar"
boton_auditar = crear_boton_auditar()

estilo_pestanas = ttk.Style()
estilo_pestanas.theme_create("EstiloPersonalizado", parent="alt", settings={
    "TNotebook.Tab": {"configure": {"padding": [5, 5], "background": "#80c8ed"}, "map": {"background": [("selected", "#919191")]}},
})
estilo_pestanas.theme_use("EstiloPersonalizado")

# Pestaña 2: Detalles
frame_detalles = ttk.Frame(notebook)
frame_detalles.pack(fill="both", expand=True)
notebook.add(frame_detalles, text="Detalles")

# Crear el Treeview en la pestaña de Detalles
lista_recomendaciones = []
with open("recomendaciones.txt", 'r', encoding='utf-8') as procfile:
    for line in procfile:
        lista_recomendaciones.append(line)
# Crear el Treeview con encabezados y columnas
tree = ttk.Treeview(frame_detalles, column=("col0", "col1", "col2"), show='headings', height=15)
tree.heading("col0", text="No.")
tree.column("col0", anchor=tk.CENTER, width=30)
tree.heading("col1", text="Política")
tree.column("col1", anchor=tk.W, width=900)
tree.heading("col2", text="Estado")
tree.column("col2", anchor=tk.CENTER, width=40)

# Agregar barras de desplazamiento al Treeview
scrollbar_y = ttk.Scrollbar(frame_detalles, orient="vertical", command=tree.yview)
scrollbar_y.pack(side="right", fill="y")
scrollbar_x = ttk.Scrollbar(frame_detalles, orient="horizontal", command=tree.xview)
scrollbar_x.pack(side="bottom", fill="x")
tree.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
tree.bind("<Double-1>", informacion)
tree.pack()


# Pestaña 3: Gráfico
frame_grafico = ttk.Frame(notebook)
frame_grafico.pack(fill="both", expand=True)
notebook.add(frame_grafico, text="Gráfico")

notebook.tab(1, state="hidden")
notebook.tab(2, state="hidden")
notebook.pack(fill="both", expand=True)
ventana.mainloop()

