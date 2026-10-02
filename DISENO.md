leer_fallos(ruta)
    recibe: ruta del archivo
    devuelve: lista de líneas que son fallo
    ___ abrir en modo lectura
    ___ recorrer línea por línea
    ___ quedarse con la línea si ___

extraer_ip_y_tiempo(linea)
    recibe: UNA línea
    devuelve: (ip, tiempo)
    ___ sacar el texto de la fecha
    ___ añadir el año y convertir a un valor de tiempo
    ___ sacar la IP

agrupar_por_ip(lineas)
    recibe: lista de líneas de fallo
    devuelve: diccionario {ip: [tiempos]}
    ___ por cada línea, llamar a extraer_ip_y_tiempo
    ___ agregar el tiempo a la lista de esa ip

es_sospechosa(tiempos)
    recibe: lista de tiempos de UNA ip
    devuelve: True o False
    ___ ordenar los tiempos
    ___ ¿hay 3 fallos dentro de una ventana de 5 minutos?

mostrar_sospechosas(diccionario)
    recibe: diccionario {ip: [tiempos]}
    devuelve: nada (imprime)
    ___ por cada ip, llamar a es_sospechosa
    ___ imprimir las que den True
