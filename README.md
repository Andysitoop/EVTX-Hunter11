# EVTX Hunter


![EVTX Hunter](image/logo.jpeg)


 
Manual de usuario para extraer eventos específicos desde archivos `.evtx` y exportarlos a `.csv`.
 
El flujo recomendado es usar la **UI Web** (Flask). La **API** es opcional.
 
## Muestra (UI)
 
![Muestra de la herramienta](image/muestra.jpg)
 
## Creador
 
Andysitoop
 
## Qué hace
 
 - Procesa carpetas de evidencia dentro de `Input\`.
 - Genera CSV en `Salidacsv\` (o en la carpeta de salida que indiques).
 - Permite limitar eventos por archivo, incluir/excluir XML y elegir qué logs procesar.
 
## Guía rápida (UI)
 
 1. Coloca tu evidencia en `Input\Evidencia 1\`, `Input\Evidencia 2\`, etc.
 2. Instala dependencias.
 3. Ejecuta `python app.py`.
 4. Abre http://127.0.0.1:5000.
 5. Ejecuta la extracción y descarga los `.csv`.
 
 ## Preparar la evidencia (estructura y nombres)
 
 En la raíz del proyecto:
 
 - `Input\` (carpeta raíz de evidencia)
 - `Salidacsv\` (salida por defecto)
 
 Dentro de `Input\` crea carpetas por evidencia:
 
 - `Input\Evidencia 1\`
 - `Input\Evidencia 2\`
 - etc.
 
 En cada `Evidencia N` coloca los EVTX. El extractor intenta encontrar los siguientes nombres (también acepta algunas variantes):
 
 - `Security.evtx` (o `Security`)
 - `Microsoft-Windows-PowerShell%4Operational.evtx`
 - `Microsoft-Windows-Sysmon%4Operational.evtx` (o `Sysmon.evtx` / `Sysmon`)
 
 ## Instalación
 
 Requisitos:
 
 - Python 3.x
 
 En PowerShell, desde la raíz del proyecto:
 
 ```powershell
 python -m venv .venv
 .\.venv\Scripts\Activate.ps1
 pip install -r requirements.txt
 ```
 
 ## Usar la aplicación (UI Web)
 
 ### 1) Iniciar
 
 ```powershell
 python app.py
 ```
 
 Abre:
 
 - http://127.0.0.1:5000
 
 ### 2) Configurar
 
 En la pantalla principal puedes ajustar:
 
 - **input_root**: carpeta raíz de evidencia (por defecto `./Input`).
   - Debe contener subcarpetas tipo `Evidencia 1`, `Evidencia 2`, etc.
 
 - **output_root**: carpeta de salida (por defecto `./Salidacsv`).
   - Aquí se guardan los CSV y también es la carpeta que la UI lista para descargar.
 
 - **max_events**: máximo de eventos exportados por cada EVTX.
   - `0` = sin límite.
   - Útil si solo quieres una muestra rápida o si los EVTX son muy grandes.
 
 - **include_xml**: incluye o no la columna `Xml`.
   - Activado: el CSV contiene el XML completo del evento (más peso/tamaño).
   - Desactivado: CSV más liviano, con campos principales.
 
 - **logs_choice**: qué logs procesar.
   - `all`: procesa Security + PowerShell Operational + Sysmon.
   - `security`: solo `Security.evtx`.
   - `powershell`: solo `Microsoft-Windows-PowerShell%4Operational.evtx`.
   - `sysmon`: solo `Microsoft-Windows-Sysmon%4Operational.evtx` / `Sysmon`.
 
 ### 3) Ejecutar y descargar
 
 - Inicia la extracción desde el botón de ejecutar.
 - Al finalizar, la UI lista los `.csv` disponibles en la carpeta de salida.
 - Puedes descargar los archivos desde la misma UI.
 
 ## API (opcional)
 
 Si quieres automatizar (sin UI), puedes controlar la extracción vía JSON:
 
 - `POST /api/start`
 - `GET /api/status/<job_id>`
 - `POST /api/pause/<job_id>`
 - `POST /api/resume/<job_id>`
 - `POST /api/cancel/<job_id>`
 
 Ejemplo:
 
 ```powershell
 curl -Method Post http://127.0.0.1:5000/api/start -ContentType "application/json" -Body '{
   "input_root": "C:\\ruta\\al\\proyecto\\Input",
   "output_root": "C:\\ruta\\al\\proyecto\\Salidacsv",
   "max_events": 0,
   "include_xml": true,
   "logs_choice": "all"
 }'
 ```
 
 ## Resultados (qué CSV genera)
 
 Para cada `Evidencia N` y por cada log detectado, crea un CSV con estos filtros:
 
 - **Security**: EventID `4688`
 - **PowerShell Operational**: EventID `4103`, `4104`, `4105`
 - **Sysmon Operational**: EventID `1`
 
 Columnas incluidas:
 
 - `TimeCreated`, `Id`, `ProviderName`, `Level`, `MachineName`, `RecordId`
 - `Xml` (solo si `include_xml` está habilitado)
 
 ## Notas
 
 - La app genera nombres de archivo únicos si detecta colisiones en la carpeta de salida.
 - El flujo principal ya no depende del script PowerShell.
 
 ## Solución de problemas
 
 - **No se genera CSV para una evidencia**
   - Verifica que exista la carpeta `Input\Evidencia N\`.
   - Verifica que el EVTX exista y tenga uno de los nombres esperados (o variantes).
 
 - **Se genera CSV pero viene vacío**
   - Recuerda que la herramienta exporta solo los EventID indicados en “Resultados”.
   - Prueba ejecutando con `logs_choice=all`.
 
 - **La UI no abre**
   - Confirma que `python app.py` se esté ejecutando sin errores.
   - Abre exactamente http://127.0.0.1:5000.
