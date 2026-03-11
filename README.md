# EVTX Extractor

## Estructura de carpetas

En la raíz del proyecto:

- `Input\Evidencia 1\` (y `Evidencia 2`, etc.)
- `Salidacsv\`

En cada carpeta `Evidencia N` debes colocar los EVTX:

- `Security.evtx`
- `Microsoft-Windows-PowerShell%4Operational.evtx`
- `Microsoft-Windows-Sysmon%4Operational.evtx`

## Versión Python + Web

Los archivos están en la raíz del proyecto:

- `app.py`
- `evtx_extractor.py`
- `requirements.txt`
- `templates\`

### Instalación

En PowerShell, desde la raíz del proyecto:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Ejecutar la página web

```powershell
python app.py
```

Luego abre:

- http://127.0.0.1:5000

## Qué genera

Crea CSV en `Salidacsv` con filtros:

- Security: EventID 4688
- PowerShell Operational: EventID 4103, 4104, 4105
- Sysmon: EventID 1

## Limpieza

El script PowerShell ya no es necesario para el flujo principal.
