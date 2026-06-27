"""API FastAPI del prototipo de priorización de vulnerabilidades.

Expone dos endpoints:

  POST /scan-report
      Recibe la salida JSON cruda de pip-audit. Para cada vulnerabilidad:
        1. Resuelve el ID al CVE correspondiente.
        2. Enriquece con el CVSS base consultando el NVD del NIST.
        3. Construye el vector de features.
        4. Llama a la función `classify()`.
      Devuelve la lista de resultados ordenada por prioridad.

  POST /classify
      Recibe directamente un VulnerabilityFeatures ya construido y lo
      pasa a `classify()`. Este es el endpoint de contrato puro y el que
      consumirá el modelo Scikit-learn en Taller de Grado 2.

Para arrancar la API en local:
    uvicorn main:app --host 0.0.0.0 --port 8000
"""

from typing import List, Optional
import requests as http
from fastapi import FastAPI
from pydantic import BaseModel

from classifier import VulnerabilityFeatures, PriorityOutput, classify


# ============================================================================
# APLICACIÓN FastAPI
# ============================================================================

app = FastAPI(
    title="vulnpriori-demo",
    description=(
        "Prototipo básico de priorización de vulnerabilidades en "
        "dependencias de software (Tesis UPEA, Dueñas Lopez 2026)."
    ),
    version="0.1.0",
)


# ============================================================================
# MODELOS PARA LA SALIDA CRUDA DE pip-audit
# ============================================================================

class PipAuditVuln(BaseModel):
    """Una vulnerabilidad reportada por pip-audit."""
    id: str
    fix_versions: List[str] = []
    aliases: List[str] = []
    description: str = ""


class PipAuditDep(BaseModel):
    """Una dependencia analizada con sus vulnerabilidades."""
    name: str
    version: str
    vulns: List[PipAuditVuln] = []


class PipAuditReport(BaseModel):
    """Salida JSON cruda de `pip-audit --format json`."""
    dependencies: List[PipAuditDep]


# ============================================================================
# ENRIQUECIMIENTO DE METADATOS
# ============================================================================

def _resolve_cve_id(raw_id: str, aliases: List[str]) -> str:
    """Si el ID original no es un CVE, busca un alias CVE.

    pip-audit suele devolver IDs PYSEC o GHSA; el NVD solo entiende CVEs.
    """
    if raw_id.startswith("CVE-"):
        return raw_id
    for alias in aliases:
        if alias.startswith("CVE-"):
            return alias
    return raw_id


def _fetch_cvss_from_nvd(cve_id: str) -> Optional[float]:
    """Consulta el NVD para obtener el CVSS base score de un CVE.

    Devuelve None si el ID no es un CVE válido, si el NVD no tiene métricas
    o si falla la consulta. La llamada usa un timeout conservador.

    NOTA: en esta versión básica del prototipo, la consulta al NVD se
    realiza en tiempo de inferencia. En la versión completa el CVSS estará
    disponible en el dataset de entrenamiento del modelo y no será
    necesario consultarlo en línea.
    """
    if not cve_id.startswith("CVE-"):
        return None

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        resp = http.get(url, timeout=20)
        if resp.status_code != 200:
            return None
        data = resp.json()
        items = data.get("vulnerabilities", [])
        if not items:
            return None
        metrics = items[0].get("cve", {}).get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            entries = metrics.get(key, [])
            if entries:
                return entries[0].get("cvssData", {}).get("baseScore")
        return None
    except Exception:
        return None


# ============================================================================
# ENDPOINTS
# ============================================================================

@app.get("/")
def root():
    """Healthcheck básico."""
    return {"status": "ok", "service": "vulnpriori-demo", "version": "0.1.0"}


@app.post("/classify", response_model=PriorityOutput)
def classify_endpoint(features: VulnerabilityFeatures) -> PriorityOutput:
    """Clasifica una única vulnerabilidad a partir de su vector de features.

    Este es el endpoint de contrato puro: recibe el vector ya construido y
    delega en la función `classify()`. Es el endpoint que consumirá el
    modelo Scikit-learn en Taller de Grado 2.
    """
    return classify(features)


@app.post("/scan-report", response_model=List[PriorityOutput])
def scan_report_endpoint(report: PipAuditReport) -> List[PriorityOutput]:
    """Procesa una salida JSON cruda de pip-audit.

    Para cada vulnerabilidad detectada:
      1. Resuelve el ID al CVE correspondiente.
      2. Enriquece con CVSS base consultando NVD.
      3. Construye el vector de features.
      4. Aplica `classify()`.

    Devuelve la lista priorizada (Crítica primero, Baja al final).
    """
    results: List[PriorityOutput] = []

    for dep in report.dependencies:
        for vuln in dep.vulns:
            cve_id = _resolve_cve_id(vuln.id, vuln.aliases)
            cvss_base = _fetch_cvss_from_nvd(cve_id)

            features = VulnerabilityFeatures(
                package_name=dep.name,
                package_version=dep.version,
                cve_id=cve_id,
                fix_versions=vuln.fix_versions,
                cvss_base=cvss_base,
                fix_available=bool(vuln.fix_versions),
            )

            results.append(classify(features))

    # Ordenar por prioridad: Crítica > Alta > Media > Baja
    priority_rank = {"Crítica": 0, "Alta": 1, "Media": 2, "Baja": 3}
    results.sort(key=lambda r: priority_rank.get(r.priority, 99))

    return results
