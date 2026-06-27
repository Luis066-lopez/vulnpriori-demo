"""Función placeholder de clasificación y schemas Pydantic del contrato.

Este módulo define dos cosas:

  1. El CONTRATO de entrada y salida de la función de clasificación
     (VulnerabilityFeatures y PriorityOutput). Este contrato refleja las
     10 features definidas en el Capítulo III de la tesis y NO debe
     cambiar cuando se reemplace el placeholder por el modelo ML real.

  2. La función `classify()`, que es la pieza INTERCAMBIABLE. En esta
     versión aplica reglas heurísticas simples sobre el CVSS base.
     En Taller de Grado 2 se reemplazará por una llamada al modelo
     Scikit-learn entrenado, sin tocar nada más del sistema.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


# ============================================================================
# CONTRATO DE LA FUNCIÓN DE CLASIFICACIÓN
# ============================================================================

class VulnerabilityFeatures(BaseModel):
    """Vector de features de entrada para la clasificación.

    Refleja las 10 features definidas en el Capítulo III, desglosadas en
    17 campos físicos. En esta versión del prototipo, solo cvss_base se
    utiliza efectivamente; los demás campos están declarados para
    preservar el contrato que el modelo Scikit-learn consumirá.
    """

    # --- Identificación (no son features predictivas, solo trazabilidad) ---
    package_name: str = Field(description="Nombre del paquete vulnerable")
    package_version: str = Field(description="Versión instalada del paquete")
    cve_id: str = Field(description="Identificador CVE/GHSA/PYSEC")
    fix_versions: List[str] = Field(
        default_factory=list,
        description="Versiones que corrigen la vulnerabilidad",
    )

    # --- Feature 1: CVSS base score ---
    cvss_base: Optional[float] = Field(
        default=None, description="Puntaje CVSS v3.x base, rango 0.0 a 10.0"
    )

    # --- Feature 2: Vector CVSS desglosado en 8 componentes ---
    cvss_av: Optional[str] = Field(default=None, description="Attack Vector: N/A/L/P")
    cvss_ac: Optional[str] = Field(default=None, description="Attack Complexity: L/H")
    cvss_pr: Optional[str] = Field(default=None, description="Privileges Required: N/L/H")
    cvss_ui: Optional[str] = Field(default=None, description="User Interaction: N/R")
    cvss_s: Optional[str] = Field(default=None, description="Scope: U/C")
    cvss_c: Optional[str] = Field(default=None, description="Confidentiality Impact: N/L/H")
    cvss_i: Optional[str] = Field(default=None, description="Integrity Impact: N/L/H")
    cvss_a: Optional[str] = Field(default=None, description="Availability Impact: N/L/H")

    # --- Feature 3: EPSS score ---
    epss_score: Optional[float] = Field(
        default=None,
        description="Probabilidad de explotación a 30 días, rango 0.0 a 1.0",
    )

    # --- Feature 4: Presencia en CISA KEV ---
    in_kev: Optional[bool] = Field(
        default=None, description="Presencia en catálogo KEV de CISA"
    )

    # --- Feature 5: CWE asociado ---
    cwe_id: Optional[str] = Field(
        default=None, description="Identificador CWE de la debilidad subyacente"
    )

    # --- Feature 6: Tipo de dependencia por jerarquía ---
    dependency_hierarchy: Optional[str] = Field(
        default=None, description="'direct' o 'transitive'"
    )

    # --- Feature 7: Tipo de dependencia por uso ---
    dependency_usage: Optional[str] = Field(
        default=None, description="'production' o 'development'"
    )

    # --- Feature 8: Antigüedad del CVE en días ---
    cve_age_days: Optional[int] = Field(
        default=None, description="Días desde la publicación del CVE"
    )

    # --- Feature 9: Versión de corrección disponible ---
    fix_available: Optional[bool] = Field(
        default=None, description="Existe una versión que corrige la vulnerabilidad"
    )

    # --- Feature 10: Existencia de exploit público ---
    public_exploit: Optional[bool] = Field(
        default=None, description="Existe un exploit público conocido"
    )


class PriorityOutput(BaseModel):
    """Resultado de la clasificación de una vulnerabilidad."""

    package_name: str
    package_version: str
    cve_id: str
    fix_versions: List[str] = Field(default_factory=list)
    priority: str = Field(description="Crítica, Alta, Media o Baja")
    cvss_base: Optional[float] = None
    reasoning: str = Field(
        description="Explicación en lenguaje natural del por qué de la prioridad"
    )


# ============================================================================
# FUNCIÓN PLACEHOLDER DE CLASIFICACIÓN
# ============================================================================

def classify(features: VulnerabilityFeatures) -> PriorityOutput:
    """Asigna una prioridad a una vulnerabilidad.

    IMPORTANTE: esta es la función PLACEHOLDER del prototipo.

    Aplica reglas heurísticas simples basadas únicamente en el puntaje
    CVSS base. El modelo Scikit-learn entrenado en Taller de Grado 2
    reemplazará esta función SIN modificar su firma
    (VulnerabilityFeatures -> PriorityOutput).

    Reglas actuales:
        CVSS base >= 9.0           -> Crítica
        CVSS base entre 7.0 y 8.9  -> Alta
        CVSS base entre 4.0 y 6.9  -> Media
        CVSS base <  4.0           -> Baja
        CVSS base no disponible    -> Media (asignación conservadora por defecto)
    """
    score = features.cvss_base

    if score is None:
        priority = "Media"
        reasoning = (
            "No se pudo obtener el puntaje CVSS; se asigna prioridad Media "
            "por defecto conservador."
        )
    elif score >= 9.0:
        priority = "Crítica"
        reasoning = f"Puntaje CVSS base {score:.1f} en rango Crítica (>= 9.0)."
    elif score >= 7.0:
        priority = "Alta"
        reasoning = f"Puntaje CVSS base {score:.1f} en rango Alta (7.0 a 8.9)."
    elif score >= 4.0:
        priority = "Media"
        reasoning = f"Puntaje CVSS base {score:.1f} en rango Media (4.0 a 6.9)."
    else:
        priority = "Baja"
        reasoning = f"Puntaje CVSS base {score:.1f} en rango Baja (< 4.0)."

    return PriorityOutput(
        package_name=features.package_name,
        package_version=features.package_version,
        cve_id=features.cve_id,
        fix_versions=features.fix_versions,
        priority=priority,
        cvss_base=score,
        reasoning=reasoning,
    )
