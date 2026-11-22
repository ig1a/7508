"""Part C of the BrandAI project: untrusted relay + leak extraction.

Public surface
--------------
relay7508.canary   canary corpus loading and representation-aware matching
relay7508.relay    the logging forward proxy (passive / active modes)
relay7508.scan     leak rates per recipient, condition, secret type and phrasing
relay7508.cli      ``python -m relay7508 relay|scan``
"""

from .canary import Canary, CanarySet, flatten_json_text
from .config import ActivePolicy, RelayConfig

__all__ = ["Canary", "CanarySet", "flatten_json_text", "ActivePolicy", "RelayConfig"]
__version__ = "0.1.0"
