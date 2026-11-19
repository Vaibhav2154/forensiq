"""Legacy LogIQ CLI agent, migrated for ForensIQ.

Provenance: ``LogIQ-main/aiagent`` inside ``LogIQ-main.zip``
(SHA-256 ``d49210675b8a1c6ff05fb3264b6e976e4f1bd4eb449f0df438f9dc2d85b42ac4``).

Contents are behaviourally unchanged. The only edits are import mechanics:

* ``from ai_agent import ...`` -> ``from .ai_agent import ...`` (and likewise
  for ``dynamic_log_extractor`` / ``mongodb_service``);
* the Pre-RAG classifier is imported lazily, so importing this package does not
  require the optional ML stack (pandas/numpy/joblib/redis).

Do not add new features here. New behaviour belongs in ``cli_agent.client``.
"""

__version__ = "1.8.0"
