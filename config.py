"""Shared pipeline configuration module for TEAM T12 DFIR Pipeline."""

from dataclasses import dataclass


@dataclass
class PipelineConfig:
    use_llm: bool = False
    ollama_model: str = "llama3.1:8b-instruct-q4_K_M"
    ollama_seed: int = 42
    ollama_temp: float = 0.0

    use_ast_norm: bool = False
    use_morse_decay: bool = False
    use_size_norm: bool = True
    use_bm25_context: bool = False

    alpha_tactic_diversity: float = 0.25
    pseudo_edge_window_sec: int = 300
    top_k_subgraphs: int = 5
    max_events_per_prompt: int = 25

    # Canonical-time comparison tolerance (ms). Never compare timestamps for equality.
    # Observed TimeCreated vs Sysmon UtcTime skew in reference samples: 0..2048 ms.
    temporal_tolerance_ms: int = 2500

    benign_roots: tuple = (
        "services.exe",
        "svchost.exe",
        "wininit.exe",
        "explorer.exe",
        "lsass.exe",
        "smss.exe",
        "csrss.exe",
    )


config = PipelineConfig()

