import json
import logging
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from config.settings import get_iso_timestamp
from utils.subprocess_utils import run_command

logger = logging.getLogger("polaris")


class ParserConfig(BaseModel):
    name: str
    executable_path: str = ""
    version: str = ""
    supported_artifacts: list[str] = Field(default_factory=list)
    enabled: bool = True


class ParserResult(BaseModel):
    parser_name: str
    parser_version: str
    status: str  # "success", "failed", "not_configured"
    output_files: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    execution_timestamp: str = Field(default_factory=get_iso_timestamp)


class ParserRegistry:
    def __init__(self) -> None:
        self._parsers: dict[str, ParserConfig] = {}
        self._auto_register_from_env()

    def _auto_register_from_env(self) -> None:
        pecmd_path = os.environ.get("POLARIS_PECMD_PATH", "")
        if pecmd_path and Path(pecmd_path).is_file():
            version = self._detect_version(pecmd_path)
            self.register(ParserConfig(
                name="PECmd",
                executable_path=pecmd_path,
                version=version,
                supported_artifacts=["prefetch"],
                enabled=True,
            ))

    def _detect_version(self, executable_path: str) -> str:
        try:
            returncode, stdout, stderr = run_command(
                [executable_path, "--version"], timeout=15
            )
            combined = (stdout + stderr).strip()
            if combined:
                for line in combined.splitlines():
                    line = line.strip()
                    if line:
                        return line[:120]
            return "unknown"
        except Exception:
            return "unknown"

    def register(self, config: ParserConfig) -> None:
        self._parsers[config.name.lower()] = config
        logger.info(f"Registered parser: {config.name} ({config.executable_path})")

    def unregister(self, name: str) -> bool:
        key = name.lower()
        if key in self._parsers:
            del self._parsers[key]
            return True
        return False

    def get(self, name: str) -> Optional[ParserConfig]:
        return self._parsers.get(name.lower())

    def list_parsers(self) -> list[ParserConfig]:
        return list(self._parsers.values())

    def is_available(self, name: str) -> bool:
        config = self.get(name)
        if not config or not config.enabled:
            return False
        if config.executable_path:
            return Path(config.executable_path).is_file()
        return False

    def run_parser(
        self,
        name: str,
        args: list[str],
        output_dir: Path,
        timeout: int = 300,
    ) -> ParserResult:
        config = self.get(name)
        if not config:
            return ParserResult(
                parser_name=name,
                parser_version="",
                status="not_configured",
                errors=[f"Parser '{name}' is not registered"],
            )

        if not config.enabled:
            return ParserResult(
                parser_name=config.name,
                parser_version=config.version,
                status="not_configured",
                errors=[f"Parser '{config.name}' is disabled"],
            )

        if config.executable_path and not Path(config.executable_path).is_file():
            return ParserResult(
                parser_name=config.name,
                parser_version=config.version,
                status="not_configured",
                errors=[f"Executable not found: {config.executable_path}"],
            )

        output_dir.mkdir(parents=True, exist_ok=True)
        command = [config.executable_path] + args

        logger.info(f"Running parser {config.name}: {' '.join(command)}")
        returncode, stdout, stderr = run_command(command, timeout=timeout)

        output_files: list[str] = []
        for fpath in output_dir.rglob("*"):
            if fpath.is_file():
                output_files.append(str(fpath))

        if returncode == 0:
            return ParserResult(
                parser_name=config.name,
                parser_version=config.version,
                status="success",
                output_files=output_files,
            )
        else:
            errors: list[str] = []
            if stderr.strip():
                errors.append(stderr.strip()[:500])
            errors.append(f"Exit code: {returncode}")
            return ParserResult(
                parser_name=config.name,
                parser_version=config.version,
                status="failed",
                output_files=output_files,
                errors=errors,
            )

    def save_registry(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: v.model_dump() for k, v in self._parsers.items()}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def load_registry(self, path: Path) -> None:
        if not path.exists():
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key, val in data.items():
            self._parsers[key] = ParserConfig(**val)
