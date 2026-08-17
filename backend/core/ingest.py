"""Target ingestion — zip extraction and loose file staging."""

import shutil
import zipfile
from pathlib import Path

from fastapi import UploadFile

SOURCE_EXTENSIONS = {
    "c", "h", "cpp", "cc", "cxx", "hpp", "hxx",
    "py", "js", "jsx", "ts", "tsx", "mjs", "cjs",
    "java", "kt", "go", "rs", "rb", "php", "cs",
    "swift", "m", "mm", "scala", "sql", "sh",
    "yaml", "yml", "json", "toml", "xml", "txt", "md",
}

LANGUAGE_MAP = {
    "c": "C", "h": "C", "cpp": "C++", "cc": "C++", "cxx": "C++",
    "hpp": "C++", "hxx": "C++", "py": "Python", "js": "JavaScript",
    "jsx": "JavaScript", "ts": "TypeScript", "tsx": "TypeScript",
    "java": "Java", "go": "Go", "rs": "Rust",
}


def _ext(name: str) -> str:
    parts = name.rsplit(".", 1)
    return parts[-1].lower() if len(parts) > 1 else ""


def detect_languages(paths: list[Path]) -> list[str]:
    langs: set[str] = set()
    for p in paths:
        lang = LANGUAGE_MAP.get(_ext(p.name))
        if lang:
            langs.add(lang)
    return sorted(langs)


async def ingest_upload(files: list[UploadFile], dest: Path) -> tuple[int, list[str], str]:
    """
    Save uploaded files to dest/source/.
    Returns (file_count, languages, target_name).
    """
    source_dir = dest / "source"
    source_dir.mkdir(parents=True, exist_ok=True)

    saved_paths: list[Path] = []
    target_name = "uploaded-target"

    for upload in files:
        filename = upload.filename or "unknown"
        ext = _ext(filename)

        if ext == "zip":
            target_name = Path(filename).stem
            zip_path = source_dir / filename
            content = await upload.read()
            zip_path.write_bytes(content)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(source_dir / "extracted")
            saved_paths.extend(source_dir.rglob("*"))
        elif ext in SOURCE_EXTENSIONS:
            if target_name == "uploaded-target":
                target_name = Path(filename).stem
            out = source_dir / filename
            out.parent.mkdir(parents=True, exist_ok=True)
            content = await upload.read()
            out.write_bytes(content)
            saved_paths.append(out)
        else:
            raise ValueError(f"Unsupported file type: {filename}")

    file_count = sum(1 for p in saved_paths if p.is_file())
    languages = detect_languages([p for p in saved_paths if p.is_file()])
    return file_count, languages, target_name
