"""Generate a JSON library from FLAC metadata in the Music folder.

The output file (music-library.json) can be consumed by the static music player.
Album entries are grouped and sorted alphabetically, and cover art is pulled
from embedded FLAC pictures when available.
"""
from __future__ import annotations

import base64
import json
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from mutagen.flac import FLAC

try:
    from PIL import Image
except Exception:  # Pillow may not be installed
    Image = None  # type: ignore

MAX_COVER_SIZE = 1000  # longest side in pixels
JPEG_QUALITY = 85

def first_tag(audio: FLAC, key: str, default: Optional[str] = None) -> Optional[str]:
    """Return the first string value for a tag or a default."""
    value = audio.get(key)
    if not value:
        return default
    candidate = value[0]
    return candidate.strip() if isinstance(candidate, str) else default


def encode_cover(audio: FLAC) -> Optional[str]:
    """Return a data URI for the first embedded picture, if present."""
    if not audio.pictures:
        return None
    picture = audio.pictures[0]
    encoded = base64.b64encode(picture.data).decode("ascii")
    return f"data:{picture.mime};base64,{encoded}"


def normalize_name(name: str) -> str:
    """Normalize strings for loose matching (casefold, keep letters/digits incl. CJK)."""
    normalized = unicodedata.normalize("NFKC", name).casefold()
    return "".join(ch for ch in normalized if ch.isalnum())


def build_library(music_dir: Path) -> Dict:
    albums: Dict[str, Dict] = {}
    album_covers: Dict[str, Dict[str, bytes]] = {}

    for path in sorted(music_dir.glob("*.flac")):
        audio = FLAC(path)

        album = first_tag(audio, "album", "Unknown Album") or "Unknown Album"
        artist = first_tag(audio, "artist", "Unknown Artist") or "Unknown Artist"
        album_artist = first_tag(audio, "albumartist", artist) or artist
        year = first_tag(audio, "date") or first_tag(audio, "year")
        title = first_tag(audio, "title", path.stem) or path.stem

        track_number_raw = first_tag(audio, "tracknumber")
        track_number: Optional[int] = None
        if track_number_raw:
            try:
                track_number = int(track_number_raw.split("/")[0])
            except ValueError:
                track_number = None

        duration = round(audio.info.length, 2) if audio.info else None
        cover_pic = audio.pictures[0] if audio.pictures else None
        cover_mime = cover_pic.mime if cover_pic else None
        cover_data = cover_pic.data if cover_pic else None

        rel_src = path.relative_to(music_dir.parent).as_posix()

        album_entry = albums.setdefault(
            album,
            {
                "album": album,
                "albumArtist": album_artist,
                "year": year,
                "cover": None,
                "tracks": [],
            },
        )

        if album not in album_covers and cover_data:
            album_covers[album] = {"mime": cover_mime, "data": cover_data}

        if album_entry.get("albumArtist") in (None, "Unknown Artist") and album_artist:
            album_entry["albumArtist"] = album_artist

        album_entry["tracks"].append(
            {
                "title": title,
                "artist": artist,
                "track": track_number,
                "duration": duration,
                "src": rel_src,
            }
        )

    # Sort tracks inside each album
    for album_entry in albums.values():
        album_entry["tracks"].sort(
            key=lambda t: (
                t["track"] is None,
                t["track"] if t["track"] is not None else 0,
                t["title"].lower(),
            )
        )

    albums_list: List[Dict] = sorted(albums.values(), key=lambda a: a["album"].lower())

    cover_dir = music_dir / "cover"
    cover_dir.mkdir(exist_ok=True)

    def slugify(name: str) -> str:
        base = unicodedata.normalize("NFKC", name)
        safe = "".join(ch if ch.isalnum() else "_" for ch in base)
        safe = "_".join(filter(None, safe.split("_")))
        return safe or "cover"

    def mime_ext(mime: Optional[str]) -> str:
        if not mime:
            return ".jpg"
        if "png" in mime:
            return ".png"
        if "webp" in mime:
            return ".webp"
        if "bmp" in mime:
            return ".bmp"
        return ".jpg"

    for album_entry in albums_list:
        album_name = album_entry["album"]
        cov = album_covers.get(album_name)
        if not cov:
            continue
        mime = cov.get("mime") or "image/jpeg"
        data = cov.get("data")
        if data is None:
            continue
        ext = mime_ext(str(mime))
        filename = f"{slugify(album_name)}{ext}"
        out_path = cover_dir / filename

        try:
            if Image:
                from io import BytesIO

                with Image.open(BytesIO(data)) as img:
                    img = img.convert("RGB")
                    img.thumbnail((MAX_COVER_SIZE, MAX_COVER_SIZE))
                    img.save(out_path, format="JPEG", quality=JPEG_QUALITY, optimize=True)
            else:
                out_path.write_bytes(data)
        except Exception as exc:
            print(f"[cover] Failed to write cover for {album_name}: {exc}")
            continue

        album_entry["cover"] = out_path.relative_to(music_dir.parent).as_posix()

    return {
        "generatedAt": datetime.now().isoformat(timespec="seconds"),
        "musicDir": str(music_dir),
        "albumCount": len(albums_list),
        "trackCount": sum(len(a["tracks"]) for a in albums_list),
        "albums": albums_list,
    }


def main() -> None:
    music_dir = Path(__file__).parent / "Music"
    if not music_dir.exists():
        raise SystemExit(f"Music directory not found at {music_dir}")

    library = build_library(music_dir)
    output_path = Path(__file__).parent / "music-library.json"
    output_path.write_text(json.dumps(library, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {output_path} with {library['albumCount']} albums and {library['trackCount']} tracks.")


if __name__ == "__main__":
    main()
