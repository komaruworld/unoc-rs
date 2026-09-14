# unoc-rs

CLI for Android mod developers. Map classes between app versions, port mods and
hooks, check DEX references, and update class names in smali or Java sources.

Supports APK, APKS, XAPK, APKM and split APK directories, including multi-DEX.

Experimental alpha. Matching is heuristic; review important results before use.

## Install

Requires Rust and Cargo. From the repository root:

```sh
cargo install --path . --locked
```

No Android SDK or Java required.

## Compare

```sh
unoc-rs old.apk new.apk -o report/
```

Open `report/report.html` to browse matches. The output also includes TXT, JSON
and ProGuard mappings.

- `--verified-only` accepts matches that pass stricter checks.
- `--members` adds method and field mappings in `methods.tsv` and `fields.tsv`.
- `--no-html --no-json --no-proguard` reduces report size for large apps.

Start with `verified.txt`. Review `name-only.txt` and `unsafe.txt` manually.
Verified matches can still be wrong; conflicts are excluded from verified output.

## Commands

```sh
# Inspect APK and DEX coverage
unoc-rs inspect app.xapk -o inspect-report/

# Check a standalone DEX against an app
unoc-rs audit-refs app.apk --references bridge.dex -o audit-report/

# Look up a class in a mapping
unoc-rs query -m report/mapping.json 'Lexample/Foo;'

# Apply class mappings to smali or Java sources
unoc-rs remap -m report/mapping.json smali-src/ -o smali-remapped/
```

`audit-refs` skips platform prefixes by default. It fails on incomplete source
DEX parsing or unresolved references above the `--allow-missing` threshold
(default: `0`).

`remap` applies accepted mappings by default and preserves file names and
directory layout. Input and output paths must not overlap; symlinks are rejected.
Regenerate older TXT mappings before remapping, as they may lack conflict markers.

Use `unoc-rs --help` or `unoc-rs <command> --help` for all options.

Address-space limits default to 12 GiB on Linux and are disabled on macOS/Windows.
Windows accepts only `--memory-limit 0`.

## License

TikTokYou developers and anyone acting on their behalf may not use this project.
See [MIT-FTTY (MIT FuckTikTokYou)](LICENSE), a modified MIT license.
