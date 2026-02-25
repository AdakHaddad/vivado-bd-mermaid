# vivado-bd-mermaid

Generate Mermaid diagrams from **Vivado IP Integrator Block Design (BD)** Tcl exports.

This repository is a **reusable GitHub Action** (composite action). Use it in any repo that contains exported Vivado BD `.tcl` files to generate Mermaid `.mmd` diagrams (and optionally update/create a README section).

## What it generates

- `docs/bd/*_axi.mmd` — AXI/interface view (closest to Vivado “bus” diagram)
- `docs/bd/*_clkreset.mmd` — clock/reset view (filtered to avoid noise)

It can also update `README.md` between these markers:

```md
<!-- BD_MERMAID_INDEX_START -->
<!-- BD_MERMAID_INDEX_END -->
```

If `README.md` (or the markers) don’t exist, the generator can create/append them (if your `bd_tcl_to_mermaid.py` includes that behavior).

## Inputs

| Input | Default | Description |
|------|---------|-------------|
| `repo-root` | `.` | Repository root to scan for `.tcl` files |
| `out-dir` | `docs/bd` | Output directory for generated `.mmd` files |
| `readme` | `README.md` | README file to update |
| `args` | `""` | Extra CLI args passed to the generator script |

Common `args` examples:
- `--axi-edge-labels kind --clkreset-edge-labels none`
- `--show-vlnv`

## Example workflow (recommended)

Add this to your target repo as `.github/workflows/vivado-bd-mermaid.yml`:

```yaml
name: Vivado BD -> Mermaid

on:
  push:
    paths:
      - "**/*.tcl"
      - "README.md"
      - ".github/workflows/vivado-bd-mermaid.yml"
  workflow_dispatch: {}

permissions:
  contents: write

jobs:
  generate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: AdakHaddad/vivado-bd-mermaid@v1
        with:
          repo-root: "."
          out-dir: "docs/bd"
          readme: "README.md"
          args: "--axi-edge-labels kind --clkreset-edge-labels none"

      - name: Commit changes (if any)
        run: |
          if git diff --quiet; then exit 0; fi
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add README.md docs/bd
          git commit -m "chore: auto-generate Vivado BD Mermaid diagrams"
          git push
```

## Required repo settings (target repo)

To allow the workflow to push commits:

**Repo → Settings → Actions → General → Workflow permissions → Read and write permissions**

## Notes / limitations

- The generator uses heuristics to detect Vivado BD export Tcl files (looks for `create_bd_cell` and `connect_bd_*`).
- Clock/reset nets are filtered to reduce clutter; AXI is extracted from `connect_bd_intf_net`.
- Mermaid layout is not identical to Vivado; it’s a best-effort structural view.

## License

Choose a license (MIT/Apache-2.0) if you plan to share publicly.
