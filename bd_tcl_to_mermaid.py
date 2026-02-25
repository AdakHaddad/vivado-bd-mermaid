#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


BD_HINT_PATTERNS = [
    re.compile(r"\bcreate_bd_design\b"),
    re.compile(r"\bcreate_bd_cell\b"),
    re.compile(r"\bconnect_bd_intf_net\b"),
    re.compile(r"\bconnect_bd_net\b"),
    re.compile(r"\bassign_bd_address\b"),
    re.compile(r"\bcreate_bd_addr_seg\b"),
]

CREATE_CELL_RE = re.compile(
    r"""create_bd_cell\s+
        (?:-type\s+\S+\s+)?          # optional -type
        (?:-vlnv\s+(\S+)\s+)?        # optional -vlnv
        (\S+)                        # instance name
    """,
    re.VERBOSE,
)

GET_BD_INTF_PINS_RE = re.compile(r"get_bd_intf_pins\s+([^\]\s]+)")
GET_BD_PINS_RE = re.compile(r"get_bd_pins\s+([^\]\s]+)")

# Filter for "Vivado-like" clk/reset nets (to avoid drawing *everything*)
CLKRESET_ALLOW_RE = re.compile(
    r"""(?ix)
    (?:^|/)(?:clk|aclk|s_axi_aclk|m_axi_aclk|slowest_sync_clk)(?:$|[^A-Za-z0-9_])|
    (?:^|/)(?:reset|rst|aresetn|s_axi_aresetn|peripheral_aresetn|interconnect_aresetn|mb_reset|bus_struct_reset|peripheral_reset|ext_reset_in|aux_reset_in|dcm_locked|locked)(?:$|[^A-Za-z0-9_])
    """
)


@dataclass(frozen=True)
class Edge:
    src_cell: str
    dst_cell: str
    kind: str  # "intf" or "net"
    src_ep: str
    dst_ep: str


def looks_like_bd_tcl(text: str) -> bool:
    hits = sum(1 for pat in BD_HINT_PATTERNS if pat.search(text))
    return ("create_bd_cell" in text) and (("connect_bd_intf_net" in text) or ("connect_bd_net" in text)) and hits >= 2


def sanitize_path_to_filename(p: Path) -> str:
    s = p.as_posix()
    s = re.sub(r"[^A-Za-z0-9._/-]+", "_", s)
    s = s.replace("/", "__")
    if not s.endswith(".mmd"):
        s += ".mmd"
    return s


def cell_from_endpoint(ep: str) -> str:
    return ep.split("/", 1)[0] if "/" in ep else ep


def node_id_for_cell(cell: str) -> str:
    return "n_" + re.sub(r"[^A-Za-z0-9_]", "_", cell)


def parse_cells(text: str) -> Dict[str, Optional[str]]:
    cells: Dict[str, Optional[str]] = {}
    for m in CREATE_CELL_RE.finditer(text):
        vlnv = m.group(1)
        inst = m.group(2)
        cells[inst] = vlnv
    return cells


def _extract_command_blocks(text: str, cmd: str) -> List[str]:
    lines = text.splitlines()
    blocks: List[str] = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if not line.startswith(cmd):
            i += 1
            continue

        buf = [line]
        i += 1

        # Vivado often uses "\" line continuations
        while buf[-1].endswith("\\") and i < len(lines):
            buf[-1] = buf[-1][:-1].rstrip()
            buf.append(lines[i].strip())
            i += 1

        blocks.append(" ".join(buf))
    return blocks


def _pairwise_fanout(items: Sequence[str]) -> Iterable[Tuple[str, str]]:
    """Turn [A,B,C] into (A,B) and (A,C). For [A,B] returns (A,B)."""
    if len(items) < 2:
        return []
    first = items[0]
    return [(first, it) for it in items[1:]]


def parse_intf_edges(text: str) -> List[Edge]:
    edges: Set[Edge] = set()
    for blk in _extract_command_blocks(text, "connect_bd_intf_net"):
        eps = GET_BD_INTF_PINS_RE.findall(blk)
        for a, b in _pairwise_fanout(eps):
            ca = cell_from_endpoint(a)
            cb = cell_from_endpoint(b)
            if ca != cb:
                edges.add(Edge(ca, cb, "intf", a, b))
    return sorted(edges, key=lambda e: (e.src_cell, e.dst_cell, e.src_ep, e.dst_ep))


def _is_clkreset_endpoint(ep: str) -> bool:
    # ep is like "rst_clk_wiz_0_100M/peripheral_aresetn" or "clk_wiz_0/clk_out1"
    return bool(CLKRESET_ALLOW_RE.search(ep))


def parse_clkreset_net_edges(text: str) -> List[Edge]:
    edges: Set[Edge] = set()
    for blk in _extract_command_blocks(text, "connect_bd_net"):
        eps = GET_BD_PINS_RE.findall(blk)
        # only keep endpoints that look like clk/reset network signals
        eps = [ep for ep in eps if _is_clkreset_endpoint(ep)]
        for a, b in _pairwise_fanout(eps):
            ca = cell_from_endpoint(a)
            cb = cell_from_endpoint(b)
            if ca != cb:
                edges.add(Edge(ca, cb, "net", a, b))
    return sorted(edges, key=lambda e: (e.src_cell, e.dst_cell, e.src_ep, e.dst_ep))


def mermaid_for_design(
    title: str,
    cells: Dict[str, Optional[str]],
    edges: List[Edge],
    *,
    show_vlnv: bool,
    edge_labels: str,  # "none" | "kind" | "short"
) -> str:
    lines: List[str] = []
    lines.append("flowchart LR")
    lines.append(f"  %% {title}")
    lines.append("")

    seen_cells: Set[str] = set(cells.keys())
    for e in edges:
        seen_cells.add(e.src_cell)
        seen_cells.add(e.dst_cell)

    for inst in sorted(seen_cells):
        nid = node_id_for_cell(inst)
        vlnv = cells.get(inst)
        if show_vlnv and vlnv:
            lines.append(f'  {nid}["{inst}\\n{vlnv}"]')
        else:
            lines.append(f'  {nid}["{inst}"]')

    lines.append("")

    for e in edges:
        na = node_id_for_cell(e.src_cell)
        nb = node_id_for_cell(e.dst_cell)

        if edge_labels == "none":
            lines.append(f"  {na} --> {nb}")
            continue

        if edge_labels == "kind":
            kind = "AXI" if e.kind == "intf" else "net"
            lines.append(f"  {na} -->|{kind}| {nb}")
            continue

        # short: keep endpoints but compact them (only port names, not full cell/port)
        def port_only(ep: str) -> str:
            return ep.split("/", 1)[1] if "/" in ep else ep

        kind = "AXI" if e.kind == "intf" else "net"
        lbl = f"{port_only(e.src_ep)}→{port_only(e.dst_ep)}"
        lbl = lbl.replace('"', "'")
        lines.append(f'  {na} -->|{kind}: {lbl}| {nb}')

    lines.append("")
    return "\n".join(lines)


def update_readme_index(readme_path: Path, generated_files_abs: List[Path], repo_root: Path) -> None:
    start = "<!-- BD_MERMAID_INDEX_START -->"
    end = "<!-- BD_MERMAID_INDEX_END -->"

    if not readme_path.exists():
        raise SystemExit(
            f"README not found at {readme_path}.\n"
            "Create README.md with the markers, or run with --readme pointing to an existing file."
        )

    content = readme_path.read_text(encoding="utf-8")

    if start not in content or end not in content:
        raise SystemExit(
            "README is missing required markers.\n"
            "Add these lines to README.md once:\n\n"
            f"{start}\n{end}\n"
        )

    rels = [p.relative_to(repo_root).as_posix() for p in sorted(generated_files_abs)]

    # Prefer previewing the AXI diagram if present
    preview_rel = None
    for r in rels:
        if r.endswith("_axi.mmd"):
            preview_rel = r
            break
    if preview_rel is None and rels:
        preview_rel = rels[0]

    block_lines: List[str] = []
    block_lines.append(start)
    block_lines.append("")
    block_lines.append("## Vivado Block Designs (auto-generated)")
    block_lines.append("")
    if not rels:
        block_lines.append("_No Vivado BD Tcl files detected (no create_bd_cell/connect_bd_* found)._")
    else:
        block_lines.append("Generated Mermaid files:")
        block_lines.append("")
        for r in rels:
            block_lines.append(f"- `{r}`")

        if preview_rel:
            block_lines.append("")
            block_lines.append("Preview (AXI view):")
            block_lines.append("")
            block_lines.append("```mermaid")
            block_lines.append((repo_root / preview_rel).read_text(encoding="utf-8").rstrip())
            block_lines.append("```")

    block_lines.append("")
    block_lines.append(end)

    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    new_content = pattern.sub("\n".join(block_lines), content)
    readme_path.write_text(new_content, encoding="utf-8")


def find_tcl_files(repo_root: Path) -> Iterable[Path]:
    for p in repo_root.rglob("*.tcl"):
        if ".git" in p.parts:
            continue
        yield p


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".", help="Repository root")
    ap.add_argument("--out-dir", default="docs/bd", help="Output directory for .mmd files")
    ap.add_argument("--readme", default="README.md", help="README file to update")

    ap.add_argument("--show-vlnv", action="store_true", help="Include VLNV text inside node labels.")
    ap.add_argument("--axi-edge-labels", choices=["none", "kind", "short"], default="kind", help="Edge labels for AXI diagram.")
    ap.add_argument("--clkreset-edge-labels", choices=["none", "kind", "short"], default="none", help="Edge labels for clk/reset diagram.")
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    out_dir = (repo_root / args.out_dir).resolve()
    readme_path = (repo_root / args.readme).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    generated_abs: List[Path] = []

    for tcl in find_tcl_files(repo_root):
        text = tcl.read_text(encoding="utf-8", errors="ignore")
        if not looks_like_bd_tcl(text):
            continue

        cells = parse_cells(text)
        tcl_rel = tcl.relative_to(repo_root)

        # AXI-only (Vivado-like bus view)
        axi_edges = parse_intf_edges(text)
        axi_mmd = mermaid_for_design(
            title=f"AXI view from {tcl_rel.as_posix()}",
            cells=cells,
            edges=axi_edges,
            show_vlnv=args.show_vlnv,
            edge_labels=args.axi_edge_labels,
        )
        axi_out = out_dir / (sanitize_path_to_filename(tcl_rel).replace(".mmd", "_axi.mmd"))
        axi_out.write_text(axi_mmd, encoding="utf-8")
        generated_abs.append(axi_out)

        # Clock/reset filtered net view
        clk_edges = parse_clkreset_net_edges(text)
        clk_mmd = mermaid_for_design(
            title=f"Clock/reset view from {tcl_rel.as_posix()}",
            cells=cells,
            edges=clk_edges,
            show_vlnv=False,
            edge_labels=args.clkreset_edge_labels,
        )
        clk_out = out_dir / (sanitize_path_to_filename(tcl_rel).replace(".mmd", "_clkreset.mmd"))
        clk_out.write_text(clk_mmd, encoding="utf-8")
        generated_abs.append(clk_out)

    update_readme_index(readme_path, generated_abs, repo_root)


if __name__ == "__main__":
    main()