def update_readme_index(readme_path: Path, generated_files_abs: List[Path], repo_root: Path) -> None:
    start = "<!-- BD_MERMAID_INDEX_START -->"
    end = "<!-- BD_MERMAID_INDEX_END -->"

    # If README doesn't exist, create a minimal one with markers.
    if not readme_path.exists():
        readme_path.write_text(
            "# Vivado BD Mermaid\n\n"
            f"{start}\n"
            f"{end}\n",
            encoding="utf-8",
        )

    content = readme_path.read_text(encoding="utf-8")

    # If markers are missing, append them at the end (do not fail).
    if start not in content or end not in content:
        if not content.endswith("\n"):
            content += "\n"
        content += "\n" + start + "\n" + end + "\n"

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

    # Now replace the marker block
    updated = readme_path.read_text(encoding="utf-8")
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.DOTALL)
    new_content = pattern.sub("\n".join(block_lines), updated)
    readme_path.write_text(new_content, encoding="utf-8")
