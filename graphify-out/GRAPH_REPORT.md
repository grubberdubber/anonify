# Graph Report - anonify  (2026-10-02)

## Corpus Check
- 28 files · ~15,507 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 6 file(s) not represented in the graph (top: (none) 5, .xml 1)

## Summary
- 189 nodes · 237 edges · 21 communities (13 shown, 8 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `22d15e67`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- State
- What You Must Do When Invoked
- Module
- sys.rs
- 🕶️ anonify
- Cmd
- graphify reference: extra exports and benchmark
- state.rs
- tor.rs
- sysctl.rs
- graphify reference: query, path, explain
- graphify reference: add a URL and watch a folder
- graphify reference: commit hook and native CLAUDE.md integration
- graphify reference: incremental update and cluster-only
- graphify reference: GitHub clone and cross-repo merge
- graphify reference: transcribe video and audio
- CLAUDE.md
- .claude/CLAUDE.md
- extraction-spec.md
- dev.sh
- anonify

## God Nodes (most connected - your core abstractions)
1. `State` - 22 edges
2. `Module` - 19 edges
3. `What You Must Do When Invoked` - 12 edges
4. `Cmd` - 10 edges
5. `/graphify` - 10 edges
6. `🕶️ anonify` - 10 edges
7. `graphify reference: extra exports and benchmark` - 8 edges
8. `🎮 Modo de Uso` - 7 edges
9. `main()` - 6 edges
10. `Launch` - 5 edges

## Surprising Connections (you probably didn't know these)
- `enable()` --references--> `State`  [EXTRACTED]
  src/modules/killswitch.rs → src/state.rs
- `Cmd` --references--> `Module`  [EXTRACTED]
  src/main.rs → src/modules/mod.rs
- `activate()` --references--> `State`  [EXTRACTED]
  src/main.rs → src/state.rs
- `deactivate()` --references--> `State`  [EXTRACTED]
  src/main.rs → src/state.rs
- `holds()` --references--> `State`  [EXTRACTED]
  src/main.rs → src/state.rs

## Import Cycles
- None detected.

## Communities (21 total, 8 thin omitted)

### Community 0 - "State"
Cohesion: 0.12
Nodes (16): disable(), enable(), TARGET, disable(), enable(), disable(), enable(), nm_devices() (+8 more)

### Community 1 - "What You Must Do When Invoked"
Cohesion: 0.08
Nodes (24): For /graphify add and --watch, For /graphify query, For the commit hook and native CLAUDE.md integration, For --update and --cluster-only, /graphify, Honesty Rules, Interpreter guard for subcommands, Part A - Structural extraction for code files (+16 more)

### Community 2 - "Module"
Cohesion: 0.13
Nodes (19): activate(), check(), deactivate(), disable(), enable(), holds(), main(), settle_check() (+11 more)

### Community 3 - "sys.rs"
Cohesion: 0.14
Nodes (5): enable(), TABLE, proton(), spawn(), vbox()

### Community 4 - "🕶️ anonify"
Cohesion: 0.12
Nodes (16): 1. Activar el escudo completo (Modo Paranoico), 2. Activar solo lo que te interese, 3. Ver estado y detectar trampas del sistema, 4. Testear fugas (Check de Tor), 5. Lanzar aplicaciones aisladas (sin ser root), 6. Volver a la normalidad (Restauración Total), 🕶️ anonify, ⚡ Características Principales (+8 more)

### Community 5 - "Cmd"
Cohesion: 0.17
Nodes (12): Cli, Cmd, Check, Disable, Enable, Launch, Restore, Status (+4 more)

### Community 6 - "graphify reference: extra exports and benchmark"
Cohesion: 0.22
Nodes (8): graphify reference: extra exports and benchmark, Step 6b - Wiki (only if --wiki flag), Step 7 - Neo4j export (only if --neo4j or --neo4j-push flag), Step 7a - FalkorDB export (only if --falkordb or --falkordb-push flag), Step 7b - SVG export (only if --svg flag), Step 7c - GraphML export (only if --graphml flag), Step 7d - MCP server (only if --mcp flag), Step 8 - Token reduction benchmark (only if total_words > 5000)

### Community 8 - "tor.rs"
Cohesion: 0.36
Nodes (5): dd(), disable(), enable(), stop(), TABLE

### Community 9 - "sysctl.rs"
Cohesion: 0.43
Nodes (6): apply(), HARDEN, holds(), IPV6, path(), revert()

### Community 10 - "graphify reference: query, path, explain"
Cohesion: 0.33
Nodes (5): For /graphify explain, For /graphify path, graphify reference: query, path, explain, Step 0 — Constrained query expansion (REQUIRED before traversal), Step 1 — Traversal

### Community 11 - "graphify reference: add a URL and watch a folder"
Cohesion: 0.50
Nodes (3): For /graphify add, For --watch, graphify reference: add a URL and watch a folder

### Community 12 - "graphify reference: commit hook and native CLAUDE.md integration"
Cohesion: 0.50
Nodes (3): For git commit hook, For native CLAUDE.md integration, graphify reference: commit hook and native CLAUDE.md integration

### Community 13 - "graphify reference: incremental update and cluster-only"
Cohesion: 0.50
Nodes (3): For --cluster-only, For --update (incremental re-extraction), graphify reference: incremental update and cluster-only

## Knowledge Gaps
- **84 isolated node(s):** `anonify`, `dev.sh script`, `Enable`, `Disable`, `Restore` (+79 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 116 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **8 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `State` connect `State` to `sysctl.rs`, `Module`, `sys.rs`, `state.rs`?**
  _High betweenness centrality (0.112) - this node is a cross-community bridge._
- **Why does `Module` connect `Module` to `State`, `Cmd`, `state.rs`?**
  _High betweenness centrality (0.080) - this node is a cross-community bridge._
- **Why does `Cmd` connect `Cmd` to `Module`?**
  _High betweenness centrality (0.042) - this node is a cross-community bridge._
- **What connects `anonify`, `dev.sh script`, `Enable` to the rest of the system?**
  _84 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `State` be split into smaller, more focused modules?**
  _Cohesion score 0.1225071225071225 - nodes in this community are weakly interconnected._
- **Should `What You Must Do When Invoked` be split into smaller, more focused modules?**
  _Cohesion score 0.08 - nodes in this community are weakly interconnected._
- **Should `Module` be split into smaller, more focused modules?**
  _Cohesion score 0.13043478260869565 - nodes in this community are weakly interconnected._