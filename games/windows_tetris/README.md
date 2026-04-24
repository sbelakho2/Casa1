Casa1 Windows Tetris

This folder contains a standalone Windows x64 Tetris executable implemented as a regular Win32 GUI program.

Properties:
- No Casa1 headers, symbols, or runtime dependencies
- Builds into a self-contained Windows PE executable
- Uses Win32 window creation, a DXGI/D3D11 swapchain, and XAudio2 for sound

Controls:
- `A`: move left
- `D`: move right
- `S`: soft drop
- `W`: rotate clockwise
- `Q`: rotate counter-clockwise
- `Left` / `Right` / `Down`: live-play aliases for `A` / `D` / `S`
- `Up`: live-play alias for `W`
- `Space`: hard drop
- `Enter`: start from the title screen or resume from pause
- `P`: pause or resume the current game
- `N`: start a fresh game immediately
- `R`: restart immediately

Gameplay:
- Starts on a title screen instead of dropping straight into a run
- Tracks score, cleared lines, current level, next piece, and best score
- Uses a compact right-side HUD during play and shows the top-5 table on title and game-over screens
- Shows a pause overlay and a game-over overlay
- Maintains a top-5 high-score table in `casa1-tetris.dat`
- Uses a shuffled 7-bag piece generator instead of a fixed demo sequence
- Awards score for soft drops, hard drops, and standard line clears

Replay fixtures:
- `replays/start-enter.json`: start from the title screen with `Enter`
- `replays/pause-after-start.json`: start, then land on the pause overlay immediately
- `replays/resume-after-pause.json`: start, pause, then resume with `Enter`
- `replays/restart-after-start.json`: start, then trigger the immediate restart path with `R`
- `replays/new-game-after-start.json`: start, then trigger the immediate new-game path with `N`
- All replay events are injected at window creation, so these files are meant for short launch-time state transitions

Example live launch:

```sh
cargo run --quiet --bin macwin -- ge:play \
	--ge /Users/sabelakhoua/IdeaProjects/Casa1/games/windows_tetris/ges/casa1-live-tetris \
	--exe /Users/sabelakhoua/IdeaProjects/Casa1/games/windows_tetris/dist/casa1-tetris.exe \
	--input-replay /Users/sabelakhoua/IdeaProjects/Casa1/games/windows_tetris/replays/pause-after-start.json
```

Build:

```sh
sh ./build.sh
```

Smoke build for automated runtime validation:

```sh
TETRIS_SMOKE=1 sh ./build.sh
```

To choose a different output path:

```sh
sh ./build.sh /absolute/path/to/casa1-tetris.exe
```

The smoke build is still a normal standalone Windows PE executable. It keeps the same Win32, DXGI/D3D11, and XAudio2 imports, but exits quickly enough for Casa1 regression runs.

Default output:
- `dist/casa1-tetris.exe`