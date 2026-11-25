# In-process overlay — drawing into the game's frame

If the task needs ESP, an FPS counter or an in-game menu drawn over the game, draw into the
game's own back buffer from its present callback. Do **not** create a separate topmost
layered window.

## 1. Why not a second window

A layered `WS_EX_TOPMOST` window positioned over a flip-model swap chain can make the
game's `Present` block. When `Present` blocks, the message pump stalls, and Windows marks
the application "Not Responding". This is not a subtle race: it reproduces within seconds
of inject, on every run.

The symptom is confusing because your own code is fine — the game simply cannot present
while your window owns that region of the desktop.

## 2. The present hook

```cpp
using PresentFn  = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain*, UINT, UINT);
using Present1Fn = HRESULT(STDMETHODCALLTYPE*)(IDXGISwapChain*, UINT, UINT,
                                               const DXGI_PRESENT_PARAMETERS*);
```

- Hook **both** `Present` (vtable index 8) and `Present1` (index 22). Titles commonly switch
  to `Present1` and a `Present`-only hook then never fires.
- Obtain the vtable from a throwaway swap chain you create yourself (`D3D11CreateDeviceAnd
  SwapChain` with `GetDesktopWindow()` as the output), then release it. Hooking the target
  process's own swap chain object is not needed and is fragile.
- Hook the vtable entry address (the code), not the object.
- Do the engine-thread work queue drain here too (`thread-and-reentrancy.md` §1): `Present`
  always runs on the game thread.

## 3. Which buffer to draw into

```cpp
UINT index = 0;
IDXGISwapChain3* s3 = nullptr;
if (SUCCEEDED(swap->QueryInterface(__uuidof(IDXGISwapChain3), (void**)&s3)) && s3) {
    index = s3->GetCurrentBackBufferIndex();
    s3->Release();
}
swap->GetBuffer(index, __uuidof(ID3D11Texture2D), (void**)&back);
```

Buffer 0 is only "the one being presented" for the classic discard model. On a flip model
the buffers rotate; drawing into buffer 0 produces a plate that flickers or never appears.

## 4. Set your own viewport — this is the big one

The engine leaves a viewport bound (often a sub-rectangle for a render pass). Anything you
draw outside that rectangle is clipped, silently. The classic symptom: your text at the
top-left never appears, while a big block you drew in the middle does — which sends you
hunting for a text bug that does not exist.

```cpp
D3D11_VIEWPORT saved[4] = {}; UINT n = 4;
ctx->RSGetViewports(&n, saved);

D3D11_VIEWPORT vp{};
vp.Width  = (float)desc.Width;
vp.Height = (float)desc.Height;
vp.MinDepth = 0.f; vp.MaxDepth = 1.f;
ctx->RSSetViewports(1, &vp);

/* ... draw ... */

if (n) ctx->RSSetViewports(n, saved);   // always restore
```

## 5. Texture upload: pitch must match the width you claim

Two independent traps:

**Crop without repack.** If you render text into a wide canvas, then crop it by lowering
`width`, you must also repack each row into a new buffer. Keeping the old stride while
claiming a smaller width makes `SysMemPitch` describe rows that do not exist; the GPU reads
garbage and the quad renders as noise or as nothing.

```cpp
std::vector<uint8_t> packed((size_t)usedW * usedH * 4);
for (int y = 0; y < usedH; ++y)
    memcpy(packed.data() + (size_t)y * usedW * 4,
           canvas.data() + (size_t)y * canvasW * 4, (size_t)usedW * 4);
```

**Alpha left at zero.** GDI's `TextOut` writes RGB and leaves the alpha byte untouched. With
normal alpha blending, every pixel then blends at alpha 0 → fully invisible, even though
`CreateTexture2D` succeeded and `UpdateSubresource` reported success.

```cpp
for (size_t i = 0; i < n; ++i) {
    uint8_t* px = &bits[i*4];
    if (px[0] || px[1] || px[2]) px[3] = 255;   // paint → opaque, else transparent
}
```

Or force it in the shader (`return float4(c.rgb, 1.0);`) if the plate should be fully
opaque.

## 6. Minimal renderer that works

- one vertex buffer: a unit quad, 6 vertices `(pos.xy, uv)` in 0..1;
- one constant buffer: `{screenSize.xy, origin.xy, size.xy, pad.xy}`;
- vertex shader converts pixel space → NDC:

```hlsl
float2 ndc = float2(px.x / screen.x * 2.0 - 1.0, 1.0 - px.y / screen.y * 2.0);
```

- two pixel shaders: textured (atlas sampling) and solid (boxes/lines);
- one sampler: linear, clamp, `ComparisonFunc = NEVER`, `MaxLOD = FLOAT32_MAX`;
- one blend state: standard src-alpha / inv-src-alpha, alpha channel
  `ONE / INV_SRC_ALPHA`;
- one rasterizer: solid fill, **cull none** (otherwise half your quads vanish depending on
  winding), depth clip on.

Gotcha worth remembering: an under-initialised `D3D11_SAMPLER_DESC` (leaving
`ComparisonFunc` at 0) can fail `CreateSamplerState`, and a failed sampler means nothing
renders while every other call reports success. Check `FAILED()` on *every* create call, and
log the pointers once.

## 7. Text strategy

- Render all text with GDI into **one atlas bitmap per frame**, one row per label.
- Draw each label as its own quad with a UV sub-rectangle from that atlas. Do not create one
  texture per label.
- No background plate unless the design asks for it: with per-pixel alpha you can have text
  over the scene with no box at all.
- Keep the font small and the position fixed for lightweight counters (FPS).

## 8. World-space markers (ESP)

For ESP drawn on entities you need projection, which lives in the engine:

1. Get the engine's viewport/camera object through a verified accessor.
2. Call the engine's world→screen function: typically
   `float3* f(out, viewport, worldPos, flag)`.
3. Accept the result only when the returned `z >= 1.0` (in front of the camera) and the
   coordinates are finite.
4. Run projection on the **game thread** (`thread-and-reentrancy.md` §1) and hand finished
   screen-space markers to the renderer.
5. Draw a box sized by distance and the label next to it.

Two traps: calling the projection with a component instead of the camera object returns
zeros; and a wrong viewport getter faults inside the engine (this is where a mid-function
RVA shows itself as an `AV addr=0x...` in your first-chance log).

## 9. Debugging "I drew but nothing appears"

Do this in order, and stop at the first line that behaves differently:

1. Draw one **large solid quad** (e.g. 200×200 at 100,100) with the solid shader. Visible? →
   the pipeline, target and viewport are fine.
2. Draw a **textured quad** with the atlas. Visible? → text rendering/alpha are fine.
3. Draw the **actual label quad**. Visible? → the problem is in the UV rect or the text
   canvas.
4. Compare pixels against a baseline capture with the overlay disabled, so "it looks like
   the scene" cannot fool you.

That sequence isolates: target buffer → viewport → shader/sampler/blend → texture pitch/alpha
→ UV → text, in four captures instead of four hours.
