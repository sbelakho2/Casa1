#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FRAME_W 128
#define FRAME_H 144
#define BOARD_W 10
#define BOARD_H 20
#define CELL 6
#define BOARD_X 8
#define BOARD_Y 8
#define BOARD_CENTER_X (BOARD_X + (BOARD_W * CELL) / 2)
#define PANEL_X 76
#define PANEL_Y 8
#define PANEL_W 44
#define PANEL_H 120
#define BOTTOM_PANEL_X 4
#define BOTTOM_PANEL_Y 52
#define BOTTOM_PANEL_W 56
#define BOTTOM_PANEL_H 40
#define WINDOW_SCALE 5
#define WINDOW_W (FRAME_W * WINDOW_SCALE + 32)
#define WINDOW_H (FRAME_H * WINDOW_SCALE + 54)
#define HORIZONTAL_DAS_MS 150u
#define HORIZONTAL_ARR_MS 55u
#define SOFT_DROP_STEP_MS 30u
#define MAX_HIGH_SCORES 5
#ifdef TETRIS_SMOKE
#define MAX_FRAMES 1
#define MAX_LOCKS 1
#else
#define MAX_FRAMES 0
#define MAX_LOCKS 0
#endif
#define LOCK_WAVE_FRAMES 32
#define CLEAR_WAVE_FRAMES 64

#define TRUE 1
#define FALSE 0

#define WM_QUIT 0x0012u
#define WM_KEYDOWN 0x0100u
#define WM_KEYUP 0x0101u
#define PM_REMOVE 0x0001u

#define WS_VISIBLE 0x10000000u
#define WS_OVERLAPPEDWINDOW 0x00cf0000u

#define DXGI_FORMAT_B8G8R8A8_UNORM 87u
#define DXGI_USAGE_RENDER_TARGET_OUTPUT 0x00000020u
#define DXGI_SWAP_EFFECT_DISCARD 0u

#define D3D_DRIVER_TYPE_HARDWARE 1u
#define D3D_FEATURE_LEVEL_10_1 0x0000a100u
#define D3D11_SDK_VERSION 7u

#define WAVE_FORMAT_PCM 1u
#define XAUDIO2_DEFAULT_PROCESSOR 1u
#define AUDIO_CATEGORY_GAME_EFFECTS 6u
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 0x00000001u
#define OPEN_EXISTING 3u
#define CREATE_ALWAYS 2u
#define FILE_ATTRIBUTE_NORMAL 0x00000080u

typedef int32_t HRESULT;
typedef int32_t BOOL;
typedef uint8_t BYTE;
typedef uint16_t WORD;
typedef uint32_t UINT;
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef int64_t LPARAM;
typedef uint64_t WPARAM;
typedef void *HANDLE;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HICON;
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef uint16_t WCHAR;

typedef struct GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} GUID;

typedef const GUID *REFIID;

typedef struct POINT {
    LONG x;
    LONG y;
} POINT;

typedef struct MSG {
    HWND hwnd;
    UINT message;
    uint32_t padding;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
    DWORD lPrivate;
} MSG;

typedef intptr_t (*WndProc)(HWND, UINT, WPARAM, LPARAM);

typedef struct WNDCLASSEXW {
    UINT cbSize;
    UINT style;
    WndProc lpfnWndProc;
    int32_t cbClsExtra;
    int32_t cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    const WCHAR *lpszMenuName;
    const WCHAR *lpszClassName;
    HICON hIconSm;
} WNDCLASSEXW;

typedef struct DXGI_RATIONAL {
    UINT Numerator;
    UINT Denominator;
} DXGI_RATIONAL;

typedef struct DXGI_MODE_DESC {
    UINT Width;
    UINT Height;
    DXGI_RATIONAL RefreshRate;
    UINT Format;
    UINT ScanlineOrdering;
    UINT Scaling;
} DXGI_MODE_DESC;

typedef struct DXGI_SAMPLE_DESC {
    UINT Count;
    UINT Quality;
} DXGI_SAMPLE_DESC;

typedef struct DXGI_SWAP_CHAIN_DESC {
    DXGI_MODE_DESC BufferDesc;
    DXGI_SAMPLE_DESC SampleDesc;
    UINT BufferUsage;
    UINT BufferCount;
    UINT Reserved;
    HWND OutputWindow;
    BOOL Windowed;
    UINT SwapEffect;
    UINT Flags;
} DXGI_SWAP_CHAIN_DESC;

typedef struct WAVEFORMATEX {
    WORD wFormatTag;
    WORD nChannels;
    DWORD nSamplesPerSec;
    DWORD nAvgBytesPerSec;
    WORD nBlockAlign;
    WORD wBitsPerSample;
    WORD cbSize;
} WAVEFORMATEX;

typedef struct XAUDIO2_BUFFER {
    UINT Flags;
    UINT AudioBytes;
    const BYTE *pAudioData;
    UINT PlayBegin;
    UINT PlayLength;
    UINT LoopBegin;
    UINT LoopLength;
    UINT LoopCount;
    void *pContext;
} XAUDIO2_BUFFER;

typedef struct ID3D11Device {
    void **lpVtbl;
} ID3D11Device;

typedef struct ID3D11DeviceContext {
    void **lpVtbl;
} ID3D11DeviceContext;

typedef struct ID3D11Texture2D {
    void **lpVtbl;
} ID3D11Texture2D;

typedef struct IDXGISwapChain {
    void **lpVtbl;
} IDXGISwapChain;

typedef struct IXAudio2 {
    void **lpVtbl;
} IXAudio2;

typedef struct IXAudio2MasteringVoice {
    void **lpVtbl;
} IXAudio2MasteringVoice;

typedef struct IXAudio2SourceVoice {
    void **lpVtbl;
} IXAudio2SourceVoice;

__declspec(dllimport) WORD RegisterClassExW(const WNDCLASSEXW *window_class);
__declspec(dllimport) HWND CreateWindowExW(
    DWORD ex_style,
    const WCHAR *class_name,
    const WCHAR *window_name,
    DWORD style,
    int32_t x,
    int32_t y,
    int32_t width,
    int32_t height,
    HWND parent,
    HMENU menu,
    HINSTANCE instance,
    void *param
);
__declspec(dllimport) BOOL PeekMessageW(MSG *message, HWND hwnd, UINT min, UINT max, UINT remove);
__declspec(dllimport) intptr_t DispatchMessageW(const MSG *message);
__declspec(dllimport) intptr_t DefWindowProcW(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
__declspec(dllimport) DWORD GetTickCount(void);
__declspec(dllimport) void Sleep(DWORD milliseconds);
__declspec(dllimport) void ExitProcess(UINT code);
__declspec(dllimport) HANDLE CreateFileW(
    const WCHAR *file_name,
    DWORD desired_access,
    DWORD share_mode,
    void *security_attributes,
    DWORD creation_disposition,
    DWORD flags_and_attributes,
    HANDLE template_file
);
__declspec(dllimport) BOOL ReadFile(
    HANDLE file,
    void *buffer,
    DWORD bytes_to_read,
    DWORD *bytes_read,
    void *overlapped
);
__declspec(dllimport) BOOL WriteFile(
    HANDLE file,
    const void *buffer,
    DWORD bytes_to_write,
    DWORD *bytes_written,
    void *overlapped
);
__declspec(dllimport) BOOL CloseHandle(HANDLE handle);

__declspec(dllimport) HRESULT D3D11CreateDeviceAndSwapChain(
    void *adapter,
    UINT driver_type,
    void *software,
    UINT flags,
    const UINT *feature_levels,
    UINT feature_level_count,
    UINT sdk_version,
    const DXGI_SWAP_CHAIN_DESC *swapchain_desc,
    IDXGISwapChain **swapchain,
    ID3D11Device **device,
    UINT *feature_level,
    ID3D11DeviceContext **context
);

__declspec(dllimport) HRESULT XAudio2Create(IXAudio2 **engine, UINT flags, UINT processor);

typedef struct {
    int kind;
    int rotation;
    int x;
    int y;
} Piece;

typedef enum ScreenState {
    SCREEN_TITLE = 0,
    SCREEN_PLAYING = 1,
    SCREEN_PAUSED = 2,
    SCREEN_GAME_OVER = 3
} ScreenState;

typedef struct ScoreFileData {
    uint32_t magic;
    uint32_t version;
    uint32_t scores[MAX_HIGH_SCORES];
} ScoreFileData;

typedef struct {
    HWND hwnd;
    IDXGISwapChain *swapchain;
    ID3D11Device *device;
    ID3D11DeviceContext *context;
    ID3D11Texture2D *backbuffer;
    IXAudio2 *audio;
    IXAudio2MasteringVoice *mastering;
    IXAudio2SourceVoice *source;
    uint8_t board[BOARD_H][BOARD_W];
    uint8_t bag[7];
    uint8_t input_cooldowns[64];
    Piece current;
    uint8_t next_piece;
    uint8_t running;
    uint8_t score_saved;
    uint8_t bag_index;
    uint8_t left_seen;
    uint8_t right_seen;
    uint8_t down_seen;
    uint8_t horizontal_repeat_armed;
    uint8_t soft_drop_active;
    uint8_t frame_dirty;
    uint8_t hold_used;
    int8_t new_high_score_rank;
    int8_t hold_piece;
    int8_t horizontal_hold_direction;
    ScreenState screen;
    uint32_t frame_counter;
    uint32_t gravity_counter;
    uint32_t last_tick_ms;
    uint32_t gravity_elapsed_ms;
    uint32_t horizontal_hold_ms;
    uint32_t horizontal_repeat_ms;
    uint32_t soft_drop_elapsed_ms;
    uint32_t lines_cleared;
    uint32_t pieces_locked;
    uint32_t score;
    uint32_t level;
    uint32_t rng_state;
    uint32_t high_scores[MAX_HIGH_SCORES];
} AppState;

static AppState g_app;
static uint32_t g_pixels[FRAME_W * FRAME_H];
static int16_t g_lock_wave[LOCK_WAVE_FRAMES * 2];
static int16_t g_clear_wave[CLEAR_WAVE_FRAMES * 2];

static const WCHAR k_score_file_path[] = {
    'c','a','s','a','1','-','t','e','t','r','i','s','.','d','a','t',0
};

#define SCORE_FILE_MAGIC 0x31545443u
#define SCORE_FILE_VERSION 1u

static const GUID IID_ID3D11Texture2D = {
    0x6f15aaf2u,
    0xd208u,
    0x4e89u,
    {0x9a, 0xb4, 0x48, 0x95, 0x35, 0xd3, 0x4f, 0x9c},
};

static const uint16_t k_shapes[7][4] = {
    {0x0f00, 0x2222, 0x00f0, 0x4444},
    {0x0660, 0x0660, 0x0660, 0x0660},
    {0x0e40, 0x4c40, 0x4e00, 0x4640},
    {0x0e80, 0xc440, 0x2e00, 0x4460},
    {0x0e20, 0x44c0, 0x8e00, 0x6440},
    {0x06c0, 0x8c40, 0x06c0, 0x8c40},
    {0x0c60, 0x4c80, 0x0c60, 0x4c80},
};

static const uint32_t k_piece_colors[8] = {
    0xff101820u,
    0xff34d0ffu,
    0xffffd447u,
    0xffb070ffu,
    0xff5f85ffu,
    0xffff7b72u,
    0xff63e38bu,
    0xfff54f6du,
};

static const WCHAR k_class_name[] = {
    'C','a','s','a','1','S','t','a','n','d','a','l','o','n','e','T','e','t','r','i','s',0
};
static const WCHAR k_window_title[] = {
    'C','a','s','a','1',' ','S','t','a','n','d','a','l','o','n','e',' ','T','e','t','r','i','s',0
};

static const uint8_t k_font_letters[26][5] = {
    {7, 5, 7, 5, 5},
    {6, 5, 6, 5, 6},
    {7, 4, 4, 4, 7},
    {6, 5, 5, 5, 6},
    {7, 4, 6, 4, 7},
    {7, 4, 6, 4, 4},
    {7, 4, 5, 5, 7},
    {5, 5, 7, 5, 5},
    {7, 2, 2, 2, 7},
    {1, 1, 1, 5, 7},
    {5, 5, 6, 5, 5},
    {4, 4, 4, 4, 7},
    {5, 7, 7, 5, 5},
    {5, 7, 7, 7, 5},
    {7, 5, 5, 5, 7},
    {7, 5, 7, 4, 4},
    {7, 5, 5, 7, 1},
    {7, 5, 7, 6, 5},
    {7, 4, 7, 1, 7},
    {7, 2, 2, 2, 2},
    {5, 5, 5, 5, 7},
    {5, 5, 5, 5, 2},
    {5, 5, 7, 7, 5},
    {5, 5, 2, 5, 5},
    {5, 5, 2, 2, 2},
    {7, 1, 2, 4, 7}
};

static const uint8_t k_font_digits[10][5] = {
    {7, 5, 5, 5, 7},
    {2, 6, 2, 2, 7},
    {7, 1, 7, 4, 7},
    {7, 1, 7, 1, 7},
    {5, 5, 7, 1, 1},
    {7, 4, 7, 1, 7},
    {7, 4, 7, 5, 7},
    {7, 1, 2, 2, 2},
    {7, 5, 7, 5, 7},
    {7, 5, 7, 1, 7}
};

static int failed(HRESULT hr) {
    return hr < 0;
}

static void zero_bytes(void *ptr, size_t len) {
    uint8_t *bytes = (uint8_t *)ptr;
    size_t index;
    for (index = 0; index < len; ++index) {
        bytes[index] = 0;
    }
}

static uint32_t color_rgb(uint8_t red, uint8_t green, uint8_t blue) {
    return 0xff000000u | ((uint32_t)red << 16) | ((uint32_t)green << 8) | (uint32_t)blue;
}

static void mark_frame_dirty(void) {
    g_app.frame_dirty = 1u;
}

static uint32_t com_release(void *object) {
    typedef uint32_t (*ReleaseFn)(void *);
    void **vtable = *(void ***)object;
    ReleaseFn release = (ReleaseFn)vtable[2];
    return release(object);
}

static void d3d11_get_immediate_context(ID3D11Device *device, ID3D11DeviceContext **context) {
    typedef void (*Fn)(ID3D11Device *, ID3D11DeviceContext **);
    Fn fn = (Fn)device->lpVtbl[40];
    fn(device, context);
}

static void d3d11_update_subresource(
    ID3D11DeviceContext *context,
    ID3D11Texture2D *texture,
    const void *src_data,
    UINT row_pitch
) {
    typedef void (*Fn)(ID3D11DeviceContext *, ID3D11Texture2D *, UINT, const void *, const void *, UINT, UINT);
    Fn fn = (Fn)context->lpVtbl[48];
    fn(context, texture, 0, 0, src_data, row_pitch, 0);
}

static HRESULT dxgi_get_buffer(IDXGISwapChain *swapchain, UINT index, REFIID riid, void **surface) {
    typedef HRESULT (*Fn)(IDXGISwapChain *, UINT, REFIID, void **);
    Fn fn = (Fn)swapchain->lpVtbl[9];
    return fn(swapchain, index, riid, surface);
}

static HRESULT dxgi_present(IDXGISwapChain *swapchain, UINT sync_interval, UINT flags) {
    typedef HRESULT (*Fn)(IDXGISwapChain *, UINT, UINT);
    Fn fn = (Fn)swapchain->lpVtbl[8];
    return fn(swapchain, sync_interval, flags);
}

static HRESULT xaudio_create_source_voice(
    IXAudio2 *engine,
    IXAudio2SourceVoice **voice,
    const WAVEFORMATEX *format,
    UINT flags,
    float max_frequency_ratio
) {
    typedef HRESULT (*Fn)(IXAudio2 *, IXAudio2SourceVoice **, const WAVEFORMATEX *, UINT, float, void *, void *, void *);
    Fn fn = (Fn)engine->lpVtbl[5];
    return fn(engine, voice, format, flags, max_frequency_ratio, 0, 0, 0);
}

static HRESULT xaudio_create_mastering_voice(
    IXAudio2 *engine,
    IXAudio2MasteringVoice **voice,
    UINT channels,
    UINT sample_rate,
    UINT flags,
    UINT stream_category
) {
    typedef HRESULT (*Fn)(IXAudio2 *, IXAudio2MasteringVoice **, UINT, UINT, UINT, const WCHAR *, void *, UINT);
    Fn fn = (Fn)engine->lpVtbl[7];
    return fn(engine, voice, channels, sample_rate, flags, 0, 0, stream_category);
}

static void xaudio_start_engine(IXAudio2 *engine) {
    typedef HRESULT (*Fn)(IXAudio2 *);
    Fn fn = (Fn)engine->lpVtbl[8];
    fn(engine);
}

static void xaudio_voice_destroy(void *voice) {
    typedef void (*Fn)(void *);
    void **vtable = *(void ***)voice;
    Fn fn = (Fn)vtable[18];
    fn(voice);
}

static void xaudio_source_start(IXAudio2SourceVoice *voice) {
    typedef HRESULT (*Fn)(IXAudio2SourceVoice *, UINT, UINT);
    Fn fn = (Fn)voice->lpVtbl[19];
    fn(voice, 0, 0);
}

static void xaudio_source_stop(IXAudio2SourceVoice *voice) {
    typedef HRESULT (*Fn)(IXAudio2SourceVoice *, UINT, UINT);
    Fn fn = (Fn)voice->lpVtbl[20];
    fn(voice, 0, 0);
}

static void xaudio_source_submit(IXAudio2SourceVoice *voice, const XAUDIO2_BUFFER *buffer) {
    typedef HRESULT (*Fn)(IXAudio2SourceVoice *, const XAUDIO2_BUFFER *, const void *);
    Fn fn = (Fn)voice->lpVtbl[21];
    fn(voice, buffer, 0);
}

static void xaudio_source_flush(IXAudio2SourceVoice *voice) {
    typedef HRESULT (*Fn)(IXAudio2SourceVoice *);
    Fn fn = (Fn)voice->lpVtbl[22];
    fn(voice);
}

static int piece_cell(int kind, int rotation, int x, int y) {
    uint16_t bits = k_shapes[kind][rotation & 3];
    return (bits >> (y * 4 + x)) & 1;
}

static int can_place_piece(int kind, int rotation, int origin_x, int origin_y) {
    int py;
    int px;
    for (py = 0; py < 4; ++py) {
        for (px = 0; px < 4; ++px) {
            int board_x;
            int board_y;
            if (!piece_cell(kind, rotation, px, py)) {
                continue;
            }
            board_x = origin_x + px;
            board_y = origin_y + py;
            if (board_x < 0 || board_x >= BOARD_W || board_y < 0 || board_y >= BOARD_H) {
                return 0;
            }
            if (g_app.board[board_y][board_x] != 0u) {
                return 0;
            }
        }
    }
    return 1;
}

static void fill_audio_buffers(void) {
    uint32_t index;
    for (index = 0; index < LOCK_WAVE_FRAMES; ++index) {
        int phase = (int)(index & 31u);
        int16_t sample = (phase < 16) ? 12000 : -12000;
        g_lock_wave[index * 2] = sample;
        g_lock_wave[index * 2 + 1] = sample;
    }
    for (index = 0; index < CLEAR_WAVE_FRAMES; ++index) {
        int band = (int)((index >> 5) & 7u);
        int16_t sample = (band < 4) ? (int16_t)(14000 - band * 2000) : (int16_t)(-14000 + (band - 4) * 2000);
        g_clear_wave[index * 2] = sample;
        g_clear_wave[index * 2 + 1] = sample;
    }
}

static void play_wave(const int16_t *samples, uint32_t sample_bytes) {
    XAUDIO2_BUFFER buffer;
    if (g_app.source == 0) {
        return;
    }
    zero_bytes(&buffer, sizeof(buffer));
    xaudio_source_stop(g_app.source);
    xaudio_source_flush(g_app.source);
    buffer.AudioBytes = sample_bytes;
    buffer.pAudioData = (const BYTE *)samples;
    xaudio_source_submit(g_app.source, &buffer);
    xaudio_source_start(g_app.source);
}

static void play_lock_sound(void) {
    play_wave(g_lock_wave, sizeof(g_lock_wave));
}

static void play_clear_sound(void) {
    play_wave(g_clear_wave, sizeof(g_clear_wave));
}

static HANDLE invalid_handle_value(void) {
    return (HANDLE)(intptr_t)-1;
}

static uint32_t next_random_u32(void) {
    uint32_t value = g_app.rng_state;
    if (value == 0u) {
        value = 0x13579bdfu;
    }
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    g_app.rng_state = value;
    return value;
}

static void refill_bag(void) {
    uint8_t index;
    for (index = 0; index < 7u; ++index) {
        g_app.bag[index] = index;
    }
    for (index = 6u; index > 0u; --index) {
        uint8_t other = (uint8_t)(next_random_u32() % (uint32_t)(index + 1u));
        uint8_t temp = g_app.bag[index];
        g_app.bag[index] = g_app.bag[other];
        g_app.bag[other] = temp;
    }
    g_app.bag_index = 0u;
}

static uint8_t next_piece_kind(void) {
    if (g_app.bag_index >= 7u) {
        refill_bag();
    }
    return g_app.bag[g_app.bag_index++];
}

static uint32_t current_level(void) {
    return (g_app.level == 0u) ? 1u : g_app.level;
}

static uint32_t gravity_ms_for_level(void) {
    static const uint16_t k_gravity_ms[] = {
        0u,
        800u,
        716u,
        633u,
        550u,
        466u,
        383u,
        300u,
        216u,
        133u,
        100u,
        83u,
        83u,
        83u,
        66u,
        66u,
        50u,
        50u,
        33u,
        33u,
        16u
    };
    uint32_t level = current_level();
    if (level < (uint32_t)(sizeof(k_gravity_ms) / sizeof(k_gravity_ms[0]))) {
        return k_gravity_ms[level];
    }
    return 16u;
}

static uint32_t line_clear_score(uint32_t cleared) {
    uint32_t level = current_level();
    switch (cleared) {
    case 1:
        return 100u * level;
    case 2:
        return 300u * level;
    case 3:
        return 500u * level;
    case 4:
        return 800u * level;
    default:
        return 0u;
    }
}

static const uint8_t *glyph_rows(char ch) {
    static const uint8_t colon_rows[5] = {0, 2, 0, 2, 0};
    static const uint8_t dash_rows[5] = {0, 0, 7, 0, 0};
    if (ch >= 'a' && ch <= 'z') {
        ch = (char)(ch - 'a' + 'A');
    }
    if (ch >= 'A' && ch <= 'Z') {
        return k_font_letters[ch - 'A'];
    }
    if (ch >= '0' && ch <= '9') {
        return k_font_digits[ch - '0'];
    }
    switch (ch) {
    case ':':
        return colon_rows;
    case '-':
        return dash_rows;
    default:
        return 0;
    }
}

static int text_width(const char *text, int scale) {
    int width = 0;
    while (*text != 0) {
        width += 4 * scale;
        text += 1;
    }
    if (width != 0) {
        width -= scale;
    }
    return width;
}

static void put_pixel(int x, int y, uint32_t color) {
    if (x < 0 || y < 0 || x >= FRAME_W || y >= FRAME_H) {
        return;
    }
    g_pixels[y * FRAME_W + x] = color;
}

static void fill_rect(int x, int y, int width, int height, uint32_t color) {
    int py;
    int px;
    for (py = 0; py < height; ++py) {
        int px;
        for (px = 0; px < width; ++px) {
            put_pixel(x + px, y + py, color);
        }
    }
}

static void draw_glyph(int x, int y, char ch, int scale, uint32_t color) {
    const uint8_t *rows = glyph_rows(ch);
    int row;
    if (rows == 0) {
        return;
    }
    for (row = 0; row < 5; ++row) {
        int col;
        for (col = 0; col < 3; ++col) {
            if (rows[row] & (1u << (2 - col))) {
                fill_rect(x + col * scale, y + row * scale, scale, scale, color);
            }
        }
    }
}

static void draw_text(int x, int y, const char *text, int scale, uint32_t color) {
    while (*text != 0) {
        if (*text != ' ') {
            draw_glyph(x, y, *text, scale, color);
        }
        x += 4 * scale;
        text += 1;
    }
}

static void draw_centered_text(int center_x, int y, const char *text, int scale, uint32_t color) {
    draw_text(center_x - text_width(text, scale) / 2, y, text, scale, color);
}

static void u32_to_ascii(uint32_t value, char *buffer) {
    char reverse[11];
    int index = 0;
    if (value == 0u) {
        buffer[0] = '0';
        buffer[1] = 0;
        return;
    }
    while (value != 0u) {
        reverse[index++] = (char)('0' + (value % 10u));
        value /= 10u;
    }
    while (index > 0) {
        *buffer++ = reverse[--index];
    }
    *buffer = 0;
}

static void draw_u32(int x, int y, uint32_t value, uint32_t color) {
    char buffer[12];
    u32_to_ascii(value, buffer);
    draw_text(x, y, buffer, 1, color);
}

static void draw_centered_u32(int center_x, int y, uint32_t value, uint32_t color) {
    char buffer[12];
    u32_to_ascii(value, buffer);
    draw_centered_text(center_x, y, buffer, 1, color);
}

static void write_score_file(void) {
    ScoreFileData data;
    DWORD written = 0;
    HANDLE file;
    uint32_t index;

    zero_bytes(&data, sizeof(data));
    data.magic = SCORE_FILE_MAGIC;
    data.version = SCORE_FILE_VERSION;
    for (index = 0; index < MAX_HIGH_SCORES; ++index) {
        data.scores[index] = g_app.high_scores[index];
    }

    file = CreateFileW(
        k_score_file_path,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        0,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        0
    );
    if (file == invalid_handle_value()) {
        return;
    }
    WriteFile(file, &data, (DWORD)sizeof(data), &written, 0);
    CloseHandle(file);
}

static void load_high_scores(void) {
    ScoreFileData data;
    DWORD bytes_read = 0;
    HANDLE file;
    uint32_t index;

    for (index = 0; index < MAX_HIGH_SCORES; ++index) {
        g_app.high_scores[index] = 0u;
    }

    zero_bytes(&data, sizeof(data));
    file = CreateFileW(
        k_score_file_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0
    );
    if (file == invalid_handle_value()) {
        return;
    }
    if (ReadFile(file, &data, (DWORD)sizeof(data), &bytes_read, 0)
        && bytes_read == sizeof(data)
        && data.magic == SCORE_FILE_MAGIC
        && data.version == SCORE_FILE_VERSION) {
        for (index = 0; index < MAX_HIGH_SCORES; ++index) {
            g_app.high_scores[index] = data.scores[index];
        }
    }
    CloseHandle(file);
}

static int maybe_record_high_score(uint32_t score) {
    int index;
    if (score == 0u) {
        return -1;
    }
    for (index = 0; index < (int)MAX_HIGH_SCORES; ++index) {
        if (score >= g_app.high_scores[index]) {
            int shift;
            for (shift = (int)MAX_HIGH_SCORES - 1; shift > index; --shift) {
                g_app.high_scores[shift] = g_app.high_scores[shift - 1];
            }
            g_app.high_scores[index] = score;
            write_score_file();
            return index;
        }
    }
    return -1;
}

static void finish_game(void) {
    if (!g_app.score_saved) {
        g_app.new_high_score_rank = (int8_t)maybe_record_high_score(g_app.score);
        g_app.score_saved = 1u;
    }
    g_app.screen = SCREEN_GAME_OVER;
    g_app.left_seen = 0u;
    g_app.right_seen = 0u;
    g_app.down_seen = 0u;
    g_app.horizontal_repeat_armed = 0u;
    g_app.soft_drop_active = 0u;
    g_app.horizontal_hold_direction = 0;
    g_app.horizontal_hold_ms = 0u;
    g_app.horizontal_repeat_ms = 0u;
    g_app.soft_drop_elapsed_ms = 0u;
    mark_frame_dirty();
}

static void update_level_from_lines(void) {
    g_app.level = 1u + g_app.lines_cleared / 10u;
}

static void activate_piece(int kind) {
    g_app.current.kind = kind;
    g_app.current.rotation = 0;
    g_app.current.x = 3;
    g_app.current.y = 0;
    g_app.gravity_elapsed_ms = 0u;
    g_app.horizontal_repeat_armed = 0u;
    g_app.horizontal_hold_direction = 0;
    g_app.horizontal_hold_ms = 0u;
    g_app.horizontal_repeat_ms = 0u;
    g_app.soft_drop_active = 0u;
    g_app.soft_drop_elapsed_ms = 0u;
    if (!can_place_piece(g_app.current.kind, g_app.current.rotation, g_app.current.x, g_app.current.y)) {
        finish_game();
        return;
    }
    mark_frame_dirty();
}

static void spawn_piece(void) {
    int next_kind = g_app.next_piece;
    g_app.next_piece = next_piece_kind();
    g_app.hold_used = 0u;
    activate_piece(next_kind);
}

static uint32_t clear_complete_lines(void) {
    int row;
    uint32_t cleared = 0u;
    for (row = BOARD_H - 1; row >= 0; --row) {
        int col;
        int full = 1;
        for (col = 0; col < BOARD_W; ++col) {
            if (g_app.board[row][col] == 0u) {
                full = 0;
                break;
            }
        }
        if (!full) {
            continue;
        }
        cleared += 1u;
        for (; row > 0; --row) {
            for (col = 0; col < BOARD_W; ++col) {
                g_app.board[row][col] = g_app.board[row - 1][col];
            }
        }
        for (col = 0; col < BOARD_W; ++col) {
            g_app.board[0][col] = 0u;
        }
        row += 1;
    }
    g_app.lines_cleared += cleared;
    if (cleared != 0u) {
        update_level_from_lines();
    }
    return cleared;
}

static void lock_piece(void) {
    int py;
    int px;
    uint32_t cleared;
    for (py = 0; py < 4; ++py) {
        for (px = 0; px < 4; ++px) {
            int board_x;
            int board_y;
            if (!piece_cell(g_app.current.kind, g_app.current.rotation, px, py)) {
                continue;
            }
            board_x = g_app.current.x + px;
            board_y = g_app.current.y + py;
            if (board_x >= 0 && board_x < BOARD_W && board_y >= 0 && board_y < BOARD_H) {
                g_app.board[board_y][board_x] = (uint8_t)(g_app.current.kind + 1);
            }
        }
    }
    g_app.pieces_locked += 1u;
    cleared = clear_complete_lines();
    if (cleared != 0u) {
        g_app.score += line_clear_score(cleared);
        play_clear_sound();
    } else {
        play_lock_sound();
    }
    if (MAX_LOCKS != 0 && g_app.pieces_locked >= MAX_LOCKS) {
        finish_game();
        return;
    }
    spawn_piece();
    mark_frame_dirty();
}

static int try_move_current_piece(int dx, int dy) {
    int next_x = g_app.current.x + dx;
    int next_y = g_app.current.y + dy;
    if (can_place_piece(g_app.current.kind, g_app.current.rotation, next_x, next_y)) {
        g_app.current.x = next_x;
        g_app.current.y = next_y;
        mark_frame_dirty();
        return 1;
    }
    return 0;
}

static void soft_drop_current_piece(void) {
    if (try_move_current_piece(0, 1)) {
        g_app.score += 1u;
        mark_frame_dirty();
    } else {
        lock_piece();
    }
}

static void rotate_current_piece(int delta) {
    int next_rotation = (g_app.current.rotation + delta) & 3;
    if (can_place_piece(g_app.current.kind, next_rotation, g_app.current.x, g_app.current.y)) {
        g_app.current.rotation = next_rotation;
        mark_frame_dirty();
        return;
    }
    if (can_place_piece(g_app.current.kind, next_rotation, g_app.current.x - 1, g_app.current.y)) {
        g_app.current.x -= 1;
        g_app.current.rotation = next_rotation;
        mark_frame_dirty();
        return;
    }
    if (can_place_piece(g_app.current.kind, next_rotation, g_app.current.x + 1, g_app.current.y)) {
        g_app.current.x += 1;
        g_app.current.rotation = next_rotation;
        mark_frame_dirty();
    }
}

static void hard_drop_current_piece(void) {
    uint32_t steps = 0u;
    while (try_move_current_piece(0, 1)) {
        steps += 1u;
    }
    g_app.score += steps * 2u;
    lock_piece();
}

static void hold_current_piece(void) {
    int swap_kind;

    if (g_app.hold_used || g_app.screen != SCREEN_PLAYING) {
        return;
    }

    swap_kind = g_app.current.kind;
    g_app.hold_used = 1u;
    if (g_app.hold_piece < 0) {
        g_app.hold_piece = (int8_t)swap_kind;
        spawn_piece();
        g_app.hold_used = 1u;
        mark_frame_dirty();
        return;
    }

    g_app.current.kind = g_app.hold_piece;
    g_app.hold_piece = (int8_t)swap_kind;
    activate_piece(g_app.current.kind);
    mark_frame_dirty();
}

static void start_new_game(void) {
    zero_bytes(g_app.board, sizeof(g_app.board));
    zero_bytes(g_app.input_cooldowns, sizeof(g_app.input_cooldowns));
    g_app.screen = SCREEN_PLAYING;
    g_app.score_saved = 0u;
    g_app.new_high_score_rank = -1;
    g_app.score = 0u;
    g_app.lines_cleared = 0u;
    g_app.level = 1u;
    g_app.pieces_locked = 0u;
    g_app.gravity_counter = 0u;
    g_app.gravity_elapsed_ms = 0u;
    g_app.frame_counter = 0u;
    g_app.last_tick_ms = GetTickCount();
    g_app.left_seen = 0u;
    g_app.right_seen = 0u;
    g_app.down_seen = 0u;
    g_app.horizontal_repeat_armed = 0u;
    g_app.soft_drop_active = 0u;
    g_app.hold_used = 0u;
    g_app.hold_piece = -1;
    g_app.horizontal_hold_direction = 0;
    g_app.horizontal_hold_ms = 0u;
    g_app.horizontal_repeat_ms = 0u;
    g_app.soft_drop_elapsed_ms = 0u;
    g_app.bag_index = 7u;
    g_app.next_piece = next_piece_kind();
    spawn_piece();
    play_lock_sound();
    mark_frame_dirty();
}

static uint32_t poll_elapsed_ms(void) {
    uint32_t now = GetTickCount();
    uint32_t elapsed = now - g_app.last_tick_ms;
    g_app.last_tick_ms = now;
    if (elapsed == 0u) {
        return 1u;
    }
    if (elapsed > 250u) {
        return 250u;
    }
    return elapsed;
}

static void reset_live_input_state(void) {
    g_app.left_seen = 0u;
    g_app.right_seen = 0u;
    g_app.down_seen = 0u;
    g_app.horizontal_repeat_armed = 0u;
    g_app.soft_drop_active = 0u;
    g_app.horizontal_hold_direction = 0;
    g_app.horizontal_hold_ms = 0u;
    g_app.horizontal_repeat_ms = 0u;
    g_app.soft_drop_elapsed_ms = 0u;
}

static void tick_input_cooldowns(void) {
    uint32_t index;
    for (index = 0; index < (uint32_t)sizeof(g_app.input_cooldowns); ++index) {
        if (g_app.input_cooldowns[index] != 0u) {
            g_app.input_cooldowns[index] -= 1u;
        }
    }
}

static int consume_one_shot(uint16_t scancode) {
    uint8_t *cooldown = &g_app.input_cooldowns[scancode & 63u];
    switch (scancode) {
    case 0x10:
    case 0x11:
    case 0x13:
    case 0x19:
    case 0x1c:
    case 0x2e:
    case 0x31:
    case 0x39:
        if (*cooldown != 0u) {
            return 0;
        }
        *cooldown = 6u;
        return 1;
    default:
        return 1;
    }
}

static void handle_scancode(uint16_t scancode) {
    if (!consume_one_shot(scancode)) {
        return;
    }

    if (scancode == 0x01) {
        g_app.running = 0u;
        return;
    }

    if (scancode == 0x13 || scancode == 0x31) {
        start_new_game();
        return;
    }

    if (scancode == 0x1c) {
        if (g_app.screen == SCREEN_TITLE || g_app.screen == SCREEN_GAME_OVER) {
            start_new_game();
        } else if (g_app.screen == SCREEN_PAUSED) {
            g_app.screen = SCREEN_PLAYING;
            mark_frame_dirty();
        }
        return;
    }

    if (scancode == 0x19) {
        if (g_app.screen == SCREEN_PLAYING) {
            g_app.screen = SCREEN_PAUSED;
            reset_live_input_state();
            mark_frame_dirty();
        } else if (g_app.screen == SCREEN_PAUSED) {
            g_app.screen = SCREEN_PLAYING;
            mark_frame_dirty();
        }
        return;
    }

    if (g_app.screen == SCREEN_TITLE || g_app.screen == SCREEN_GAME_OVER) {
        if (scancode == 0x39) {
            start_new_game();
        }
        return;
    }

    if (g_app.screen != SCREEN_PLAYING) {
        return;
    }

    switch (scancode) {
    case 0x1e:
        try_move_current_piece(-1, 0);
        break;
    case 0x20:
        try_move_current_piece(1, 0);
        break;
    case 0x1f:
        soft_drop_current_piece();
        break;
    case 0x11:
        rotate_current_piece(1);
        break;
    case 0x10:
        rotate_current_piece(-1);
        break;
    case 0x2e:
        hold_current_piece();
        break;
    case 0x39:
        hard_drop_current_piece();
        break;
    default:
        break;
    }
}

static int current_ghost_y(void) {
    int ghost_y = g_app.current.y;
    while (can_place_piece(g_app.current.kind, g_app.current.rotation, g_app.current.x, ghost_y + 1)) {
        ghost_y += 1;
    }
    return ghost_y;
}

static void update_horizontal_input(uint32_t elapsed_ms) {
    int direction = 0;

    if (g_app.left_seen && !g_app.right_seen) {
        direction = -1;
    } else if (g_app.right_seen && !g_app.left_seen) {
        direction = 1;
    }

    if (direction == 0) {
        g_app.horizontal_repeat_armed = 0u;
        g_app.horizontal_hold_direction = 0;
        g_app.horizontal_hold_ms = 0u;
        g_app.horizontal_repeat_ms = 0u;
        return;
    }

    if (g_app.horizontal_hold_direction != direction) {
        g_app.horizontal_hold_direction = (int8_t)direction;
        g_app.horizontal_repeat_armed = 0u;
        g_app.horizontal_hold_ms = 0u;
        g_app.horizontal_repeat_ms = 0u;
        try_move_current_piece(direction, 0);
        return;
    }

    if (!g_app.horizontal_repeat_armed) {
        g_app.horizontal_hold_ms += elapsed_ms;
        if (g_app.horizontal_hold_ms >= HORIZONTAL_DAS_MS) {
            g_app.horizontal_repeat_armed = 1u;
            g_app.horizontal_repeat_ms = 0u;
            try_move_current_piece(direction, 0);
        }
        return;
    }

    g_app.horizontal_repeat_ms += elapsed_ms;
    if (g_app.horizontal_repeat_ms >= HORIZONTAL_ARR_MS) {
        g_app.horizontal_repeat_ms = 0u;
        try_move_current_piece(direction, 0);
    }
}

static void update_soft_drop_input(uint32_t elapsed_ms) {
    uint32_t steps = 0u;

    if (!g_app.down_seen) {
        g_app.soft_drop_active = 0u;
        g_app.soft_drop_elapsed_ms = 0u;
        return;
    }

    if (!g_app.soft_drop_active) {
        g_app.soft_drop_active = 1u;
        g_app.soft_drop_elapsed_ms = 0u;
        soft_drop_current_piece();
        return;
    }

    g_app.soft_drop_elapsed_ms += elapsed_ms;
    while (g_app.soft_drop_elapsed_ms >= SOFT_DROP_STEP_MS && steps < 6u && g_app.screen == SCREEN_PLAYING) {
        g_app.soft_drop_elapsed_ms -= SOFT_DROP_STEP_MS;
        soft_drop_current_piece();
        steps += 1u;
    }
}

static void draw_well(void) {
    int col;
    int row;
    fill_rect(BOARD_X - 2, BOARD_Y - 2, BOARD_W * CELL + 4, BOARD_H * CELL + 4, color_rgb(48, 58, 74));
    fill_rect(BOARD_X, BOARD_Y, BOARD_W * CELL, BOARD_H * CELL, color_rgb(16, 22, 32));
    for (col = 1; col < BOARD_W; ++col) {
        fill_rect(BOARD_X + col * CELL, BOARD_Y, 1, BOARD_H * CELL, color_rgb(24, 31, 44));
    }
    for (row = 1; row < BOARD_H; ++row) {
        fill_rect(BOARD_X, BOARD_Y + row * CELL, BOARD_W * CELL, 1, color_rgb(24, 31, 44));
    }
}

static void draw_piece_at(int kind, int rotation, int cell_x, int cell_y, uint32_t color) {
    int py;
    int px;
    for (py = 0; py < 4; ++py) {
        for (px = 0; px < 4; ++px) {
            if (!piece_cell(kind, rotation, px, py)) {
                continue;
            }
            fill_rect(
                BOARD_X + (cell_x + px) * CELL,
                BOARD_Y + (cell_y + py) * CELL,
                CELL - 1,
                CELL - 1,
                color
            );
        }
    }
}

static void draw_board_cells(void) {
    int row;
    int col;
    for (row = 0; row < BOARD_H; ++row) {
        for (col = 0; col < BOARD_W; ++col) {
            uint8_t value = g_app.board[row][col];
            if (value != 0u) {
                fill_rect(
                    BOARD_X + col * CELL,
                    BOARD_Y + row * CELL,
                    CELL - 1,
                    CELL - 1,
                    k_piece_colors[value]
                );
            }
        }
    }
}

static void draw_current_piece(void) {
    if (g_app.screen == SCREEN_TITLE) {
        return;
    }
    draw_piece_at(
        g_app.current.kind,
        g_app.current.rotation,
        g_app.current.x,
        g_app.current.y,
        k_piece_colors[g_app.current.kind + 1]
    );
}

static void draw_ghost_piece(void) {
    if (g_app.screen != SCREEN_PLAYING) {
        return;
    }
    draw_piece_at(
        g_app.current.kind,
        g_app.current.rotation,
        g_app.current.x,
        current_ghost_y(),
        color_rgb(74, 88, 112)
    );
}

static void draw_panel_shell(void) {
    fill_rect(PANEL_X - 1, PANEL_Y - 1, PANEL_W + 2, PANEL_H + 2, color_rgb(48, 58, 74));
    fill_rect(PANEL_X, PANEL_Y, PANEL_W, PANEL_H, color_rgb(20, 26, 38));
}

static void draw_preview_box(int x, int y, const char *label, int kind) {
    int py;
    int px;

    draw_text(x, PANEL_Y + 4, label, 1, color_rgb(220, 231, 244));
    fill_rect(x - 2, y - 2, 20, 20, color_rgb(12, 16, 24));
    if (kind < 0) {
        return;
    }
    for (py = 0; py < 4; ++py) {
        for (px = 0; px < 4; ++px) {
            if (!piece_cell(kind, 0, px, py)) {
                continue;
            }
            fill_rect(x + px * 4, y + py * 4, 4, 4, k_piece_colors[kind + 1]);
        }
    }
}

static void draw_preview_piece(void) {
    draw_preview_box(PANEL_X + 2, PANEL_Y + 16, "HOLD", g_app.hold_piece);
    draw_preview_box(PANEL_X + 24, PANEL_Y + 16, "NEXT", g_app.next_piece);
}

static void draw_stats_panel(void) {
    draw_text(PANEL_X + 6, PANEL_Y + 44, "SCORE", 1, color_rgb(180, 194, 210));
    draw_u32(PANEL_X + 6, PANEL_Y + 52, g_app.score, color_rgb(244, 208, 84));
    draw_text(PANEL_X + 6, PANEL_Y + 62, "LINES", 1, color_rgb(180, 194, 210));
    draw_u32(PANEL_X + 6, PANEL_Y + 70, g_app.lines_cleared, color_rgb(99, 227, 139));
    draw_text(PANEL_X + 6, PANEL_Y + 80, "LEVEL", 1, color_rgb(180, 194, 210));
    draw_u32(PANEL_X + 6, PANEL_Y + 88, current_level(), color_rgb(176, 112, 255));
}

static void draw_high_score_table(int x, int y) {
    int index;
    char rank[3];
    for (index = 0; index < (int)MAX_HIGH_SCORES; ++index) {
        rank[0] = (char)('1' + index);
        rank[1] = ':';
        rank[2] = 0;
        draw_text(x, y + index * 10, rank, 1, color_rgb(180, 194, 210));
        draw_u32(x + 12, y + index * 10, g_app.high_scores[index], color_rgb(244, 208, 84));
    }
}

static void draw_playing_help(void) {
    draw_text(PANEL_X + 6, PANEL_Y + 98, "MOVE A D", 1, color_rgb(220, 231, 244));
    draw_text(PANEL_X + 6, PANEL_Y + 106, "DROP S SPC", 1, color_rgb(220, 231, 244));
    draw_text(PANEL_X + 6, PANEL_Y + 114, "TURN W Q", 1, color_rgb(220, 231, 244));
    draw_text(PANEL_X + 6, PANEL_Y + 122, "C HOLD P EN", 1, color_rgb(180, 194, 210));
}

static void draw_score_help(void) {
    draw_text(PANEL_X + 6, PANEL_Y + 6, "TOP5", 1, color_rgb(220, 231, 244));
    draw_high_score_table(PANEL_X + 6, PANEL_Y + 20);
}

static void draw_title_overlay(void) {
    fill_rect(BOARD_X - 2, 24, BOARD_W * CELL + 4, 54, color_rgb(24, 34, 48));
    draw_centered_text(BOARD_CENTER_X, 30, "TETRIS", 2, color_rgb(244, 208, 84));
    draw_centered_text(BOARD_CENTER_X, 58, "ENTER", 1, color_rgb(220, 231, 244));
    draw_centered_text(BOARD_CENTER_X, 66, "OR SPACE", 1, color_rgb(180, 194, 210));
    draw_centered_text(BOARD_CENTER_X, 74, "TO START", 1, color_rgb(220, 231, 244));
}

static void draw_pause_overlay(void) {
    fill_rect(BOARD_X - 2, 50, BOARD_W * CELL + 4, 24, color_rgb(22, 26, 40));
    draw_centered_text(BOARD_CENTER_X, 56, "PAUSED", 1, color_rgb(220, 231, 244));
    draw_centered_text(BOARD_CENTER_X, 64, "P OR EN", 1, color_rgb(180, 194, 210));
}

static void draw_game_over_overlay(void) {
    fill_rect(BOARD_X - 2, 24, BOARD_W * CELL + 4, 58, color_rgb(56, 20, 34));
    draw_centered_text(BOARD_CENTER_X, 30, "GAME", 2, color_rgb(255, 214, 214));
    draw_centered_text(BOARD_CENTER_X, 50, "OVER", 2, color_rgb(255, 214, 214));
    draw_centered_text(BOARD_CENTER_X, 70, "SCORE", 1, color_rgb(220, 231, 244));
    draw_centered_u32(BOARD_CENTER_X, 78, g_app.score, color_rgb(244, 208, 84));
    if (g_app.new_high_score_rank >= 0) {
        draw_centered_text(BOARD_CENTER_X, 88, "TOP5", 1, color_rgb(99, 227, 139));
    }
}

static void render_frame(void) {
    uint32_t index;
    for (index = 0; index < FRAME_W * FRAME_H; ++index) {
        g_pixels[index] = color_rgb(8, 12, 18);
    }

    draw_well();
    draw_panel_shell();
    draw_board_cells();
    draw_ghost_piece();
    draw_current_piece();

    if (g_app.screen == SCREEN_TITLE) {
        draw_title_overlay();
        draw_score_help();
    } else {
        if (g_app.screen == SCREEN_GAME_OVER) {
            draw_game_over_overlay();
            draw_score_help();
        } else {
            draw_preview_piece();
            draw_stats_panel();
            draw_playing_help();
            if (g_app.screen == SCREEN_PAUSED) {
                draw_pause_overlay();
            }
        }
    }
}

static void update_game(void) {
    uint32_t elapsed_ms = 0u;

    g_app.frame_counter += 1u;
    tick_input_cooldowns();
    if (!g_app.running) {
        return;
    }
    if (g_app.screen == SCREEN_PLAYING) {
        uint32_t steps = 0u;

        elapsed_ms = poll_elapsed_ms();

        update_horizontal_input(elapsed_ms);
        update_soft_drop_input(elapsed_ms);

        g_app.gravity_elapsed_ms += elapsed_ms;
        while (g_app.gravity_elapsed_ms >= gravity_ms_for_level() && steps < 4u && g_app.screen == SCREEN_PLAYING) {
            g_app.gravity_elapsed_ms -= gravity_ms_for_level();
            if (!try_move_current_piece(0, 1)) {
                g_app.gravity_elapsed_ms = 0u;
                lock_piece();
                break;
            }
            steps += 1u;
        }
    } else {
        g_app.last_tick_ms = GetTickCount();
        reset_live_input_state();
    }
    if (MAX_FRAMES != 0 && g_app.frame_counter >= MAX_FRAMES) {
        g_app.running = 0u;
    }
}

static void process_messages(void) {
    MSG message;

    while (PeekMessageW(&message, 0, 0, 0, PM_REMOVE)) {
        if (message.message == WM_KEYDOWN) {
            uint16_t scancode = (uint16_t)(message.lParam & 0xffffu);
            switch (scancode) {
            case 0x1e:
                g_app.left_seen = 1u;
                break;
            case 0x20:
                g_app.right_seen = 1u;
                break;
            case 0x1f:
                g_app.down_seen = 1u;
                break;
            default:
                handle_scancode(scancode);
                break;
            }
        } else if (message.message == WM_KEYUP) {
            uint16_t scancode = (uint16_t)(message.lParam & 0xffffu);
            switch (scancode) {
            case 0x1e:
                g_app.left_seen = 0u;
                break;
            case 0x20:
                g_app.right_seen = 0u;
                break;
            case 0x1f:
                g_app.down_seen = 0u;
                break;
            default:
                break;
            }
        } else if (message.message == WM_QUIT) {
            g_app.running = 0u;
        }
        DispatchMessageW(&message);
    }
}

#ifdef TETRIS_SMOKE
static void process_messages_smoke(void) {
    MSG message;
    uint32_t remaining = 128u;
    while (remaining-- != 0u && PeekMessageW(&message, 0, 0, 0, PM_REMOVE)) {
        if (message.message == WM_QUIT) {
            g_app.running = 0u;
        }
        DispatchMessageW(&message);
    }
}
#endif

static HWND create_window(void) {
    WNDCLASSEXW window_class;
    zero_bytes(&window_class, sizeof(window_class));
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = (WndProc)DefWindowProcW;
    window_class.lpszClassName = k_class_name;

    if (RegisterClassExW(&window_class) == 0) {
        return 0;
    }

    return CreateWindowExW(
        0,
        k_class_name,
        k_window_title,
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        64,
        64,
        WINDOW_W,
        WINDOW_H,
        0,
        0,
        0,
        0
    );
}

static int init_graphics(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC swapchain_desc;
    UINT requested_feature_level = D3D_FEATURE_LEVEL_10_1;
    UINT actual_feature_level = 0;
    HRESULT hr;

    zero_bytes(&swapchain_desc, sizeof(swapchain_desc));
    swapchain_desc.BufferDesc.Width = FRAME_W;
    swapchain_desc.BufferDesc.Height = FRAME_H;
    swapchain_desc.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    swapchain_desc.SampleDesc.Count = 1;
    swapchain_desc.SampleDesc.Quality = 0;
    swapchain_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swapchain_desc.BufferCount = 2;
    swapchain_desc.OutputWindow = hwnd;
    swapchain_desc.Windowed = TRUE;
    swapchain_desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    hr = D3D11CreateDeviceAndSwapChain(
        0,
        D3D_DRIVER_TYPE_HARDWARE,
        0,
        0,
        &requested_feature_level,
        1,
        D3D11_SDK_VERSION,
        &swapchain_desc,
        &g_app.swapchain,
        &g_app.device,
        &actual_feature_level,
        &g_app.context
    );
    if (failed(hr) || actual_feature_level != D3D_FEATURE_LEVEL_10_1) {
        return 0;
    }
    d3d11_get_immediate_context(g_app.device, &g_app.context);
    hr = dxgi_get_buffer(g_app.swapchain, 0, &IID_ID3D11Texture2D, (void **)&g_app.backbuffer);
    return !failed(hr);
}

static int init_audio(void) {
    WAVEFORMATEX format;
    HRESULT hr;

    fill_audio_buffers();

    hr = XAudio2Create(&g_app.audio, 0, XAUDIO2_DEFAULT_PROCESSOR);
    if (failed(hr)) {
        return 0;
    }
    hr = xaudio_create_mastering_voice(g_app.audio, &g_app.mastering, 2, 48000, 0, AUDIO_CATEGORY_GAME_EFFECTS);
    if (failed(hr)) {
        return 0;
    }
    zero_bytes(&format, sizeof(format));
    format.wFormatTag = WAVE_FORMAT_PCM;
    format.nChannels = 2;
    format.nSamplesPerSec = 48000;
    format.nBlockAlign = 4;
    format.wBitsPerSample = 16;
    format.nAvgBytesPerSec = 192000;

    hr = xaudio_create_source_voice(g_app.audio, &g_app.source, &format, 0, 1.0f);
    if (failed(hr)) {
        return 0;
    }
    xaudio_start_engine(g_app.audio);
    return 1;
}

static void init_game(void) {
    g_app.running = 1u;
    g_app.screen = SCREEN_TITLE;
    g_app.level = 1u;
    g_app.rng_state = GetTickCount() ^ 0x31415926u;
    g_app.last_tick_ms = GetTickCount();
    g_app.bag_index = 7u;
    g_app.new_high_score_rank = -1;
    g_app.hold_piece = -1;
    g_app.frame_dirty = 1u;
    load_high_scores();
}

static DWORD idle_sleep_ms(void) {
    uint32_t delay;

    if (g_app.screen != SCREEN_PLAYING) {
        return 16u;
    }
    if (g_app.left_seen || g_app.right_seen || g_app.down_seen) {
        return 1u;
    }
    delay = gravity_ms_for_level();
    if (g_app.gravity_elapsed_ms < delay) {
        delay -= g_app.gravity_elapsed_ms;
    } else {
        delay = 1u;
    }
    if (delay > 16u) {
        delay = 16u;
    }
    if (delay == 0u) {
        delay = 1u;
    }
    return (DWORD)delay;
}

static void present_frame(void) {
    d3d11_update_subresource(g_app.context, g_app.backbuffer, g_pixels, FRAME_W * sizeof(uint32_t));
    dxgi_present(g_app.swapchain, 1, 0);
}

static void shutdown_app(void) {
    if (g_app.source != 0) {
        xaudio_voice_destroy(g_app.source);
        g_app.source = 0;
    }
    if (g_app.mastering != 0) {
        xaudio_voice_destroy(g_app.mastering);
        g_app.mastering = 0;
    }
    if (g_app.audio != 0) {
        com_release(g_app.audio);
        g_app.audio = 0;
    }
    if (g_app.backbuffer != 0) {
        com_release(g_app.backbuffer);
        g_app.backbuffer = 0;
    }
    if (g_app.context != 0) {
        com_release(g_app.context);
        g_app.context = 0;
    }
    if (g_app.device != 0) {
        com_release(g_app.device);
        g_app.device = 0;
    }
    if (g_app.swapchain != 0) {
        com_release(g_app.swapchain);
        g_app.swapchain = 0;
    }
}

static int main(void) {
    HWND hwnd;

    zero_bytes(&g_app, sizeof(g_app));

    hwnd = create_window();
    if (hwnd == 0) {
        ExitProcess(1);
    }
    g_app.hwnd = hwnd;

    if (!init_graphics(hwnd)) {
        shutdown_app();
        ExitProcess(2);
    }
    if (!init_audio()) {
        shutdown_app();
        ExitProcess(3);
    }

    init_game();

#ifndef TETRIS_SMOKE
    render_frame();
    present_frame();
    g_app.frame_dirty = 0u;
#endif

#ifdef TETRIS_SMOKE
    start_new_game();
    process_messages_smoke();
    update_game();
    render_frame();
    present_frame();
#else
    while (g_app.running) {
        process_messages();
        update_game();
        if (g_app.frame_dirty) {
            render_frame();
            present_frame();
            g_app.frame_dirty = 0u;
            Sleep(1);
        } else {
            Sleep(idle_sleep_ms());
        }
    }
#endif

    shutdown_app();
    ExitProcess(0);
    return 0;
}

void mainCRTStartup(void) {
    main();
}
