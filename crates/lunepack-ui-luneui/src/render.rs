//! Headless rendering: scripted engine messages and input are played into a model and the frames
//! are drawn on a GPU device with no window. It serves the golden frames and the demo. Frame
//! times come from the script, so a run is the same every time on one adapter.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use lune_ui::dump;
use lune_ui::frame::FrameRenderer;
use lune_ui::gpu::{self, Gpu};
use lune_ui::image::ImageStore;
use lune_ui::input::{FrameOutput, Key, Keymap, NamedKey, PointerButton};
use lune_ui::motion::{Cadence, MotionTier};
use lune_ui::scene::{BlurLimits, FrameParams, Scene};
use lune_ui::shortcuts::Shortcuts;
use lune_ui::strings::{DisplayFormat, StringTable};
use lune_ui::testing::ScriptedInput;
use lune_ui::text::{TextCache, TextRendering, TextSystem};
use lune_ui::ui::{FrameConfig, Ui, UiStore};

use lunepack_core::ui::{ChoiceValue, EngineMsg, Flow, UiMsg};

use crate::model::{Env, UiModel};
use crate::{FONT_FAMILY, fonts, look};

/// Why a render failed.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// No adapter, or the device could not be opened.
    #[error("no GPU adapter: {0}")]
    Gpu(String),
    /// Drawing or reading back a frame failed.
    #[error("render failed: {0}")]
    Draw(String),
    /// A scripted message was refused by the reducer.
    #[error("the script is invalid: {0}")]
    Script(String),
}

/// One thing that happens at a script time.
#[derive(Debug, Clone)]
pub enum Step {
    /// A message from the engine.
    Engine(EngineMsg),
    /// The user answers the open prompt (as if the button was clicked).
    Choose(ChoiceValue),
    /// The user cancels the running operation.
    Cancel,
    /// The pointer moves to `(x, y)` logical pixels.
    Pointer(f32, f32),
    /// The pointer leaves the window.
    PointerAway,
    /// A click at `(x, y)`.
    Click(f32, f32),
    /// A key press and release.
    Key(NamedKey),
}

/// A step and the time it happens.
#[derive(Debug, Clone)]
pub struct Timed {
    /// When, since the window opened.
    pub at: Duration,
    /// What.
    pub step: Step,
}

/// A script step at `ms` milliseconds.
pub fn at(ms: u64, step: Step) -> Timed {
    Timed {
        at: Duration::from_millis(ms),
        step,
    }
}

/// How to render.
#[derive(Debug, Clone, Copy)]
pub struct RenderOptions {
    /// The OS wording and the window material.
    pub env: Env,
    /// The motion tier.
    pub tier: MotionTier,
    /// Device pixels per logical pixel.
    pub scale: f32,
    /// The flow whose window is rendered (its size).
    pub flow: Flow,
}

impl Default for RenderOptions {
    fn default() -> Self {
        RenderOptions {
            env: Env::current(),
            tier: MotionTier::Full,
            scale: 1.0,
            flow: Flow::Install,
        }
    }
}

/// A frame as straight RGBA bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RgbaImage {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// `width * height * 4` bytes, top row first.
    pub rgba: Vec<u8>,
}

impl RgbaImage {
    /// Writes the image as a PNG file.
    pub fn write_png(&self, path: &Path) -> Result<(), RenderError> {
        dump::write_png(path, (self.width, self.height), &self.rgba).map_err(RenderError::Draw)
    }
}

/// Polls `future` to its end on the calling thread.
fn block_on<F: Future>(future: F) -> F::Output {
    struct Park(std::thread::Thread);
    impl Wake for Park {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Park(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::park(),
        }
    }
}

/// The model, the toolkit's retained state and a scripted input, played frame by frame. The
/// renderer draws its scenes on a GPU; the tests read its semantic tree and answers with a fake
/// text system.
pub struct Player {
    /// What the screens show.
    pub model: UiModel,
    store: UiStore,
    input: ScriptedInput,
    strings: StringTable,
    shortcuts: Shortcuts,
    opts: RenderOptions,
    answers: Vec<UiMsg>,
}

impl Player {
    /// A window of the installer's size at `opts.scale`, with the model waiting for a hello.
    pub fn new(opts: RenderOptions) -> Player {
        let m = look::Metrics::of(Some(opts.flow));
        let (w, h) = (m.w, m.h);
        let mut input = ScriptedInput::new((w, h), opts.scale);
        input.focus(true);
        Player {
            model: UiModel::new(opts.env),
            store: UiStore::default(),
            input,
            strings: StringTable::default(),
            shortcuts: Shortcuts::default(),
            opts,
            answers: Vec::new(),
        }
    }

    /// What the user answered since the last call: clicks, keys and scripted choices, in order.
    pub fn take_answers(&mut self) -> Vec<UiMsg> {
        std::mem::take(&mut self.answers)
    }

    /// Applies one script step at its own time.
    pub fn play(&mut self, item: &Timed) -> Result<(), RenderError> {
        let script = |e: lunepack_core::ui::ProtocolError| RenderError::Script(e.to_string());
        match &item.step {
            Step::Engine(msg) => self.model.apply(msg, item.at).map_err(script)?,
            Step::Choose(value) => {
                let Some((id, _)) = self.model.state().open_prompt() else {
                    return Err(RenderError::Script("no prompt is open".into()));
                };
                let msg = UiMsg::Choice { id, value: *value };
                self.model.sent(&msg, item.at).map_err(script)?;
                self.answers.push(msg);
            }
            Step::Cancel => {
                self.model.sent(&UiMsg::Cancel, item.at).map_err(script)?;
                self.answers.push(UiMsg::Cancel);
            }
            Step::Pointer(x, y) => {
                self.input.pointer_to(*x, *y);
            }
            Step::PointerAway => {
                self.input.pointer_leave();
            }
            Step::Click(x, y) => {
                self.input.pointer_to(*x, *y);
                self.input.click(PointerButton::Primary);
            }
            Step::Key(key) => {
                self.input.key_down(Key::Named(*key), None);
                self.input.key_up(Key::Named(*key));
            }
        }
        Ok(())
    }

    /// Builds the frame at `now` with `text`; the user's answer, if any, is also kept for
    /// [`Player::take_answers`].
    pub fn frame(
        &mut self,
        text: &mut dyn TextSystem,
        now: Duration,
    ) -> (Scene, FrameOutput, Option<UiMsg>) {
        self.input.set_time(now);
        let raw = self.input.end_frame();
        let config = FrameConfig {
            theme: look::theme(),
            tier: self.opts.tier,
            busy_cadence: Cadence::BUSY,
            strings: &self.strings,
            arg_format: &DisplayFormat,
            keymap: Keymap::PC,
            shortcuts: &self.shortcuts,
        };
        let mut ui = Ui::begin(&mut self.store, &raw, config, text);
        let msg = crate::frame(&mut ui, &mut self.model, now, self.opts.tier);
        let (scene, output) = ui.finish();
        if let Some(m) = &msg {
            self.answers.push(m.clone());
        }
        (scene, output, msg)
    }
}

/// A headless GPU and the text cache, kept across renders.
pub struct Renderer {
    gpu: Gpu,
    frame: FrameRenderer,
    text: TextCache,
}

impl Renderer {
    /// Opens a headless device.
    pub fn new() -> Result<Renderer, RenderError> {
        let mut gpu = block_on(Gpu::new(gpu::instance(None), None)).map_err(RenderError::Gpu)?;
        let frame = FrameRenderer::new(&mut gpu, wgpu::TextureFormat::Bgra8Unorm);
        Ok(Renderer {
            gpu,
            frame,
            text: TextCache::new(&fonts(), FONT_FAMILY, FONT_FAMILY),
        })
    }

    /// Plays `script` (sorted by time) and returns the frame at each of `times`. Frames are built
    /// every 10 ms and at every script time and capture time, so the toolkit's own transitions
    /// (hover fades, focus rings) run as they do in a window.
    pub fn render(
        &mut self,
        script: &[Timed],
        times: &[Duration],
        opts: &RenderOptions,
    ) -> Result<Vec<RgbaImage>, RenderError> {
        let m = look::Metrics::of(Some(opts.flow));
        let (lw, lh) = (m.w, m.h);
        let size = ((lw * opts.scale) as u32, (lh * opts.scale) as u32);
        let mut player = Player::new(*opts);

        let last = times
            .iter()
            .copied()
            .chain(script.iter().map(|s| s.at))
            .max()
            .unwrap_or_default();
        let mut stamps: Vec<Duration> = (0..=last.as_millis() as u64 / 10)
            .map(|i| Duration::from_millis(i * 10))
            .chain(times.iter().copied())
            .chain(script.iter().map(|s| s.at))
            .collect();
        stamps.sort();
        stamps.dedup();

        let mut next = 0;
        let mut out: Vec<Option<RgbaImage>> = vec![None; times.len()];
        let mut registered = false;
        for &now in &stamps {
            while let Some(item) = script.get(next).filter(|s| s.at <= now) {
                next += 1;
                player.play(item)?;
            }
            let (scene, _, _) = player.frame(&mut self.text, now);

            let wanted: Vec<usize> = times
                .iter()
                .enumerate()
                .filter(|(_, t)| **t == now)
                .map(|(i, _)| i)
                .collect();
            if wanted.is_empty() {
                continue;
            }
            if !registered && let Some(icon) = player.model.icon() {
                self.gpu
                    .register(crate::ICON_IMAGE, icon.clone())
                    .map_err(|e| RenderError::Draw(e.to_string()))?;
                registered = true;
            }
            let params = FrameParams {
                size,
                scale: opts.scale,
                blur_sigma: 0.0,
                saturation: 1.0,
                noise_opacity: 0.0,
                blur: BlurLimits::default(),
                text: TextRendering::SMOOTH,
            };
            let texture = dump::target(&self.gpu.device, self.frame.format(), size);
            let view = texture.create_view(&Default::default());
            // Drawn twice, as the toolkit's own dumps are: the first fills the glyph atlas.
            for _ in 0..2 {
                self.frame
                    .draw_with(
                        &mut self.gpu,
                        &mut self.text,
                        &scene,
                        &view,
                        params,
                        &mut [],
                    )
                    .map_err(RenderError::Draw)?;
                self.gpu.end_frame(&mut self.text);
            }
            let rgba = dump::read_rgba(&self.gpu.device, &self.gpu.queue, &texture)
                .map_err(RenderError::Draw)?;
            let image = RgbaImage {
                width: size.0,
                height: size.1,
                rgba,
            };
            for i in wanted {
                out[i] = Some(image.clone());
            }
        }
        if registered {
            self.gpu.release(crate::ICON_IMAGE);
        }
        out.into_iter()
            .map(|i| i.ok_or_else(|| RenderError::Draw("a capture time was not reached".into())))
            .collect()
    }
}

/// Opens a headless device, plays `script` and returns the frames at `times`.
pub fn render_headless(
    script: &[Timed],
    times: &[Duration],
    opts: &RenderOptions,
) -> Result<Vec<RgbaImage>, RenderError> {
    Renderer::new()?.render(script, times, opts)
}
