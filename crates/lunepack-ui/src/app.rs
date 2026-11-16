//! The window: the event loop's application. It creates the window only after the adapter and
//! the surface are up, sends the UI's hello, then shows each frame LuneUI draws for the engine's
//! messages and sends the user's answers back. It decides nothing: the engine validates every
//! choice, and nothing here changes an outcome.

use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::Instant;

use lunepack_core::ui::{self, EngineMsg, Flow, UiMsg};
use lunepack_ui_luneui::look::{self, Metrics};
use lunepack_ui_luneui::lune_ui::access::{AccessBridge, RootInfo};
use lunepack_ui_luneui::lune_ui::clipboard::Clipboard;
use lunepack_ui_luneui::lune_ui::frame::FrameRenderer;
use lunepack_ui_luneui::lune_ui::gpu::{self, Gpu};
use lunepack_ui_luneui::lune_ui::image::ImageStore;
use lunepack_ui_luneui::lune_ui::input::{OutputState, Translator, control_flow, keymap};
use lunepack_ui_luneui::lune_ui::material;
use lunepack_ui_luneui::lune_ui::motion::{Cadence, MotionTier};
use lunepack_ui_luneui::lune_ui::scene::{BlurLimits, FrameParams};
use lunepack_ui_luneui::lune_ui::shortcuts::Shortcuts;
use lunepack_ui_luneui::lune_ui::strings::{DisplayFormat, StringTable};
use lunepack_ui_luneui::lune_ui::surface::{Acquired, SurfaceOptions, WindowSurface};
use lunepack_ui_luneui::lune_ui::text::{TextCache, TextRendering};
use lunepack_ui_luneui::lune_ui::ui::{FrameConfig, Ui, UiStore};
use lunepack_ui_luneui::lune_ui::window::glass_attributes;
use lunepack_ui_luneui::render::block_on;
use lunepack_ui_luneui::winit::application::ApplicationHandler;
use lunepack_ui_luneui::winit::dpi::LogicalSize;
use lunepack_ui_luneui::winit::event::{ElementState, MouseButton, WindowEvent};
use lunepack_ui_luneui::winit::event_loop::{ActiveEventLoop, EventLoopProxy};
use lunepack_ui_luneui::winit::window::{Window, WindowId};
use lunepack_ui_luneui::{
    Env, FONT_FAMILY, ICON_IMAGE, Material, UiModel, fonts, frame as draw_frame,
};

use crate::channel::{Exit, UserEvent};

/// Gaussian sigma and saturation of the backdrop blur, and the noise on glass: the toolkit
/// gallery's own values.
const BLUR_SIGMA: f32 = 8.0;
const BLUR_SATURATION: f32 = 1.8;
const GLASS_NOISE: f32 = 0.0225;

/// Everything that exists once the window does. Field order is drop order: the accessibility
/// bridge goes before the window it serves.
struct Shown {
    bridge: Option<AccessBridge>,
    window: Arc<Window>,
    surface: WindowSurface,
    gpu: Gpu,
    text: TextCache,
    renderer: FrameRenderer,
    translator: Translator,
    output: OutputState,
    clipboard: Clipboard,
    icon_registered: bool,
    visible: bool,
}

/// The event loop's application.
pub struct App {
    proxy: EventLoopProxy<UserEvent>,
    writer: Sender<UiMsg>,
    start: Instant,
    tier: MotionTier,
    env: Env,
    model: UiModel,
    store: UiStore,
    strings: StringTable,
    shortcuts: Shortcuts,
    shown: Option<Shown>,
    /// Frames that arrived before the window was up.
    pending: Vec<EngineMsg>,
    /// The pointer, in logical pixels.
    cursor: (f64, f64),
    exit: Exit,
    finished: bool,
}

impl App {
    /// An application that has not opened its window yet.
    pub fn new(proxy: EventLoopProxy<UserEvent>, writer: Sender<UiMsg>, tier: MotionTier) -> App {
        let env = Env::current();
        App {
            proxy,
            writer,
            start: Instant::now(),
            tier,
            env,
            model: UiModel::new(env),
            store: UiStore::default(),
            strings: StringTable::default(),
            shortcuts: Shortcuts::default(),
            shown: None,
            pending: Vec::new(),
            cursor: (0.0, 0.0),
            exit: Exit::Closed,
            finished: false,
        }
    }

    /// How the process should end.
    pub fn exit(&self) -> Exit {
        self.exit
    }

    fn finish(&mut self, event_loop: &ActiveEventLoop, exit: Exit) {
        if !self.finished {
            self.finished = true;
            self.exit = exit;
        }
        event_loop.exit();
    }

    /// The window, its surface and the GPU, in that order; the window stays hidden until the
    /// engine's hello names the flow (and so the size).
    fn setup(&self, event_loop: &ActiveEventLoop) -> Result<Shown, Exit> {
        let m = Metrics::FULL;
        let size = (f64::from(m.w), f64::from(m.h));
        let mut attrs = glass_attributes("Lunepack", size, size, false)
            .with_resizable(false)
            // The screens draw their own title strip on every OS.
            .with_decorations(false)
            .with_transparent(self.env.material == Material::Glass);
        #[cfg(target_os = "macos")]
        {
            use lunepack_ui_luneui::winit::platform::macos::WindowAttributesExtMacOS;
            attrs = attrs.with_has_shadow(true);
        }
        let window = Arc::new(
            event_loop
                .create_window(attrs)
                .map_err(|_| Exit::NoDisplay)?,
        );
        // The bridge wants a window that was never shown; a wake only posts to the loop.
        let proxy = self.proxy.clone();
        let bridge = AccessBridge::new(event_loop, &window, move || {
            let _ = proxy.send_event(UserEvent::Wake);
        })
        .ok();
        if self.env.material == Material::Glass {
            let _ = material::apply(&window, lunepack_ui_luneui::lune_ui::near_black::MATERIAL);
        }
        let instance = gpu::instance(Some(Box::new(event_loop.owned_display_handle())));
        let surface = instance
            .create_surface(window.clone())
            .map_err(|_| Exit::NoAdapter)?;
        let mut gpu = block_on(Gpu::new(instance, Some(&surface))).map_err(|_| Exit::NoAdapter)?;
        let px = window.inner_size();
        let surface = WindowSurface::with_options(
            &gpu,
            surface,
            (px.width, px.height),
            SurfaceOptions::default(),
        )
        .map_err(|_| Exit::NoAdapter)?;
        let renderer = FrameRenderer::for_surface(&mut gpu, &surface);
        Ok(Shown {
            bridge,
            translator: Translator::new(px, window.scale_factor()),
            window,
            surface,
            gpu,
            text: TextCache::new(&fonts(), FONT_FAMILY, FONT_FAMILY),
            renderer,
            output: OutputState::new(),
            clipboard: Clipboard::new(),
            icon_registered: false,
            visible: false,
        })
    }

    /// Applies one frame from the engine. A frame the reducer refuses, or a hello from another
    /// build, ends the process.
    fn handle_engine(&mut self, event_loop: &ActiveEventLoop, msg: EngineMsg) {
        let now = self.start.elapsed();
        if let Err(e) = self.model.apply(&msg, now) {
            let exit = match e {
                ui::ProtocolError::BuildIdMismatch => Exit::BuildMismatch,
                _ => Exit::Protocol,
            };
            self.finish(event_loop, exit);
            return;
        }
        match msg {
            EngineMsg::Hello { .. } => self.show(),
            EngineMsg::Ping { n } => {
                // Answered at once, with no frame: a hidden or idle window still proves it lives.
                let pong = UiMsg::Pong { n };
                if self.model.sent(&pong, now).is_ok() {
                    let _ = self.writer.send(pong);
                }
            }
            EngineMsg::Close => {
                self.finish(event_loop, Exit::Closed);
                return;
            }
            _ => {}
        }
        if let Some(shown) = &self.shown {
            shown.window.request_redraw();
        }
    }

    /// Sizes the window for the flow, names it and shows it.
    fn show(&mut self) {
        let Some(shown) = &mut self.shown else { return };
        let m = self.model.metrics();
        let size = LogicalSize::new(f64::from(m.w), f64::from(m.h));
        let _ = shown.window.request_inner_size(size);
        shown.window.set_min_inner_size(Some(size));
        shown.window.set_max_inner_size(Some(size));
        shown.window.set_title(&self.model.window_title());
        shown.window.set_visible(true);
        shown.window.focus_window();
        shown.visible = true;
    }

    /// The width of the caption buttons the title strip shows for the current flow.
    fn caption_width(&self) -> f32 {
        match self.model.state().flow() {
            Some(Flow::Update | Flow::Uninstall) => look::CAPTION_W,
            _ => 2.0 * look::CAPTION_W,
        }
    }

    /// Draws one frame and handles its answer.
    fn render(&mut self, event_loop: &ActiveEventLoop) {
        let Some(shown) = &mut self.shown else { return };
        if !shown.visible {
            return;
        }
        if shown.gpu.is_lost() {
            self.finish(event_loop, Exit::NoAdapter);
            return;
        }
        if !shown.icon_registered
            && let Some(icon) = self.model.icon()
        {
            if shown.gpu.register(ICON_IMAGE, icon.clone()).is_err() {
                // The icon stays the monogram's job; the screens do not depend on it.
            }
            shown.icon_registered = true;
        }
        let frame = match shown.surface.acquire(&shown.gpu) {
            Ok(Acquired::Frame(frame)) => frame,
            Ok(Acquired::Skip) => return,
            Ok(Acquired::Redraw) => {
                shown.window.request_redraw();
                return;
            }
            Err(_) => {
                self.finish(event_loop, Exit::NoAdapter);
                return;
            }
        };
        let view = frame.texture.create_view(&Default::default());
        let size = shown.surface.size();
        if let Some(bridge) = &shown.bridge {
            bridge.drain(&mut shown.translator);
        }
        let scale = shown.window.scale_factor();
        shown.translator.scale_factor(scale);
        let now = self.start.elapsed();
        let input = shown.translator.take(now);
        let config = FrameConfig {
            theme: look::theme(),
            tier: self.tier,
            busy_cadence: Cadence::BUSY,
            strings: &self.strings,
            arg_format: &DisplayFormat,
            keymap: keymap(),
            shortcuts: &self.shortcuts,
        };
        let mut ui = Ui::begin(&mut self.store, &input, config, &mut shown.text);
        let msg = draw_frame(&mut ui, &mut self.model, now, self.tier);
        let (scene, out) = ui.finish();
        let _ = shown.output.apply(&shown.window, &out, scale as f32);
        shown.clipboard.service(&out, &mut shown.translator);
        if let Some(bridge) = &mut shown.bridge {
            bridge.update(
                &out,
                &RootInfo {
                    title: self.model.window_title(),
                    scale,
                },
            );
        }
        let glass = self.env.material == Material::Glass;
        let params = FrameParams {
            size,
            scale: scale as f32,
            blur_sigma: if glass { BLUR_SIGMA } else { 0.0 },
            saturation: if glass { BLUR_SATURATION } else { 1.0 },
            noise_opacity: if glass { GLASS_NOISE } else { 0.0 },
            blur: BlurLimits::default(),
            text: TextRendering::SMOOTH,
        };
        let drawn = shown
            .renderer
            .draw(&mut shown.gpu, &mut shown.text, &scene, &view, params);
        if drawn.is_err() {
            self.finish(event_loop, Exit::NoAdapter);
            return;
        }
        shown.window.pre_present_notify();
        shown.surface.present(&shown.gpu, frame);
        shown.gpu.end_frame(&mut shown.text);

        if let Some(msg) = msg {
            let _ = self.writer.send(msg);
        }
        if self.model.take_minimize() {
            shown.window.set_minimized(true);
        }
        // An update that finished fades out; the engine closes the channel afterwards.
        if self.model.closable(now, self.tier) {
            shown.window.set_visible(false);
            shown.visible = false;
        }
        let (flow, redraw) = control_flow(out.repaint, self.start);
        event_loop.set_control_flow(flow);
        if redraw {
            shown.window.request_redraw();
        }
    }

    /// The window's own close request: at an open prompt it is that prompt's Cancel or Close
    /// choice; while an operation runs it is ignored (Cancel is the explicit button).
    fn close_requested(&mut self) {
        if self.model.state().open_prompt().is_none() {
            return;
        }
        let now = self.start.elapsed();
        if let Some(msg) = self.model.close_action()
            && self.model.state().accepts(&msg)
            && self.model.sent(&msg, now).is_ok()
        {
            let _ = self.writer.send(msg);
        }
        if let Some(shown) = &self.shown {
            shown.window.request_redraw();
        }
    }
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.shown.is_some() || self.finished {
            return;
        }
        match self.setup(event_loop) {
            Ok(shown) => self.shown = Some(shown),
            Err(exit) => {
                self.finish(event_loop, exit);
                return;
            }
        }
        // The adapter and the surface are up: now the engine may send its hello.
        let _ = self.writer.send(UiMsg::Hello {
            build_id: ui::build_id(),
        });
        for msg in std::mem::take(&mut self.pending) {
            self.handle_engine(event_loop, msg);
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Engine(msg) => {
                if self.shown.is_some() {
                    self.handle_engine(event_loop, msg);
                } else {
                    self.pending.push(msg);
                }
            }
            UserEvent::Ended(exit) => self.finish(event_loop, exit),
            UserEvent::Wake => {
                if let Some(shown) = &self.shown {
                    shown.window.request_redraw();
                }
            }
        }
    }

    fn new_events(
        &mut self,
        _event_loop: &ActiveEventLoop,
        cause: lunepack_ui_luneui::winit::event::StartCause,
    ) {
        // A `Repaint::At` request: its time has come.
        if matches!(
            cause,
            lunepack_ui_luneui::winit::event::StartCause::ResumeTimeReached { .. }
        ) && let Some(shown) = &self.shown
        {
            shown.window.request_redraw();
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        if event_loop.exiting() {
            return;
        }
        let caption_w = self.caption_width();
        let Some(shown) = &mut self.shown else { return };
        if shown.window.id() != id {
            return;
        }
        if let Some(bridge) = &mut shown.bridge {
            bridge.window_event(&shown.window, &event);
        }
        match &event {
            WindowEvent::CloseRequested => {
                self.close_requested();
                return;
            }
            WindowEvent::RedrawRequested => {
                self.render(event_loop);
                return;
            }
            WindowEvent::Resized(size) => {
                shown.surface.resize(&shown.gpu, size.width, size.height);
                shown.translator.resized(*size);
            }
            WindowEvent::CursorMoved { position, .. } => {
                let scale = shown.window.scale_factor();
                self.cursor = (position.x / scale, position.y / scale);
            }
            WindowEvent::MouseInput {
                state: ElementState::Pressed,
                button: MouseButton::Left,
                ..
            } => {
                // The empty part of the title strip moves the window.
                let m = self.model.metrics();
                if self.cursor.1 < f64::from(look::TITLE_H)
                    && self.cursor.0 < f64::from(m.w - caption_w)
                    && shown.window.drag_window().is_ok()
                {
                    return;
                }
            }
            _ => {}
        }
        let Some(shown) = &mut self.shown else { return };
        shown.translator.window_event(&event);
        shown.window.request_redraw();
    }
}
