//! The installer and updater screens drawn with LuneUI (M6): the adapter between the core's UI
//! port and the toolkit. It decides nothing; the engine does (D36, D41). The `lunepack-ui` binary
//! owns the event loop, and this crate is the only one that may depend on LuneUI, wgpu, winit and
//! AccessKit (the boundary check).
