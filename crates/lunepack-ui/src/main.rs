//! `lunepack-ui`: the separate process that shows the install, update and uninstall screens
//! (M6). It is spawned by the runtime, talks to it over stdio frames and never decides anything:
//! the engine validates every choice, and the UI's failure never changes an outcome.

fn main() {}
