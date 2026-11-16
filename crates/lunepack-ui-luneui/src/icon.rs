//! The app icon: a PNG decoded defensively (M6-D11). It travels in the hello as PNG bytes of at
//! most 512 KiB; it is signed, but is still treated as untrusted. A side over 1024 px, a decoded
//! size over 16 MiB or any decode failure ends in `None` and the screens draw a monogram.

use lune_ui::image::{ImageData, ImageId};

/// The id the icon is registered under with the renderer.
pub const ICON_IMAGE: ImageId = ImageId(0x6C70_6B01);
/// Most pixels along a side.
pub const MAX_SIDE: u32 = 1024;
/// Most bytes the decoder may allocate, and the decoded size it accepts.
pub const MAX_DECODED: usize = 16 * 1024 * 1024;

/// Why a PNG was refused.
#[derive(Debug, thiserror::Error)]
pub enum IconError {
    /// The PNG could not be decoded.
    #[error("the icon is not a valid PNG")]
    Decode,
    /// A side is over [`MAX_SIDE`], or the picture has no area.
    #[error("the icon's size is outside what is accepted")]
    Size,
    /// The decoded picture would be over [`MAX_DECODED`].
    #[error("the decoded icon is too large")]
    Memory,
    /// The color type is not one the decoder expands to 8 bits.
    #[error("the icon's color type is not supported")]
    Format,
}

/// Decodes `bytes` to straight-alpha RGBA, within the caps.
pub fn decode(bytes: &[u8]) -> Result<ImageData, IconError> {
    let mut decoder = png::Decoder::new_with_limits(
        std::io::Cursor::new(bytes),
        png::Limits { bytes: MAX_DECODED },
    );
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().map_err(|_| IconError::Decode)?;
    let (w, h) = {
        let info = reader.info();
        (info.width, info.height)
    };
    if w == 0 || h == 0 || w > MAX_SIDE || h > MAX_SIDE {
        return Err(IconError::Size);
    }
    let size = reader.output_buffer_size().ok_or(IconError::Memory)?;
    if size > MAX_DECODED {
        return Err(IconError::Memory);
    }
    let mut buf = vec![0u8; size];
    let frame = reader.next_frame(&mut buf).map_err(|_| IconError::Decode)?;
    let data = &buf[..frame.buffer_size()];
    let pixels = (w as usize) * (h as usize);
    let mut rgba = Vec::with_capacity(pixels * 4);
    match (frame.color_type, frame.bit_depth) {
        (png::ColorType::Rgba, png::BitDepth::Eight) => rgba.extend_from_slice(data),
        (png::ColorType::Rgb, png::BitDepth::Eight) => {
            for px in data.as_chunks::<3>().0 {
                rgba.extend_from_slice(&[px[0], px[1], px[2], 255]);
            }
        }
        (png::ColorType::GrayscaleAlpha, png::BitDepth::Eight) => {
            for px in data.as_chunks::<2>().0 {
                rgba.extend_from_slice(&[px[0], px[0], px[0], px[1]]);
            }
        }
        (png::ColorType::Grayscale, png::BitDepth::Eight) => {
            for &g in data {
                rgba.extend_from_slice(&[g, g, g, 255]);
            }
        }
        _ => return Err(IconError::Format),
    }
    let image = ImageData {
        width: w,
        height: h,
        rgba,
    };
    if image.length_ok() {
        Ok(image)
    } else {
        Err(IconError::Decode)
    }
}
