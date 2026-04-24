use crate::audio::crc32_samples;
use crate::error::{AppError, AppResult};
use crate::reason::ReasonCode;
use crate::util;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    Mp4,
    Ogg,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VideoCodec {
    None,
    H264,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AudioCodec {
    Aac,
    Vorbis,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MediaApiSurface {
    AlternativeShim,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedContainer {
    pub container: ContainerKind,
    pub video_codec: VideoCodec,
    pub audio_codec: AudioCodec,
    pub duration_ms: u32,
    pub frame_count: u32,
    pub audio_block_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoldenClip {
    pub id: String,
    pub decoder_path: String,
    pub container_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecodedClip {
    pub frame_hashes: Vec<String>,
    pub audio_crc32: u32,
    pub parser_surface: MediaApiSurface,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MediaInputClassification {
    Valid,
    Error(ReasonCode),
}

#[derive(Debug, Clone)]
pub struct MediaShim {
    ge_root: String,
}

impl MediaShim {
    pub fn new(ge_root: &str) -> Self {
        Self {
            ge_root: normalize_path(ge_root),
        }
    }

    pub fn api_surface(&self) -> MediaApiSurface {
        MediaApiSurface::AlternativeShim
    }

    pub fn parse_container(&self, bytes: &[u8]) -> AppResult<ParsedContainer> {
        if bytes.len() < 18 {
            return Err(AppError::new(
                ReasonCode::RcMediaInvalid,
                "media container is truncated",
            ));
        }
        let magic = &bytes[..4];
        let container = match magic {
            b"MP4!" => ContainerKind::Mp4,
            b"OGG!" => ContainerKind::Ogg,
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "unknown media container magic",
                ));
            }
        };
        let video_codec = match bytes[4] {
            0 => VideoCodec::None,
            1 => VideoCodec::H264,
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "unsupported video codec",
                ));
            }
        };
        let audio_codec = match bytes[5] {
            1 => AudioCodec::Aac,
            2 => AudioCodec::Vorbis,
            _ => {
                return Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "unsupported audio codec",
                ));
            }
        };
        let duration_ms = u32::from_le_bytes(bytes[6..10].try_into().expect("duration bytes"));
        let frame_count = u32::from_le_bytes(bytes[10..14].try_into().expect("frame count bytes"));
        let audio_block_count = u32::from_le_bytes(bytes[14..18].try_into().expect("audio count bytes"));

        match container {
            ContainerKind::Mp4 if !(video_codec == VideoCodec::H264 && audio_codec == AudioCodec::Aac) => {
                Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "MP4 clips must be H.264 + AAC",
                ))
            }
            ContainerKind::Ogg if !(video_codec == VideoCodec::None && audio_codec == AudioCodec::Vorbis) => {
                Err(AppError::new(
                    ReasonCode::RcMediaInvalid,
                    "OGG clips must be Vorbis-only",
                ))
            }
            _ => Ok(ParsedContainer {
                container,
                video_codec,
                audio_codec,
                duration_ms,
                frame_count,
                audio_block_count,
            }),
        }
    }

    pub fn decode_golden_clip(&self, clip: &GoldenClip) -> AppResult<DecodedClip> {
        self.ensure_decoder_path_trusted(&clip.decoder_path)?;
        let parsed = self.parse_container(&clip.container_bytes)?;
        let frame_hashes = (0..parsed.frame_count)
            .map(|index| {
                util::sha256_bytes(
                    format!(
                        "frame|{}|{:?}|{:?}|{:?}|{}|{}",
                        clip.id,
                        parsed.container,
                        parsed.video_codec,
                        parsed.audio_codec,
                        parsed.duration_ms,
                        index
                    )
                    .as_bytes(),
                )
            })
            .collect::<Vec<_>>();
        let samples = synthesize_audio_samples(&clip.id, parsed.audio_block_count);
        Ok(DecodedClip {
            frame_hashes,
            audio_crc32: crc32_samples(&samples),
            parser_surface: self.api_surface(),
        })
    }

    pub fn measure_av_drift_ms(&self, bytes: &[u8]) -> AppResult<u32> {
        let parsed = self.parse_container(bytes)?;
        let video_duration_us = parsed.frame_count as u64 * 41_666;
        let audio_duration_us = parsed.audio_block_count as u64 * 41_667;
        Ok(video_duration_us.abs_diff(audio_duration_us).div_ceil(1_000) as u32)
    }

    pub fn classify_input(&self, bytes: &[u8]) -> MediaInputClassification {
        match self.parse_container(bytes) {
            Ok(_) => MediaInputClassification::Valid,
            Err(error) => MediaInputClassification::Error(error.code),
        }
    }

    pub fn ensure_decoder_path_trusted(&self, path: &str) -> AppResult<()> {
        let normalized = normalize_path(path);
        if normalized.starts_with(&self.ge_root) || normalized.starts_with("builtin://codecs") {
            Ok(())
        } else {
            Err(AppError::new(
                ReasonCode::RcFsSandboxEscape,
                format!("untrusted decoder path {path}"),
            ))
        }
    }
}

pub fn build_container_bytes(
    container: ContainerKind,
    video_codec: VideoCodec,
    audio_codec: AudioCodec,
    duration_ms: u32,
    frame_count: u32,
    audio_block_count: u32,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(match container {
        ContainerKind::Mp4 => b"MP4!",
        ContainerKind::Ogg => b"OGG!",
    });
    bytes.push(match video_codec {
        VideoCodec::None => 0,
        VideoCodec::H264 => 1,
    });
    bytes.push(match audio_codec {
        AudioCodec::Aac => 1,
        AudioCodec::Vorbis => 2,
    });
    bytes.extend_from_slice(&duration_ms.to_le_bytes());
    bytes.extend_from_slice(&frame_count.to_le_bytes());
    bytes.extend_from_slice(&audio_block_count.to_le_bytes());
    bytes
}

fn synthesize_audio_samples(clip_id: &str, block_count: u32) -> Vec<f32> {
    let seed = util::sha256_bytes(clip_id.as_bytes());
    (0..block_count)
        .flat_map(|block| {
            let phase = ((block as f32) + (seed.as_bytes()[block as usize % seed.len()] as f32 / 255.0)) / 16.0;
            [phase.sin(), phase.cos() * 0.5]
        })
        .collect()
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").to_ascii_lowercase()
}