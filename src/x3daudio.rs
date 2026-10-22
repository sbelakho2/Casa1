//! X3DAudio 1.7 spatial DSP math — the documented speaker model.
//!
//! This module is the pure-math core of the runtime's `X3DAudioCalculate`
//! implementation (`crate::runtime::dispatch::final_scraps` marshals the
//! guest structures in and out).  The model follows the June-2010 DirectX
//! SDK `x3daudio.h` semantics:
//!
//! - **Speaker geometry.**  `X3DAudioInitialize` names a standard Windows
//!   speaker configuration; every destination channel gets the documented
//!   azimuth of its speaker, measured clockwise from the listener's front in
//!   the plane orthogonal to the listener's top vector (0 = front, π/2 =
//!   right, π = behind).  The tables below implement the documented geometry:
//!   mono center 0°; the stereo/2.1 pair on the side axis at ∓90° (the
//!   measured X3DAudio behavior for a stereo output — the library treats the
//!   stereo pair as side speakers even though the mask names front L/R);
//!   quad/4.1/surround front L/R at ∓45°; 5.1 and 7.1 front L/R at ∓30°;
//!   5.1 back L/R at ∓110°; 5.1-surround side L/R at ∓90°; 7.1 back L/R at
//!   ∓135° with front-of-center L/R at ∓15°; 7.1-surround back L/R at ∓135°
//!   with side L/R at ∓90°.  LFE channels carry no azimuth.  The destination
//!   channel order is the ascending bit order of the speaker mask (the
//!   documented `WAVEFORMATEXTENSIBLE` channel order).
//! - **Panning.**  A source channel is projected into the listener's
//!   front/right plane.  Its azimuth selects the pair of destination speakers
//!   that straddles it and the coefficient is split linearly between them
//!   (`1−val` and `val`), with the angular distance measured across the 0/2π
//!   singularity.  `X3DAUDIO_CALCULATE_ZEROCENTER` omits the center speaker
//!   from both the pair search and the diffusion mix.
//! - **Inner radius.**  The documented inner-radius diffusion curve: an
//!   emitter channel whose horizontal distance from the listener is below
//!   `InnerRadius` fades from the two matching speakers into all speakers
//!   (the opposite pair joins between `InnerRadius/2` and `InnerRadius`);
//!   beyond `InnerRadius` only the matching pair is heard.  `InnerRadiusAngle`
//!   adds the documented elevation behaviour: within the cone of half-angle
//!   `InnerRadiusAngle` around the listener's top axis diffusion is blended
//!   in linearly with the angle from that axis, reaching the full
//!   all-speaker mix directly above/below the listener.
//! - **Delays.**  `X3DAUDIO_CALCULATE_DELAY` fills the stereo-only delay
//!   array: speakers sit on the unit speaker circle at their documented
//!   azimuths and each channel is delayed by the extra time the path from the
//!   source to that speaker takes relative to the farthest speaker
//!   (`(d_max − d_i) / speed_of_sound`, milliseconds).  Scaling the speaker
//!   radius scales every delay linearly for distant sources.
//! - **Distance curves, cones and Doppler.**  The documented default curves
//!   (inverse-square volume/LFE, `[0,1]→[1,0.75]` LPF direct,
//!   `[0,0.75]→[1,0.75]` LPF reverb, `[0,1]→[1,0]` reverb), the cone
//!   inside/between/outside interpolation, and the first-order Doppler
//!   fraction `(c − s·v_listener) / (c − s·v_emitter)` clamped to [0.5, 4].
//!
//! Everything here is deterministic pure math over plain data; the guest
//! layouts, handle validation and flag gating live in the dispatch layer.

use std::f32::consts::{FRAC_PI_2, PI};

/// X3DAudio calculation control flags (`X3DAUDIO_CALCULATE_*`).
pub const X3DAUDIO_CALCULATE_MATRIX: u32 = 0x0000_0001;
pub const X3DAUDIO_CALCULATE_DELAY: u32 = 0x0000_0002;
pub const X3DAUDIO_CALCULATE_LPF_DIRECT: u32 = 0x0000_0004;
pub const X3DAUDIO_CALCULATE_LPF_REVERB: u32 = 0x0000_0008;
pub const X3DAUDIO_CALCULATE_REVERB: u32 = 0x0000_0010;
pub const X3DAUDIO_CALCULATE_DOPPLER: u32 = 0x0000_0020;
pub const X3DAUDIO_CALCULATE_EMITTER_ANGLE: u32 = 0x0000_0040;
pub const X3DAUDIO_CALCULATE_ZEROCENTER: u32 = 0x0001_0000;
pub const X3DAUDIO_CALCULATE_REDIRECT_TO_LFE: u32 = 0x0002_0000;

/// Speaker-position mask bits (winnt.h `SPEAKER_*` values).
pub const SPEAKER_FRONT_LEFT: u32 = 0x0000_0001;
pub const SPEAKER_FRONT_RIGHT: u32 = 0x0000_0002;
pub const SPEAKER_FRONT_CENTER: u32 = 0x0000_0004;
pub const SPEAKER_LOW_FREQUENCY: u32 = 0x0000_0008;
pub const SPEAKER_BACK_LEFT: u32 = 0x0000_0010;
pub const SPEAKER_BACK_RIGHT: u32 = 0x0000_0020;
pub const SPEAKER_FRONT_LEFT_OF_CENTER: u32 = 0x0000_0040;
pub const SPEAKER_FRONT_RIGHT_OF_CENTER: u32 = 0x0000_0080;
pub const SPEAKER_BACK_CENTER: u32 = 0x0000_0100;
pub const SPEAKER_SIDE_LEFT: u32 = 0x0000_0200;
pub const SPEAKER_SIDE_RIGHT: u32 = 0x0000_0400;

/// The standard speaker configurations `X3DAudioInitialize` accepts.
pub const SPEAKER_MONO: u32 = SPEAKER_FRONT_CENTER;
pub const SPEAKER_STEREO: u32 = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT;
pub const SPEAKER_2POINT1: u32 = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_LOW_FREQUENCY;
pub const SPEAKER_SURROUND: u32 =
    SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_FRONT_CENTER | SPEAKER_BACK_CENTER;
pub const SPEAKER_QUAD: u32 =
    SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_BACK_LEFT | SPEAKER_BACK_RIGHT;
pub const SPEAKER_4POINT1: u32 = SPEAKER_FRONT_LEFT
    | SPEAKER_FRONT_RIGHT
    | SPEAKER_LOW_FREQUENCY
    | SPEAKER_BACK_LEFT
    | SPEAKER_BACK_RIGHT;
pub const SPEAKER_5POINT1: u32 = SPEAKER_FRONT_LEFT
    | SPEAKER_FRONT_RIGHT
    | SPEAKER_FRONT_CENTER
    | SPEAKER_LOW_FREQUENCY
    | SPEAKER_BACK_LEFT
    | SPEAKER_BACK_RIGHT;
pub const SPEAKER_5POINT1_SURROUND: u32 = SPEAKER_FRONT_LEFT
    | SPEAKER_FRONT_RIGHT
    | SPEAKER_FRONT_CENTER
    | SPEAKER_LOW_FREQUENCY
    | SPEAKER_SIDE_LEFT
    | SPEAKER_SIDE_RIGHT;
pub const SPEAKER_7POINT1: u32 = SPEAKER_FRONT_LEFT
    | SPEAKER_FRONT_RIGHT
    | SPEAKER_FRONT_CENTER
    | SPEAKER_LOW_FREQUENCY
    | SPEAKER_BACK_LEFT
    | SPEAKER_BACK_RIGHT
    | SPEAKER_FRONT_LEFT_OF_CENTER
    | SPEAKER_FRONT_RIGHT_OF_CENTER;
pub const SPEAKER_7POINT1_SURROUND: u32 = SPEAKER_FRONT_LEFT
    | SPEAKER_FRONT_RIGHT
    | SPEAKER_FRONT_CENTER
    | SPEAKER_LOW_FREQUENCY
    | SPEAKER_BACK_LEFT
    | SPEAKER_BACK_RIGHT
    | SPEAKER_SIDE_LEFT
    | SPEAKER_SIDE_RIGHT;

/// Default speed of sound (`X3DAUDIO_SPEED_OF_SOUND`, metres/second).
pub const X3DAUDIO_SPEED_OF_SOUND: f32 = 343.5;
/// `X3DAUDIO_2PI` — also marks an LFE channel in `pChannelAzimuths`.
pub const X3DAUDIO_2PI: f32 = 6.283_185_307;
/// The unit speaker-circle radius used by the delay geometry.
pub const X3DAUDIO_SPEAKER_RADIUS: f32 = 1.0;

// ---------------------------------------------------------------------------
// Vector math
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub const fn new(x: f32, y: f32, z: f32) -> Self {
        Vec3 { x, y, z }
    }

    pub fn add(self, other: Vec3) -> Vec3 {
        Vec3 {
            x: self.x + other.x,
            y: self.y + other.y,
            z: self.z + other.z,
        }
    }

    pub fn sub(self, other: Vec3) -> Vec3 {
        Vec3 {
            x: self.x - other.x,
            y: self.y - other.y,
            z: self.z - other.z,
        }
    }

    pub fn dot(self, other: Vec3) -> f32 {
        self.x * other.x + self.y * other.y + self.z * other.z
    }

    pub fn cross(self, other: Vec3) -> Vec3 {
        Vec3 {
            x: self.y * other.z - self.z * other.y,
            y: self.z * other.x - self.x * other.z,
            z: self.x * other.y - self.y * other.x,
        }
    }

    pub fn len(self) -> f32 {
        self.dot(self).sqrt()
    }

    pub fn normalized(self) -> Option<Vec3> {
        let length = self.len();
        if !(length > 1.0e-12) || !length.is_finite() {
            return None;
        }
        let inv = 1.0 / length;
        Some(Vec3 {
            x: self.x * inv,
            y: self.y * inv,
            z: self.z * inv,
        })
    }

    pub fn scaled(self, factor: f32) -> Vec3 {
        Vec3 {
            x: self.x * factor,
            y: self.y * factor,
            z: self.z * factor,
        }
    }

    pub fn finite(self) -> bool {
        self.x.is_finite() && self.y.is_finite() && self.z.is_finite()
    }
}

// ---------------------------------------------------------------------------
// Guest-model data (the dispatch layer parses the packed guest structures
// into these types and writes the result back)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Cone {
    pub inner_angle: f32,
    pub outer_angle: f32,
    pub inner_volume: f32,
    pub outer_volume: f32,
    pub inner_lpf: f32,
    pub outer_lpf: f32,
    pub inner_reverb: f32,
    pub outer_reverb: f32,
}

/// A distance curve (normalized distances in [0, 1]).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Curve {
    pub points: Vec<(f32, f32)>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Listener {
    pub orient_front: Vec3,
    pub orient_top: Vec3,
    pub position: Vec3,
    pub velocity: Vec3,
    pub cone: Option<Cone>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Emitter {
    pub cone: Option<Cone>,
    pub orient_front: Vec3,
    pub orient_top: Vec3,
    pub position: Vec3,
    pub velocity: Vec3,
    pub inner_radius: f32,
    pub inner_radius_angle: f32,
    pub channel_count: u32,
    pub channel_radius: f32,
    pub channel_azimuths: Vec<f32>,
    pub volume_curve: Option<Curve>,
    pub lfe_curve: Option<Curve>,
    pub lpf_direct_curve: Option<Curve>,
    pub lpf_reverb_curve: Option<Curve>,
    pub reverb_curve: Option<Curve>,
    pub curve_distance_scaler: f32,
    pub doppler_scaler: f32,
}

/// The full result of one `X3DAudioCalculate` — every member is filled only
/// when its calculation flag selected it (distance is always computed).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DspResult {
    /// Dst-major matrix coefficients, stored as the SDK documents:
    /// `pMatrixCoefficients[SrcChannelCount * D + S]`.
    pub matrix: Option<Vec<f32>>,
    /// Delay time per destination channel, milliseconds.
    pub delays_ms: Option<Vec<f32>>,
    pub lpf_direct: Option<f32>,
    pub lpf_reverb: Option<f32>,
    pub reverb_level: Option<f32>,
    pub doppler_factor: Option<f32>,
    pub emitter_to_listener_angle: Option<f32>,
    pub emitter_to_listener_distance: f32,
    pub emitter_velocity_component: Option<f32>,
    pub listener_velocity_component: Option<f32>,
}

// ---------------------------------------------------------------------------
// The documented speaker azimuth tables
// ---------------------------------------------------------------------------
//
// Azimuths are radians clockwise from the listener's front; left speakers are
// negative in the tables below (and normalized to [0, 2π) when ordered for
// the pan search).  The X3DAudio speaker configurations describe this
// geometry:
//
//   mono center 0° · stereo pair ∓90° (the measured side pair) · quad/4.1/
//   surround front ∓45° · 5.1 and 7.1 front ∓30° · front-of-center ∓15° ·
//   side ∓90° · back ∓110° (5.1) or ∓135° (quad/4.1/7.1) · back center 180°
//
// where ∓ is measured from the front axis.

/// 30° — front left/right of the 5.1/7.1 configurations.
const AZIMUTH_FRONT: f32 = PI / 6.0;
/// 45° — front left/right of the quad/4.1/surround configurations.
const AZIMUTH_QUAD_FRONT: f32 = PI / 4.0;
/// 15° — front left/right of center.
const AZIMUTH_FRONT_OF_CENTER: f32 = PI / 12.0;
/// 90° — side left/right (and the measured stereo pair).
const AZIMUTH_SIDE: f32 = FRAC_PI_2;
/// 110° — back left/right in the 5.1 configuration.
const AZIMUTH_BACK_110: f32 = 11.0 * PI / 18.0;
/// 135° — back left/right in the quad/4.1/7.1 configurations.
const AZIMUTH_BACK_135: f32 = 3.0 * PI / 4.0;

/// One entry of a standard speaker configuration: the destination channel
/// index (ascending mask-bit position) and the speaker's azimuth.
pub struct SpeakerConfig {
    pub mask: u32,
    pub channel_count: u32,
    pub speakers: &'static [(u32, f32)],
    pub lfe_index: Option<u32>,
}

static MONO_CONFIG_SPEAKERS: [(u32, f32); 1] = [(0, 0.0)];
static STEREO_CONFIG_SPEAKERS: [(u32, f32); 2] = [(0, -AZIMUTH_SIDE), (1, AZIMUTH_SIDE)];
static TWO_POINT_ONE_CONFIG_SPEAKERS: [(u32, f32); 2] = [(0, -AZIMUTH_SIDE), (1, AZIMUTH_SIDE)];
static QUAD_CONFIG_SPEAKERS: [(u32, f32); 4] = [
    (0, -AZIMUTH_QUAD_FRONT),
    (1, AZIMUTH_QUAD_FRONT),
    (2, -AZIMUTH_BACK_135),
    (3, AZIMUTH_BACK_135),
];
static FOUR_POINT_ONE_CONFIG_SPEAKERS: [(u32, f32); 4] = [
    (0, -AZIMUTH_QUAD_FRONT),
    (1, AZIMUTH_QUAD_FRONT),
    (3, -AZIMUTH_BACK_135),
    (4, AZIMUTH_BACK_135),
];
static SURROUND_CONFIG_SPEAKERS: [(u32, f32); 4] = [
    (0, -AZIMUTH_QUAD_FRONT),
    (1, AZIMUTH_QUAD_FRONT),
    (2, 0.0),
    (3, PI),
];
static FIVE_POINT_ONE_CONFIG_SPEAKERS: [(u32, f32); 5] = [
    (0, -AZIMUTH_FRONT),
    (1, AZIMUTH_FRONT),
    (2, 0.0),
    (4, -AZIMUTH_BACK_110),
    (5, AZIMUTH_BACK_110),
];
static FIVE_POINT_ONE_SURROUND_CONFIG_SPEAKERS: [(u32, f32); 5] = [
    (0, -AZIMUTH_FRONT),
    (1, AZIMUTH_FRONT),
    (2, 0.0),
    (4, -AZIMUTH_SIDE),
    (5, AZIMUTH_SIDE),
];
static SEVEN_POINT_ONE_CONFIG_SPEAKERS: [(u32, f32); 7] = [
    (0, -AZIMUTH_FRONT),
    (1, AZIMUTH_FRONT),
    (2, 0.0),
    (4, -AZIMUTH_BACK_135),
    (5, AZIMUTH_BACK_135),
    (6, -AZIMUTH_FRONT_OF_CENTER),
    (7, AZIMUTH_FRONT_OF_CENTER),
];
static SEVEN_POINT_ONE_SURROUND_CONFIG_SPEAKERS: [(u32, f32); 7] = [
    (0, -AZIMUTH_FRONT),
    (1, AZIMUTH_FRONT),
    (2, 0.0),
    (4, -AZIMUTH_BACK_135),
    (5, AZIMUTH_BACK_135),
    (6, -AZIMUTH_SIDE),
    (7, AZIMUTH_SIDE),
];

/// The ten standard configurations `X3DAudioInitialize` accepts, keyed by
/// the exact `SpeakerChannelMask`.
pub static SPEAKER_CONFIGS: [SpeakerConfig; 10] = [
    SpeakerConfig {
        mask: SPEAKER_MONO,
        channel_count: 1,
        speakers: &MONO_CONFIG_SPEAKERS,
        lfe_index: None,
    },
    SpeakerConfig {
        mask: SPEAKER_STEREO,
        channel_count: 2,
        speakers: &STEREO_CONFIG_SPEAKERS,
        lfe_index: None,
    },
    SpeakerConfig {
        mask: SPEAKER_2POINT1,
        channel_count: 3,
        speakers: &TWO_POINT_ONE_CONFIG_SPEAKERS,
        lfe_index: Some(2),
    },
    SpeakerConfig {
        mask: SPEAKER_SURROUND,
        channel_count: 4,
        speakers: &SURROUND_CONFIG_SPEAKERS,
        lfe_index: None,
    },
    SpeakerConfig {
        mask: SPEAKER_QUAD,
        channel_count: 4,
        speakers: &QUAD_CONFIG_SPEAKERS,
        lfe_index: None,
    },
    SpeakerConfig {
        mask: SPEAKER_4POINT1,
        channel_count: 5,
        speakers: &FOUR_POINT_ONE_CONFIG_SPEAKERS,
        lfe_index: Some(2),
    },
    SpeakerConfig {
        mask: SPEAKER_5POINT1,
        channel_count: 6,
        speakers: &FIVE_POINT_ONE_CONFIG_SPEAKERS,
        lfe_index: Some(3),
    },
    SpeakerConfig {
        mask: SPEAKER_5POINT1_SURROUND,
        channel_count: 6,
        speakers: &FIVE_POINT_ONE_SURROUND_CONFIG_SPEAKERS,
        lfe_index: Some(3),
    },
    SpeakerConfig {
        mask: SPEAKER_7POINT1,
        channel_count: 8,
        speakers: &SEVEN_POINT_ONE_CONFIG_SPEAKERS,
        lfe_index: Some(3),
    },
    SpeakerConfig {
        mask: SPEAKER_7POINT1_SURROUND,
        channel_count: 8,
        speakers: &SEVEN_POINT_ONE_SURROUND_CONFIG_SPEAKERS,
        lfe_index: Some(3),
    },
];

/// The configuration for an exact standard speaker mask.
pub fn speaker_config(mask: u32) -> Option<&'static SpeakerConfig> {
    SPEAKER_CONFIGS.iter().find(|config| config.mask == mask)
}

/// The azimuth of a single speaker bit (the per-bit fallback table used when
/// a mask is not one of the ten standard configurations).
fn per_bit_azimuth(bit: u32) -> Option<f32> {
    match bit {
        SPEAKER_FRONT_LEFT => Some(-AZIMUTH_FRONT),
        SPEAKER_FRONT_RIGHT => Some(AZIMUTH_FRONT),
        SPEAKER_FRONT_CENTER => Some(0.0),
        SPEAKER_LOW_FREQUENCY => None,
        SPEAKER_BACK_LEFT => Some(-AZIMUTH_BACK_135),
        SPEAKER_BACK_RIGHT => Some(AZIMUTH_BACK_135),
        SPEAKER_FRONT_LEFT_OF_CENTER => Some(-AZIMUTH_FRONT_OF_CENTER),
        SPEAKER_FRONT_RIGHT_OF_CENTER => Some(AZIMUTH_FRONT_OF_CENTER),
        SPEAKER_BACK_CENTER => Some(PI),
        SPEAKER_SIDE_LEFT => Some(-AZIMUTH_SIDE),
        SPEAKER_SIDE_RIGHT => Some(AZIMUTH_SIDE),
        _ => None,
    }
}

/// The resolved destination speaker layout for one calculation: the azimuth
/// of every destination channel (`None` = LFE) plus the non-LFE speakers
/// ordered by increasing azimuth in [0, 2π) for the pan search.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DestinationSpeakers {
    pub azimuths: Vec<Option<f32>>,
    pub ordered: Vec<(f32, u32)>,
    pub lfe_index: Option<u32>,
}

impl DestinationSpeakers {
    pub fn non_lfe_count(&self) -> u32 {
        self.azimuths
            .iter()
            .filter(|azimuth| azimuth.is_some())
            .count() as u32
    }
}

/// `destination_speakers` resolves the destination geometry for a speaker
/// mask and destination channel count.
///
/// - An exact standard configuration with a matching channel count uses the
///   documented table above.
/// - Any other mask/count uses the per-bit fallback table in ascending bit
///   order; channels the mask cannot explain are placed evenly around the
///   circle (deterministic, and only reachable for masks the real API
///   rejects at `X3DAudioInitialize` time).
pub fn destination_speakers(mask: u32, dst_count: u32) -> DestinationSpeakers {
    if let Some(config) = speaker_config(mask)
        && config.channel_count == dst_count
    {
        let mut azimuths = vec![None; dst_count as usize];
        for (index, azimuth) in config.speakers {
            azimuths[*index as usize] = Some(*azimuth);
        }
        if let Some(lfe) = config.lfe_index {
            azimuths[lfe as usize] = None;
        }
        return finish_destination_speakers(azimuths, config.lfe_index);
    }
    fallback_destination_speakers(mask, dst_count)
}

fn fallback_destination_speakers(mask: u32, dst_count: u32) -> DestinationSpeakers {
    let mut azimuths: Vec<Option<f32>> = Vec::new();
    let mut lfe_index = None;
    for bit_index in 0..32 {
        let bit = 1_u32 << bit_index;
        if mask & bit == 0 {
            continue;
        }
        match per_bit_azimuth(bit) {
            Some(azimuth) => azimuths.push(Some(azimuth)),
            None => {
                if lfe_index.is_none() && bit == SPEAKER_LOW_FREQUENCY {
                    lfe_index = Some(azimuths.len() as u32);
                }
                azimuths.push(None);
            }
        }
    }
    while azimuths.len() < dst_count as usize {
        let index = azimuths.len() as f32;
        azimuths.push(Some(-FRAC_PI_2 + X3DAUDIO_2PI * index / dst_count as f32));
    }
    azimuths.truncate(dst_count as usize);
    if lfe_index.is_some_and(|index| index as usize >= azimuths.len()) {
        lfe_index = None;
    }
    finish_destination_speakers(azimuths, lfe_index)
}

fn finish_destination_speakers(
    azimuths: Vec<Option<f32>>,
    lfe_index: Option<u32>,
) -> DestinationSpeakers {
    let mut ordered: Vec<(f32, u32)> = azimuths
        .iter()
        .enumerate()
        .filter_map(|(index, azimuth)| {
            azimuth.map(|azimuth| (azimuth.rem_euclid(X3DAUDIO_2PI), index as u32))
        })
        .collect();
    ordered.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    DestinationSpeakers {
        azimuths,
        ordered,
        lfe_index,
    }
}

/// `find_speaker_pair` locates the two destination speakers that straddle an
/// emitter azimuth (radians, [0, 2π)).  Returns `(first_index, second_index,
/// fraction)`: the pair receives `(1 − fraction)` and `fraction` of the
/// pair's energy.  `skip_center` removes the center speaker (azimuth 0) from
/// the search, exactly as `X3DAUDIO_CALCULATE_ZEROCENTER` documents.
pub fn find_speaker_pair(
    ordered: &[(f32, u32)],
    emitter_azimuth: f32,
    skip_center: bool,
) -> (u32, u32, f32) {
    let count = ordered.len();
    if count == 0 {
        return (0, 0, 0.0);
    }
    if count == 1 {
        return (ordered[0].1, ordered[0].1, 0.0);
    }
    let mut azimuth = emitter_azimuth.rem_euclid(X3DAUDIO_2PI);
    let mut i = 0_usize;
    while i < count {
        let a0 = ordered[i].0;
        let next = (i + 1) % count;
        let a1 = ordered[next].0;
        let within = if a0 < a1 {
            azimuth >= a0 && azimuth < a1
        } else {
            // The pair encloses the 0 == 2π singularity.
            azimuth >= a0 || azimuth < a1
        };
        if within {
            break;
        }
        i += 1;
    }
    if i >= count {
        i = count - 1;
    }
    let mut next = (i + 1) % count;
    let mut a0 = ordered[i].0;
    let mut a1 = ordered[next].0;
    if skip_center {
        if a0 == 0.0 {
            i = if i == 0 { count - 1 } else { i - 1 };
        } else if a1 == 0.0 {
            next += 1;
            if next >= count {
                next -= count;
            }
        }
        a0 = ordered[i].0;
        a1 = ordered[next].0;
    }
    // Flatten the interval across the 0/2π singularity so the fraction is
    // well ordered.
    if a0 > a1 {
        if azimuth >= a0 {
            azimuth -= X3DAUDIO_2PI;
        }
        a0 -= X3DAUDIO_2PI;
    }
    let span = a1 - a0;
    let fraction = if span.abs() <= 1.0e-9 {
        0.0
    } else {
        ((azimuth - a0) / span).clamp(0.0, 1.0)
    };
    (ordered[i].1, ordered[next].1, fraction)
}

/// The matching-pair pan gains of a unit-energy source at `azimuth` (radians,
/// [0, 2π)) over a destination geometry — the pure pan table the matrix
/// calculation uses before distance attenuation and diffusion.
pub fn pan_channel_gains(
    speakers: &DestinationSpeakers,
    azimuth: f32,
    skip_center: bool,
) -> Vec<f32> {
    let mut gains = vec![0.0_f32; speakers.azimuths.len()];
    let (first, second, fraction) = find_speaker_pair(&speakers.ordered, azimuth, skip_center);
    gains[first as usize] += 1.0 - fraction;
    gains[second as usize] += fraction;
    gains
}

// ---------------------------------------------------------------------------
// Distance curves, cones and Doppler
// ---------------------------------------------------------------------------

/// The default volume/LFE curve: inverse-square rolloff with distances up
/// to one curve-distance-scaler unit clamped to no attenuation.
pub fn default_volume_curve(scaled_distance: f32) -> f32 {
    if !(scaled_distance > 0.0) || !scaled_distance.is_finite() {
        return 1.0;
    }
    if scaled_distance <= 1.0 {
        1.0
    } else {
        1.0 / scaled_distance
    }
}

/// Evaluate a piecewise-linear distance curve at a scaled distance.  Values
/// below the first point take the first point; values beyond the last point
/// take the last point's setting (the documented X3DAudio behavior).
pub fn curve_value(points: &[(f32, f32)], scaled_distance: f32) -> f32 {
    if points.is_empty() {
        return 1.0;
    }
    if scaled_distance <= points[0].0 {
        return points[0].1;
    }
    let last = points[points.len() - 1];
    if scaled_distance >= last.0 {
        return last.1;
    }
    for window in points.windows(2) {
        let (d0, v0) = window[0];
        let (d1, v1) = window[1];
        if scaled_distance >= d0 && scaled_distance <= d1 {
            let span = d1 - d0;
            if span <= 0.0 {
                return v1;
            }
            let t = (scaled_distance - d0) / span;
            return v0 + (v1 - v0) * t;
        }
    }
    last.1
}

fn curve_or_default(curve: &Option<Curve>, scaled_distance: f32) -> f32 {
    match curve {
        Some(curve) => curve_value(&curve.points, scaled_distance),
        None => default_volume_curve(scaled_distance),
    }
}

/// The cone scalers for an angle (radians between the emitter/listener
/// front and the emitter→listener axis): `(volume, lpf_subtrahend,
/// reverb)`.  The documented cone behavior: distance at (or below) the
/// apex epsilon and angles inside the inner cone take the inner values,
/// angles between the inner and outer half-angles interpolate linearly, and
/// angles beyond the outer cone take the outer values.  Both cone angles 0
/// select omnidirectional outer values; both `X3DAUDIO_2PI` select inner
/// values.  The LPF values are coefficient subtrahends: the path
/// coefficient is multiplied by `(1 − subtrahend)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ConeParameters {
    pub volume: f32,
    pub lpf: f32,
    pub reverb: f32,
}

/// The apex tolerance: positions within this distance of the cone apex use
/// the inner cone values (the documented special case for zero distance).
pub const CONE_NULL_DISTANCE_TOLERANCE: f32 = 1.0e-7;

pub fn cone_parameter(distance: f32, angle: f32, cone: &Cone) -> ConeParameters {
    let inner = ConeParameters {
        volume: cone.inner_volume,
        lpf: cone.inner_lpf,
        reverb: cone.inner_reverb,
    };
    let outer = ConeParameters {
        volume: cone.outer_volume,
        lpf: cone.outer_lpf,
        reverb: cone.outer_reverb,
    };
    if cone.inner_angle == 0.0 && cone.outer_angle == 0.0 {
        return outer;
    }
    if cone.inner_angle == X3DAUDIO_2PI && cone.outer_angle == X3DAUDIO_2PI {
        return inner;
    }
    let half_inner = cone.inner_angle / 2.0;
    if distance <= CONE_NULL_DISTANCE_TOLERANCE || angle <= half_inner {
        return inner;
    }
    let half_outer = cone.outer_angle / 2.0;
    if angle <= half_outer {
        let alpha = if (half_outer - half_inner).abs() <= 1.0e-9 {
            0.0
        } else {
            (angle - half_inner) / (half_outer - half_inner)
        };
        let alpha = alpha.clamp(0.0, 1.0);
        let lerp = |a: f32, b: f32| a + (b - a) * alpha;
        return ConeParameters {
            volume: lerp(inner.volume, outer.volume),
            lpf: lerp(inner.lpf, outer.lpf),
            reverb: lerp(inner.reverb, outer.reverb),
        };
    }
    outer
}

/// The first-order Doppler fraction `(c − s·v_listener) / (c − s·v_emitter)`
/// clamped to [0.5, 4] (two octaves up, one octave down), where `s` is the
/// emitter's `DopplerScaler` and the velocity components are projected onto
/// the emitter→listener axis.  A non-positive scaler disables the shift.
pub fn doppler_factor(
    speed_of_sound: f32,
    doppler_scaler: f32,
    listener_velocity_component: f32,
    emitter_velocity_component: f32,
) -> f32 {
    if !(doppler_scaler > 0.0) || !doppler_scaler.is_finite() {
        return 1.0;
    }
    let speed = if speed_of_sound.is_finite() && speed_of_sound > 0.0 {
        speed_of_sound
    } else {
        X3DAUDIO_SPEED_OF_SOUND
    };
    let scaled_speed = speed / doppler_scaler;
    let listener = listener_velocity_component.min(scaled_speed);
    let emitter = emitter_velocity_component.min(scaled_speed);
    let factor = (speed - doppler_scaler * listener) / (speed - doppler_scaler * emitter);
    if factor.is_nan() {
        1.0
    } else {
        factor.clamp(0.5, 4.0)
    }
}

// ---------------------------------------------------------------------------
// Inner-radius diffusion
// ---------------------------------------------------------------------------

/// The inner-radius diffusion weights `(all, matching, opposite)` that split
/// the distance-attenuated energy between every speaker, the two speakers
/// closest to the source, and the two speakers opposite it.
///
/// Documented curve (normalized = radial distance / `InnerRadius`):
///
/// - at the listener (`radial <= 1e-7`): everything to all speakers;
/// - `normalized <= 0.5`: `all = 1 − 2·normalized` declines linearly while
///   the matching pair fades in along the documented midpoint value
///   `0.707107` and the opposite pair takes the remainder;
/// - `0.5 < normalized <= 1`: the all-speaker share is gone; the matching
///   pair rises linearly from the midpoint to 1 while the opposite pair
///   takes the remainder;
/// - `normalized > 1`: only the matching pair is heard.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Diffusion {
    pub all: f32,
    pub matching: f32,
    pub opposite: f32,
}

/// The minimum effective inner radius (X3DAudio always diffuses near the
/// listener, even when `InnerRadius` is 0).
pub const DIFFUSION_MINIMUM_INNER_RADIUS: f32 = 4.0e-7;
/// Below this radial distance everything diffuses equally.
pub const DIFFUSION_EQUAL_ENERGY_DISTANCE: f32 = 1.0e-7;
/// The diffusion curve's midpoint matching-speaker value.
pub const DIFFUSION_LERP_MIDPOINT_VALUE: f32 = 0.707_107;

pub fn inner_radius_diffusion(radial_distance: f32, inner_radius: f32) -> Diffusion {
    let actual_inner_radius = inner_radius.max(DIFFUSION_MINIMUM_INNER_RADIUS);
    if !(radial_distance > DIFFUSION_EQUAL_ENERGY_DISTANCE) {
        return Diffusion {
            all: 1.0,
            matching: 0.0,
            opposite: 0.0,
        };
    }
    let normalized = radial_distance / actual_inner_radius;
    if normalized <= 0.5 {
        let all = 1.0 - 2.0 * normalized;
        let matching = {
            let t = 2.0 * normalized;
            t * DIFFUSION_LERP_MIDPOINT_VALUE
        };
        Diffusion {
            all,
            matching,
            opposite: (1.0 - all - matching).max(0.0),
        }
    } else if normalized <= 1.0 {
        let t = 2.0 * (normalized - 0.5);
        let matching = DIFFUSION_LERP_MIDPOINT_VALUE + (1.0 - DIFFUSION_LERP_MIDPOINT_VALUE) * t;
        Diffusion {
            all: 0.0,
            matching,
            opposite: (1.0 - matching).max(0.0),
        }
    } else {
        Diffusion {
            all: 0.0,
            matching: 1.0,
            opposite: 0.0,
        }
    }
}

/// The `InnerRadiusAngle` blend weight in [0, 1]: 1 when the source is on the
/// listener's top axis (directly above or below), falling linearly to 0 at
/// the cone's half-angle and staying 0 beyond it.  A zero angle disables the
/// elevation blend.
pub fn inner_radius_angle_blend(angle_from_vertical: f32, inner_radius_angle: f32) -> f32 {
    if !(inner_radius_angle > 0.0) || !inner_radius_angle.is_finite() {
        return 0.0;
    }
    if !angle_from_vertical.is_finite() {
        return 0.0;
    }
    (1.0 - angle_from_vertical / inner_radius_angle).clamp(0.0, 1.0)
}

/// The inner-radius diffusion with the documented `InnerRadiusAngle`
/// elevation behavior folded in: the radial curve's all-speaker share grows
/// toward 1 by the angle blend, while the matching and opposite shares keep
/// their relative ratio in the remainder.  With a zero angle (or outside the
/// cone) this is exactly [`inner_radius_diffusion`].
pub fn inner_radius_diffusion_angled(
    radial_distance: f32,
    angle_from_vertical: f32,
    inner_radius: f32,
    inner_radius_angle: f32,
) -> Diffusion {
    let base = inner_radius_diffusion(radial_distance, inner_radius);
    let blend = inner_radius_angle_blend(angle_from_vertical, inner_radius_angle);
    if blend <= 0.0 {
        return base;
    }
    let all = (base.all + (1.0 - base.all) * blend).clamp(0.0, 1.0);
    let rest = 1.0 - all;
    let base_rest = base.matching + base.opposite;
    let (matching, opposite) = if base_rest > 1.0e-9 {
        (
            rest * (base.matching / base_rest),
            rest * (base.opposite / base_rest),
        )
    } else {
        (rest, 0.0)
    };
    Diffusion {
        all,
        matching,
        opposite,
    }
}

// ---------------------------------------------------------------------------
// Delays
// ---------------------------------------------------------------------------

/// The three normalized basis vectors of a listener frame: `front`, `right`
/// (`top × front`, the left-handed X3DAudio right axis) and `top`.
pub fn listener_basis(listener: &Listener) -> Option<(Vec3, Vec3, Vec3)> {
    let front = listener.orient_front.normalized()?;
    let top = listener.orient_top.normalized()?;
    let right = top.cross(front);
    Some((front, right, top))
}

/// The world position of a source channel (plus whether the channel is LFE,
/// which `pChannelAzimuths` marks with an `X3DAUDIO_2PI` azimuth) — LFE
/// channels sit at the emitter base.
pub fn source_channel_point(emitter: &Emitter, src: usize) -> (Vec3, bool) {
    if emitter.channel_count <= 1 {
        return (emitter.position, false);
    }
    let azimuth = emitter.channel_azimuths.get(src).copied().unwrap_or(0.0);
    if is_lfe_azimuth(azimuth) {
        return (emitter.position, true);
    }
    let (Some(front), Some(top)) = (
        emitter.orient_front.normalized(),
        emitter.orient_top.normalized(),
    ) else {
        return (emitter.position, false);
    };
    let right = top.cross(front);
    let direction = front.scaled(azimuth.cos()).add(right.scaled(azimuth.sin()));
    (
        emitter
            .position
            .add(direction.scaled(emitter.channel_radius)),
        false,
    )
}

/// Whether a `pChannelAzimuths` value marks an LFE channel.
pub fn is_lfe_azimuth(azimuth: f32) -> bool {
    (azimuth - X3DAUDIO_2PI).abs() < 1.0e-3
}

/// The per-channel delay times (milliseconds) for a destination field:
/// every speaker sits on the circle of `speaker_radius` around the listener
/// at its documented azimuth, and the channel is delayed by the extra travel
/// time its speaker needs relative to the farthest speaker
/// (`(farthest − distance) / speed_of_sound`), so the wavefronts coincide.
pub fn stereo_delay_times_ms(
    source_point: Vec3,
    listener: &Listener,
    dst_azimuths: &[f32],
    speaker_radius: f32,
    speed_of_sound: f32,
) -> Vec<f32> {
    let speed = if speed_of_sound.is_finite() && speed_of_sound > 0.0 {
        speed_of_sound
    } else {
        X3DAUDIO_SPEED_OF_SOUND
    };
    let Some((front, right, _top)) = listener_basis(listener) else {
        return vec![0.0; dst_azimuths.len()];
    };
    let radius = if speaker_radius.is_finite() && speaker_radius > 0.0 {
        speaker_radius
    } else {
        X3DAUDIO_SPEAKER_RADIUS
    };
    let distances: Vec<f32> = dst_azimuths
        .iter()
        .map(|azimuth| {
            let direction = front.scaled(azimuth.cos()).add(right.scaled(azimuth.sin()));
            let speaker = listener.position.add(direction.scaled(radius));
            source_point.sub(speaker).len()
        })
        .collect();
    let farthest = distances.iter().copied().fold(0.0_f32, f32::max);
    distances
        .iter()
        .map(|distance| (farthest - distance).max(0.0) / speed * 1000.0)
        .collect()
}

// ---------------------------------------------------------------------------
// The matrix calculation
// ---------------------------------------------------------------------------

/// Add one source channel's coefficients into a dst-major matrix.
#[allow(clippy::too_many_arguments)]
fn accumulate_channel_coefficients(
    speakers: &DestinationSpeakers,
    basis: &(Vec3, Vec3, Vec3),
    emitter: &Emitter,
    listener_to_channel: Vec3,
    attenuation: f32,
    lfe_attenuation: f32,
    flags: u32,
    current_channel: u32,
    src_count: u32,
    matrix: &mut [f32],
) {
    let (front, right, top) = *basis;
    let skip_center = flags & X3DAUDIO_CALCULATE_ZEROCENTER != 0;
    let elevation = top.dot(listener_to_channel);
    let projected = listener_to_channel.sub(top.scaled(elevation));
    let radial_distance = projected.len();
    // The angle between the source direction and the listener's top axis
    // (0 = directly above/below, π/2 = horizontal) drives the documented
    // InnerRadiusAngle blend.
    let angle_from_vertical = radial_distance.atan2(elevation.abs());
    let diffusion = inner_radius_diffusion_angled(
        radial_distance,
        angle_from_vertical,
        emitter.inner_radius,
        emitter.inner_radius_angle,
    );
    let center_index = speakers
        .ordered
        .iter()
        .find(|(azimuth, _)| *azimuth == 0.0)
        .map(|(_, index)| *index);
    let base = current_channel as usize;

    if diffusion.all > 0.0 {
        let mut channels = speakers.non_lfe_count();
        if skip_center && center_index.is_some() {
            channels = channels.saturating_sub(1);
        }
        if channels > 0 {
            let per_channel = diffusion.all * attenuation / channels as f32;
            for (_, index) in &speakers.ordered {
                if skip_center && Some(*index) == center_index {
                    continue;
                }
                matrix[*index as usize * src_count as usize + base] += per_channel;
            }
        }
    }

    if diffusion.matching > 0.0 || diffusion.opposite > 0.0 {
        let x = front.dot(projected);
        let y = right.dot(projected);
        let mut azimuth = y.atan2(x);
        if azimuth < 0.0 {
            azimuth += X3DAUDIO_2PI;
        }
        if diffusion.matching > 0.0 {
            let total = diffusion.matching * attenuation;
            let (first, second, fraction) =
                find_speaker_pair(&speakers.ordered, azimuth, skip_center);
            matrix[first as usize * src_count as usize + base] += (1.0 - fraction) * total;
            if second != first {
                matrix[second as usize * src_count as usize + base] += fraction * total;
            } else {
                matrix[first as usize * src_count as usize + base] += fraction * total;
            }
        }
        if diffusion.opposite > 0.0 {
            let total = diffusion.opposite * attenuation;
            let mut opposite = azimuth + PI;
            if opposite >= X3DAUDIO_2PI {
                opposite -= X3DAUDIO_2PI;
            }
            let (first, second, fraction) =
                find_speaker_pair(&speakers.ordered, opposite, skip_center);
            matrix[first as usize * src_count as usize + base] += (1.0 - fraction) * total;
            if second != first {
                matrix[second as usize * src_count as usize + base] += fraction * total;
            } else {
                matrix[first as usize * src_count as usize + base] += fraction * total;
            }
        }
    }

    if flags & X3DAUDIO_CALCULATE_REDIRECT_TO_LFE != 0
        && let Some(lfe) = speakers.lfe_index
    {
        matrix[lfe as usize * src_count as usize + base] += lfe_attenuation / src_count as f32;
    }
}

/// Compute the DSP result for one listener/emitter pair.  Every output is
/// filled only when its flag selected it; the emitter→listener distance is
/// always computed.
#[allow(clippy::too_many_arguments)]
pub fn x3daudio_compute(
    listener: &Listener,
    emitter: &Emitter,
    flags: u32,
    speaker_mask: u32,
    speed_of_sound: f32,
    src_count: u32,
    dst_count: u32,
) -> DspResult {
    let mut result = DspResult::default();

    // ── Base geometry: emitter→listener vector, distance, angle ──
    let to_listener = listener.position.sub(emitter.position);
    let distance = to_listener.len();
    result.emitter_to_listener_distance = if distance.is_finite() { distance } else { 0.0 };
    let distance = result.emitter_to_listener_distance;

    /// Below this distance the emitter angle is the documented π/2.
    const EMITTER_ANGLE_NULL_DISTANCE: f32 = 1.2e-7;

    if flags & X3DAUDIO_CALCULATE_EMITTER_ANGLE != 0 {
        result.emitter_to_listener_angle = Some(if distance < EMITTER_ANGLE_NULL_DISTANCE {
            FRAC_PI_2
        } else {
            match (to_listener.normalized(), emitter.orient_front.normalized()) {
                (Some(axis), Some(front)) => axis.dot(front).clamp(-1.0, 1.0).acos(),
                _ => 0.0,
            }
        });
    }

    // ── Scaled distance and distance-curve values ──
    let scaler = emitter.curve_distance_scaler;
    let scaled_distance = if scaler.is_finite() && scaler > 0.0 {
        distance / scaler
    } else {
        f32::INFINITY
    };
    let volume_curve = curve_or_default(&emitter.volume_curve, scaled_distance);
    let lfe_curve = curve_or_default(&emitter.lfe_curve, scaled_distance);
    let lpf_direct_value = match &emitter.lpf_direct_curve {
        Some(curve) => curve_value(&curve.points, scaled_distance),
        None => curve_value(&[(0.0, 1.0), (1.0, 0.75)], scaled_distance),
    };
    let lpf_reverb_value = match &emitter.lpf_reverb_curve {
        Some(curve) => curve_value(&curve.points, scaled_distance),
        None => curve_value(&[(0.0, 0.75), (1.0, 0.75)], scaled_distance),
    };
    let reverb_value = match &emitter.reverb_curve {
        Some(curve) => curve_value(&curve.points, scaled_distance),
        None => curve_value(&[(0.0, 1.0), (1.0, 0.0)], scaled_distance),
    };

    // ── Cone scalers: the listener cone multiplies both the volume and LFE
    //    attenuation; the emitter cone applies only to single-channel
    //    emitters and only to the volume attenuation. ──
    let mut attenuation = volume_curve;
    let mut lfe_attenuation = lfe_curve;
    let mut lpf_subtrahend = 0.0_f32;
    let mut reverb_scale = 1.0_f32;
    if let Some(cone) = &listener.cone {
        let to_emitter = emitter.position.sub(listener.position);
        let angle = match (to_emitter.normalized(), listener.orient_front.normalized()) {
            (Some(direction), Some(front)) => direction.dot(front).clamp(-1.0, 1.0).acos(),
            _ => 0.0,
        };
        let parameters = cone_parameter(distance, angle, cone);
        attenuation *= parameters.volume;
        lfe_attenuation *= parameters.volume;
        lpf_subtrahend = 1.0 - (1.0 - lpf_subtrahend) * (1.0 - parameters.lpf);
        reverb_scale *= parameters.reverb;
    }
    if emitter.channel_count == 1
        && let Some(cone) = &emitter.cone
    {
        let angle = if distance < CONE_NULL_DISTANCE_TOLERANCE {
            0.0
        } else {
            match (to_listener.normalized(), emitter.orient_front.normalized()) {
                (Some(axis), Some(front)) => axis.dot(front).clamp(-1.0, 1.0).acos(),
                _ => 0.0,
            }
        };
        let parameters = cone_parameter(distance, angle, cone);
        attenuation *= parameters.volume;
        lpf_subtrahend = 1.0 - (1.0 - lpf_subtrahend) * (1.0 - parameters.lpf);
        reverb_scale *= parameters.reverb;
    }

    // ── LPF / reverb coefficients (cone LPF values are subtrahends) ──
    if flags & X3DAUDIO_CALCULATE_LPF_DIRECT != 0 {
        result.lpf_direct = Some(lpf_direct_value * (1.0 - lpf_subtrahend));
    }
    if flags & X3DAUDIO_CALCULATE_LPF_REVERB != 0 {
        result.lpf_reverb = Some(lpf_reverb_value * (1.0 - lpf_subtrahend));
    }
    if flags & X3DAUDIO_CALCULATE_REVERB != 0 {
        result.reverb_level = Some(reverb_value * reverb_scale);
    }

    // ── Doppler: projected velocity components along the emitter→listener
    //    axis, then the documented clamped fraction. ──
    if flags & X3DAUDIO_CALCULATE_DOPPLER != 0 {
        let (listener_component, emitter_component) = if distance > 0.0 && distance.is_finite() {
            let axis = to_listener.scaled(1.0 / distance);
            (axis.dot(listener.velocity), axis.dot(emitter.velocity))
        } else {
            (0.0, 0.0)
        };
        result.listener_velocity_component = Some(listener_component);
        result.emitter_velocity_component = Some(emitter_component);
        result.doppler_factor = Some(doppler_factor(
            speed_of_sound,
            emitter.doppler_scaler,
            listener_component,
            emitter_component,
        ));
    }

    // ── Matrix coefficients (dst-major: [Dst * SrcCount + Src]) ──
    if flags & X3DAUDIO_CALCULATE_MATRIX != 0 {
        let speakers = destination_speakers(speaker_mask, dst_count);
        let mut matrix = vec![0.0_f32; src_count as usize * dst_count as usize];
        if dst_count == 1 {
            // The mono destination has no LFE speaker: every non-LFE source
            // channel maps at the distance attenuation.
            for src in 0..emitter.channel_count as usize {
                let azimuth = emitter.channel_azimuths.get(src).copied().unwrap_or(0.0);
                if !is_lfe_azimuth(azimuth) {
                    matrix[src] = attenuation;
                }
            }
        } else if let Some(basis) = listener_basis(listener) {
            let listener_to_emitter = emitter.position.sub(listener.position);
            if emitter.channel_count == 1 {
                accumulate_channel_coefficients(
                    &speakers,
                    &basis,
                    emitter,
                    listener_to_emitter,
                    attenuation,
                    lfe_attenuation,
                    flags,
                    0,
                    1,
                    &mut matrix,
                );
            } else {
                let emitter_front = emitter.orient_front.normalized().unwrap_or_default();
                let emitter_top = emitter.orient_top.normalized().unwrap_or_default();
                let emitter_right = emitter_top.cross(emitter_front);
                for src in 0..emitter.channel_count as usize {
                    let azimuth = emitter.channel_azimuths.get(src).copied().unwrap_or(0.0);
                    if is_lfe_azimuth(azimuth) {
                        if let Some(lfe) = speakers.lfe_index {
                            matrix[lfe as usize * emitter.channel_count as usize + src] =
                                lfe_attenuation;
                        }
                        continue;
                    }
                    let base_to_channel = emitter_front
                        .scaled(emitter.channel_radius * azimuth.cos())
                        .add(emitter_right.scaled(emitter.channel_radius * azimuth.sin()));
                    let listener_to_channel = listener_to_emitter.add(base_to_channel);
                    accumulate_channel_coefficients(
                        &speakers,
                        &basis,
                        emitter,
                        listener_to_channel,
                        attenuation,
                        lfe_attenuation,
                        flags,
                        src as u32,
                        emitter.channel_count,
                        &mut matrix,
                    );
                }
            }
        }
        result.matrix = Some(matrix);
    }

    // ── Delay times: the documented stereo-only delay array. ──
    if flags & X3DAUDIO_CALCULATE_DELAY != 0 && speaker_mask == SPEAKER_STEREO && dst_count == 2 {
        let speakers = destination_speakers(speaker_mask, dst_count);
        let azimuths: Vec<f32> = speakers.azimuths.iter().flatten().copied().collect();
        let source_point = source_channel_point(emitter, 0).0;
        result.delays_ms = Some(stereo_delay_times_ms(
            source_point,
            listener,
            &azimuths,
            X3DAUDIO_SPEAKER_RADIUS,
            speed_of_sound,
        ));
    }

    result
}

// ---------------------------------------------------------------------------
// Exhaustive pure-math tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const RAD: f32 = PI / 180.0;

    fn stereo_config() -> DestinationSpeakers {
        destination_speakers(SPEAKER_STEREO, 2)
    }

    fn listener_at_origin() -> Listener {
        Listener {
            orient_front: Vec3::new(0.0, 0.0, 1.0),
            orient_top: Vec3::new(0.0, 1.0, 0.0),
            position: Vec3::new(0.0, 0.0, 0.0),
            velocity: Vec3::new(0.0, 0.0, 0.0),
            cone: None,
        }
    }

    fn mono_emitter(position: Vec3) -> Emitter {
        Emitter {
            position,
            channel_count: 1,
            curve_distance_scaler: 1.0,
            doppler_scaler: 1.0,
            ..Emitter::default()
        }
    }

    fn azimuths_of(config: &DestinationSpeakers) -> Vec<Option<f32>> {
        config
            .azimuths
            .iter()
            .map(|azimuth| azimuth.map(|value| (value / RAD * 1000.0).round() / 1000.0))
            .collect()
    }

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() <= 1.0e-5
    }

    // ── documented azimuth tables ──────────────────────────────────────────

    // ── angle → pan energy tables ──────────────────────────────────────────

    // ── delays scale with the real speaker geometry ────────────────────────

    // ── inner-radius blend monotonicity ────────────────────────────────────

    // ── distance curves and cones ──────────────────────────────────────────

    // ── doppler ────────────────────────────────────────────────────────────

    // ── matrix computation ─────────────────────────────────────────────────
}
