#[cfg(test)]
mod fragment_buffer_test;

use std::collections::HashMap;
use std::io::{BufWriter, Cursor};

use crate::content::*;
use crate::error::*;
use crate::handshake::handshake_header::*;
use crate::handshake::HandshakeType;
use crate::record_layer::record_layer_header::*;

// 2 mb max buffer size
const FRAGMENT_BUFFER_MAX_SIZE: usize = 2_000_000;

/// The payload of one handshake fragment: `data` covers
/// `[offset, offset + data.len())` of the handshake message body.
pub(crate) struct Fragment {
    offset: u32,
    data: Vec<u8>,
}

impl Fragment {
    fn end(&self) -> u32 {
        self.offset + self.data.len() as u32
    }
}

/// Everything received so far for one handshake message (one message
/// sequence number).
///
/// A peer may fragment a retransmitted message differently from the original
/// transmission, and DTLS implementations MUST be able to handle overlapping
/// fragment ranges (RFC 6347 Section 4.2.3). `ranges` is kept sorted by
/// offset and never holds a fragment that another one fully covers, so the
/// ends increase with the offsets as well. `covered` is the length of the
/// contiguous prefix of the body received so far; the message is complete
/// once `covered == length`.
pub(crate) struct MessageFragments {
    handshake_type: HandshakeType,
    length: u32,
    ranges: Vec<Fragment>,
    covered: u32,
    /// Handshake header and record epoch of the first fragment received at
    /// offset 0; used to rebuild the header of the reassembled message.
    start: Option<(HandshakeHeader, u16)>,
}

impl MessageFragments {
    fn new(handshake_type: HandshakeType, length: u32) -> Self {
        MessageFragments {
            handshake_type,
            length,
            ranges: vec![],
            covered: 0,
            start: None,
        }
    }

    fn size(&self) -> usize {
        self.ranges.iter().map(|f| f.data.len()).sum()
    }

    fn is_complete(&self) -> bool {
        self.start.is_some() && self.covered >= self.length
    }

    /// Stores a fragment, dropping any stored fragments it fully covers and
    /// ignoring it if a stored fragment already covers every byte of it.
    fn add(&mut self, offset: u32, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let end = offset + data.len() as u32;

        // Index of the first stored fragment starting at or after `offset`.
        let i = self.ranges.partition_point(|f| f.offset < offset);

        // Already covered: by the fragment just before `i` (ends increase with
        // offsets, so it is the only earlier candidate) or by one starting at
        // the same offset.
        if i > 0 && self.ranges[i - 1].end() >= end {
            return;
        }
        if i < self.ranges.len() && self.ranges[i].offset == offset && self.ranges[i].end() >= end {
            return;
        }

        // ranges[i..j] start inside the new fragment and end inside it: covered.
        let mut j = i;
        while j < self.ranges.len() && self.ranges[j].end() <= end {
            j += 1;
        }
        self.ranges.splice(
            i..j,
            std::iter::once(Fragment {
                offset,
                data: data.to_vec(),
            }),
        );

        // Extend the contiguous prefix, possibly through fragments received
        // earlier that start within reach of the new one.
        if offset <= self.covered {
            for f in &self.ranges[i..] {
                if f.offset > self.covered {
                    break;
                }
                self.covered = self.covered.max(f.end());
            }
        }
    }
}

pub(crate) struct FragmentBuffer {
    // map of MessageSequenceNumbers that hold the fragments received for them
    cache: HashMap<u16, MessageFragments>,

    current_message_sequence_number: u16,
}

impl FragmentBuffer {
    pub fn new() -> Self {
        FragmentBuffer {
            cache: HashMap::new(),
            current_message_sequence_number: 0,
        }
    }

    // Attempts to push a DTLS packet to the FragmentBuffer
    // when it returns true it means the FragmentBuffer has inserted and the buffer shouldn't be handled
    // when an error returns it is fatal, and the DTLS connection should be stopped
    pub fn push(&mut self, mut buf: &[u8]) -> Result<bool> {
        let current_size = self.size();
        if current_size + buf.len() >= FRAGMENT_BUFFER_MAX_SIZE {
            return Err(Error::ErrFragmentBufferOverflow {
                new_size: current_size + buf.len(),
                max_size: FRAGMENT_BUFFER_MAX_SIZE,
            });
        }

        let mut reader = Cursor::new(buf);
        let record_layer_header = RecordLayerHeader::unmarshal(&mut reader)?;

        // Fragment isn't a handshake, we don't need to handle it
        if record_layer_header.content_type != ContentType::Handshake {
            return Ok(false);
        }

        buf = &buf[RECORD_LAYER_HEADER_SIZE..];
        while !buf.is_empty() {
            let mut reader = Cursor::new(buf);
            let handshake_header = HandshakeHeader::unmarshal(&mut reader)?;

            // A record may carry several handshake messages or fragments; each
            // one spans exactly `fragment_length` bytes after its header.
            let end = HANDSHAKE_HEADER_LENGTH + handshake_header.fragment_length as usize;
            if end > buf.len() {
                return Err(Error::ErrBufferTooSmall);
            }
            // Discard all headers, when rebuilding the packet we will re-build
            let data = &buf[HANDSHAKE_HEADER_LENGTH..end];
            buf = &buf[end..];

            // Already reassembled and popped (a retransmission), or claims
            // bytes outside the message.
            if handshake_header.message_sequence < self.current_message_sequence_number
                || handshake_header.fragment_offset > handshake_header.length
                || handshake_header.fragment_length
                    > handshake_header.length - handshake_header.fragment_offset
            {
                continue;
            }

            let message = self
                .cache
                .entry(handshake_header.message_sequence)
                .or_insert_with(|| {
                    MessageFragments::new(handshake_header.handshake_type, handshake_header.length)
                });

            // Disagrees with the fragments already stored for this message;
            // admitting it would break the bounds `pop` relies on.
            if handshake_header.handshake_type != message.handshake_type
                || handshake_header.length != message.length
            {
                continue;
            }

            if handshake_header.fragment_offset == 0 && message.start.is_none() {
                message.start = Some((handshake_header, record_layer_header.epoch));
            }

            message.add(handshake_header.fragment_offset, data);
        }

        Ok(true)
    }

    pub fn pop(&mut self) -> Result<(Vec<u8>, u16)> {
        let seq_num = self.current_message_sequence_number;
        let Some(message) = self.cache.get(&seq_num) else {
            return Err(Error::ErrEmptyFragment);
        };
        if !message.is_complete() {
            return Err(Error::ErrEmptyFragment);
        }
        let Some((mut first_header, message_epoch)) = message.start else {
            return Err(Error::ErrEmptyFragment);
        };

        first_header.fragment_offset = 0;
        first_header.fragment_length = first_header.length;

        let mut content = Vec::with_capacity(HANDSHAKE_HEADER_LENGTH + message.length as usize);
        {
            let mut writer = BufWriter::<&mut Vec<u8>>::new(content.as_mut());
            if first_header.marshal(&mut writer).is_err() {
                return Err(Error::ErrEmptyFragment);
            }
        }

        // The prefix is contiguous, so each fragment continues at or before
        // where the previous one ended; skip the overlap.
        let mut cursor: u32 = 0;
        for f in &message.ranges {
            if f.offset >= message.length {
                break;
            }
            let skip = (cursor - f.offset) as usize;
            let take = (message.length.min(f.end()) - cursor) as usize;
            content.extend_from_slice(&f.data[skip..skip + take]);
            cursor = message.length.min(f.end());
            if cursor >= message.length {
                break;
            }
        }

        self.cache.remove(&seq_num);
        self.current_message_sequence_number += 1;

        Ok((content, message_epoch))
    }

    fn size(&self) -> usize {
        self.cache.values().map(|m| m.size()).sum()
    }
}
