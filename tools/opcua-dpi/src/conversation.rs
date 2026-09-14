//! Secure conversation headers for OPN, MSG and CLO messages.
//!
//! After the message header, an OPN message carries the secure channel id, an
//! asymmetric security header (SecurityPolicyUri, sender certificate and
//! receiver thumbprint), and the sequence header. MSG and CLO carry the secure
//! channel id, a symmetric security header (token id) and the sequence header.

/// Decoded secure conversation header, with the remaining message body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationHeader {
    /// Secure channel identifier.
    pub secure_channel_id: u32,
    /// Security policy URI, present on OPN.
    pub security_policy_uri: Option<String>,
    /// Symmetric token id, present on MSG and CLO.
    pub token_id: Option<u32>,
    /// Sequence number.
    pub sequence_number: u32,
    /// Request id.
    pub request_id: u32,
    /// Remaining message body.
    pub body: Vec<u8>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, offset: 0 }
    }

    fn u32(&mut self) -> Option<u32> {
        let end = self.offset.checked_add(4)?;
        let value = u32::from_le_bytes(self.bytes.get(self.offset..end)?.try_into().ok()?);
        self.offset = end;
        Some(value)
    }

    fn string(&mut self) -> Option<String> {
        let length = self.u32()? as i32;
        if length < 0 {
            return Some(String::new());
        }
        let end = self.offset.checked_add(length as usize)?;
        let value = String::from_utf8_lossy(self.bytes.get(self.offset..end)?).into_owned();
        self.offset = end;
        Some(value)
    }

    fn byte_string(&mut self) -> Option<()> {
        let length = self.u32()? as i32;
        if length < 0 {
            return Some(());
        }
        let end = self.offset.checked_add(length as usize)?;
        self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(())
    }

    fn rest(&self) -> Vec<u8> {
        self.bytes.get(self.offset..).unwrap_or_default().to_vec()
    }
}

/// Decode the secure conversation header from the message body.
pub fn parse(message_type: &[u8; 3], payload: &[u8]) -> Option<ConversationHeader> {
    let mut reader = Reader::new(payload);
    let secure_channel_id = reader.u32()?;
    let mut security_policy_uri = None;
    let mut token_id = None;
    match message_type {
        b"OPN" => {
            security_policy_uri = Some(reader.string()?);
            reader.byte_string()?; // sender certificate
            reader.byte_string()?; // receiver certificate thumbprint
        }
        b"MSG" | b"CLO" => token_id = Some(reader.u32()?),
        _ => {}
    }
    let sequence_number = reader.u32()?;
    let request_id = reader.u32()?;
    Some(ConversationHeader {
        secure_channel_id,
        security_policy_uri,
        token_id,
        sequence_number,
        request_id,
        body: reader.rest(),
    })
}
