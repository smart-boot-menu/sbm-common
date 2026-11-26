//! Command Signing Profile v1.
//!
//! The signature input is `COMMAND_SIGNING_DOMAIN_V1` followed by the compact JSON of
//! every envelope field except `signature_ed25519_hex`. Key order is Spec 06 §16.1.
//! Nested values use the `serde` representation of the `sbm-protocol` 0.1 types.
//! This is that byte string. `sbm-server` and a UEFI verifier both call
//! [`command_signing_preimage`] so they do not keep a second copy of the profile.

use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use serde::ser::{
    SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};
use serde::{Serialize, Serializer};

use sbm_types::SbmErrorCode;

use crate::{AuthScope, COMMAND_SIGNING_DOMAIN_V1, CommandEnvelope, CommandPayload};

#[derive(Serialize)]
struct Signable<'a> {
    schema_version: &'a str,
    command_id: &'a str,
    device_id: &'a str,
    sequence: u64,
    issued_at_unix: i64,
    expires_at_unix: i64,
    required_scope: &'a AuthScope,
    issuer_key_id: &'a str,
    payload: &'a CommandPayload,
}

pub fn command_canonical_json(envelope: &CommandEnvelope) -> Result<Vec<u8>, SbmErrorCode> {
    let signable = Signable {
        schema_version: &envelope.schema_version,
        command_id: &envelope.command_id,
        device_id: &envelope.device_id,
        sequence: envelope.sequence,
        issued_at_unix: envelope.issued_at_unix,
        expires_at_unix: envelope.expires_at_unix,
        required_scope: &envelope.required_scope,
        issuer_key_id: &envelope.issuer_key_id,
        payload: &envelope.payload,
    };
    to_vec(&signable).map_err(|_| SbmErrorCode::InvalidSchema)
}

pub fn command_signing_preimage(envelope: &CommandEnvelope) -> Result<Vec<u8>, SbmErrorCode> {
    let json = command_canonical_json(envelope)?;
    let mut out = Vec::with_capacity(COMMAND_SIGNING_DOMAIN_V1.len() + json.len());
    out.extend_from_slice(COMMAND_SIGNING_DOMAIN_V1);
    out.extend_from_slice(&json);
    Ok(out)
}

fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, CompactError> {
    let mut writer = Writer { buf: Vec::new() };
    value.serialize(&mut writer)?;
    Ok(writer.buf)
}

struct Writer {
    buf: Vec<u8>,
}

#[derive(Debug)]
struct CompactError;

impl fmt::Display for CompactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("compact json")
    }
}

impl serde::ser::Error for CompactError {
    fn custom<T: fmt::Display>(_message: T) -> Self {
        Self
    }
}

impl core::error::Error for CompactError {}

impl<'a> Serializer for &'a mut Writer {
    type Ok = ();
    type Error = CompactError;
    type SerializeSeq = Seq<'a>;
    type SerializeTuple = Seq<'a>;
    type SerializeTupleStruct = Seq<'a>;
    type SerializeTupleVariant = TupleVariant<'a>;
    type SerializeMap = Map<'a>;
    type SerializeStruct = Map<'a>;
    type SerializeStructVariant = StructVariant<'a>;

    fn serialize_bool(self, value: bool) -> Result<(), CompactError> {
        self.buf
            .extend_from_slice(if value { b"true" } else { b"false" });
        Ok(())
    }

    fn serialize_i8(self, value: i8) -> Result<(), CompactError> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i16(self, value: i16) -> Result<(), CompactError> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i32(self, value: i32) -> Result<(), CompactError> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i64(self, value: i64) -> Result<(), CompactError> {
        self.buf.extend_from_slice(value.to_string().as_bytes());
        Ok(())
    }

    fn serialize_u8(self, value: u8) -> Result<(), CompactError> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u16(self, value: u16) -> Result<(), CompactError> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u32(self, value: u32) -> Result<(), CompactError> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u64(self, value: u64) -> Result<(), CompactError> {
        self.buf.extend_from_slice(value.to_string().as_bytes());
        Ok(())
    }

    fn serialize_f32(self, _value: f32) -> Result<(), CompactError> {
        Err(CompactError)
    }

    fn serialize_f64(self, _value: f64) -> Result<(), CompactError> {
        Err(CompactError)
    }

    fn serialize_char(self, value: char) -> Result<(), CompactError> {
        let mut buf = [0u8; 4];
        self.serialize_str(value.encode_utf8(&mut buf))
    }

    fn serialize_str(self, value: &str) -> Result<(), CompactError> {
        push_string(&mut self.buf, value);
        Ok(())
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<(), CompactError> {
        let mut seq = self.serialize_seq(Some(value.len()))?;
        for byte in value {
            SerializeSeq::serialize_element(&mut seq, byte)?;
        }
        SerializeSeq::end(seq)
    }

    fn serialize_none(self) -> Result<(), CompactError> {
        self.serialize_unit()
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), CompactError> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), CompactError> {
        self.buf.extend_from_slice(b"null");
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), CompactError> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), CompactError> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), CompactError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), CompactError> {
        self.buf.push(b'{');
        push_string(&mut self.buf, variant);
        self.buf.push(b':');
        value.serialize(&mut *self)?;
        self.buf.push(b'}');
        Ok(())
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Seq<'a>, CompactError> {
        self.buf.push(b'[');
        Ok(Seq {
            buf: self,
            first: true,
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<Seq<'a>, CompactError> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Seq<'a>, CompactError> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<TupleVariant<'a>, CompactError> {
        self.buf.push(b'{');
        push_string(&mut self.buf, variant);
        self.buf.extend_from_slice(b":[");
        Ok(TupleVariant {
            buf: self,
            first: true,
        })
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Map<'a>, CompactError> {
        self.buf.push(b'{');
        Ok(Map {
            buf: self,
            first: true,
        })
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Map<'a>, CompactError> {
        self.serialize_map(None)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<StructVariant<'a>, CompactError> {
        self.buf.push(b'{');
        push_string(&mut self.buf, variant);
        self.buf.extend_from_slice(b":{");
        Ok(StructVariant {
            buf: self,
            first: true,
        })
    }
}

struct Seq<'a> {
    buf: &'a mut Writer,
    first: bool,
}

impl SerializeSeq for Seq<'_> {
    type Ok = ();
    type Error = CompactError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CompactError> {
        self.comma();
        value.serialize(&mut *self.buf)
    }

    fn end(self) -> Result<(), CompactError> {
        self.buf.buf.push(b']');
        Ok(())
    }
}

impl SerializeTuple for Seq<'_> {
    type Ok = ();
    type Error = CompactError;

    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CompactError> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<(), CompactError> {
        SerializeSeq::end(self)
    }
}

impl SerializeTupleStruct for Seq<'_> {
    type Ok = ();
    type Error = CompactError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CompactError> {
        SerializeSeq::serialize_element(self, value)
    }

    fn end(self) -> Result<(), CompactError> {
        SerializeSeq::end(self)
    }
}

impl Seq<'_> {
    fn comma(&mut self) {
        if !self.first {
            self.buf.buf.push(b',');
        }
        self.first = false;
    }
}

struct Map<'a> {
    buf: &'a mut Writer,
    first: bool,
}

impl SerializeMap for Map<'_> {
    type Ok = ();
    type Error = CompactError;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), CompactError> {
        self.comma();
        key.serialize(&mut *self.buf)?;
        self.buf.buf.push(b':');
        Ok(())
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CompactError> {
        value.serialize(&mut *self.buf)
    }

    fn end(self) -> Result<(), CompactError> {
        self.buf.buf.push(b'}');
        Ok(())
    }
}

impl SerializeStruct for Map<'_> {
    type Ok = ();
    type Error = CompactError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CompactError> {
        self.comma();
        push_string(&mut self.buf.buf, key);
        self.buf.buf.push(b':');
        value.serialize(&mut *self.buf)
    }

    fn end(self) -> Result<(), CompactError> {
        SerializeMap::end(self)
    }
}

impl Map<'_> {
    fn comma(&mut self) {
        if !self.first {
            self.buf.buf.push(b',');
        }
        self.first = false;
    }
}

struct TupleVariant<'a> {
    buf: &'a mut Writer,
    first: bool,
}

impl SerializeTupleVariant for TupleVariant<'_> {
    type Ok = ();
    type Error = CompactError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CompactError> {
        if !self.first {
            self.buf.buf.push(b',');
        }
        self.first = false;
        value.serialize(&mut *self.buf)
    }

    fn end(self) -> Result<(), CompactError> {
        self.buf.buf.extend_from_slice(b"]}");
        Ok(())
    }
}

struct StructVariant<'a> {
    buf: &'a mut Writer,
    first: bool,
}

impl SerializeStructVariant for StructVariant<'_> {
    type Ok = ();
    type Error = CompactError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CompactError> {
        if !self.first {
            self.buf.buf.push(b',');
        }
        self.first = false;
        push_string(&mut self.buf.buf, key);
        self.buf.buf.push(b':');
        value.serialize(&mut *self.buf)
    }

    fn end(self) -> Result<(), CompactError> {
        self.buf.buf.extend_from_slice(b"}}");
        Ok(())
    }
}

fn push_string(buf: &mut Vec<u8>, value: &str) {
    buf.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => buf.extend_from_slice(br#"\""#),
            '\\' => buf.extend_from_slice(br#"\\"#),
            '\u{0008}' => buf.extend_from_slice(br#"\b"#),
            '\u{000c}' => buf.extend_from_slice(br#"\f"#),
            '\n' => buf.extend_from_slice(br#"\n"#),
            '\r' => buf.extend_from_slice(br#"\r"#),
            '\t' => buf.extend_from_slice(br#"\t"#),
            other if (other as u32) < 0x20 => push_hex4(buf, other as u32),
            other => {
                let mut tmp = [0u8; 4];
                buf.extend_from_slice(other.encode_utf8(&mut tmp).as_bytes());
            }
        }
    }
    buf.push(b'"');
}

fn push_hex4(buf: &mut Vec<u8>, value: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    buf.extend_from_slice(b"\\u");
    buf.push(HEX[((value >> 12) & 0xf) as usize]);
    buf.push(HEX[((value >> 8) & 0xf) as usize]);
    buf.push(HEX[((value >> 4) & 0xf) as usize]);
    buf.push(HEX[(value & 0xf) as usize]);
}
