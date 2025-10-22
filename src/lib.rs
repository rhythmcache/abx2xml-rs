use base64::Engine;
use hex;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AbxError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error(
        "Invalid ABX file format - magic header mismatch. Expected: {expected:02X?}, got: {actual:02X?}"
    )]
    InvalidMagicHeader { expected: [u8; 4], actual: [u8; 4] },
    #[error("Failed to read {0} from stream")]
    ReadError(String),
    #[error("Invalid interned string index: {0}")]
    InvalidInternedStringIndex(u16),
    #[error("Unknown attribute type: {0}")]
    UnknownAttributeType(u8),
    #[error("Parse error: {0}")]
    ParseError(String),
}

pub struct AbxToXmlConverter;

impl AbxToXmlConverter {
    pub fn convert<R: Read, W: Write>(reader: R, writer: W) -> Result<()> {
        let mut deserializer = BinaryXmlDeserializer::new(reader, writer)?;
        deserializer.deserialize()
    }
    pub fn convert_file(input_path: &str, output_path: &str) -> Result<()> {
        if input_path == output_path {
            return Self::convert_file_in_place(input_path);
        }
        let input_file = File::open(input_path)?;
        let reader = BufReader::new(input_file);
        let output_file = File::create(output_path)?;
        let writer = BufWriter::new(output_file);
        Self::convert(reader, writer)
    }
    pub fn convert_stdin_stdout() -> Result<()> {
        let stdin = io::stdin();
        let reader = stdin.lock();
        let stdout = io::stdout();
        let writer = BufWriter::new(stdout.lock());
        Self::convert(reader, writer)
    }
    pub fn convert_stdin_to_file(output_path: &str) -> Result<()> {
        let stdin = io::stdin();
        let reader = stdin.lock();
        let output_file = File::create(output_path)?;
        let writer = BufWriter::new(output_file);
        Self::convert(reader, writer)
    }
    pub fn convert_file_to_stdout(input_path: &str) -> Result<()> {
        let input_file = File::open(input_path)?;
        let reader = BufReader::new(input_file);
        let writer = io::stdout();
        Self::convert(reader, writer)
    }
    fn convert_file_in_place(file_path: &str) -> Result<()> {
        let input_file = File::open(file_path)?;
        let mut reader = BufReader::new(input_file);
        let mut file_data = Vec::new();
        reader.read_to_end(&mut file_data)?;
        let cursor = Cursor::new(file_data);
        let mut output_data = Vec::new();
        {
            let writer = Cursor::new(&mut output_data);
            Self::convert(cursor, writer)?;
        }
        let output_file = File::create(file_path)?;
        let mut writer = BufWriter::new(output_file);
        writer.write_all(&output_data)?;
        writer.flush()?;
        Ok(())
    }
    pub fn convert_bytes(abx_data: &[u8]) -> Result<String> {
        let cursor = Cursor::new(abx_data);
        let mut output_data = Vec::new();
        {
            let writer = Cursor::new(&mut output_data);
            Self::convert(cursor, writer)?;
        }
        String::from_utf8(output_data)
            .map_err(|_| crate::AbxError::ParseError("Invalid UTF-8 in output".to_string()))
    }
    pub fn convert_vec(abx_data: Vec<u8>) -> Result<String> {
        Self::convert_bytes(&abx_data)
    }
}

pub type Result<T> = std::result::Result<T, AbxError>;

pub const PROTOCOL_MAGIC_VERSION_0: [u8; 4] = [0x41, 0x42, 0x58, 0x00];
pub const START_DOCUMENT: u8 = 0;
pub const END_DOCUMENT: u8 = 1;
pub const START_TAG: u8 = 2;
pub const END_TAG: u8 = 3;
pub const TEXT: u8 = 4;
pub const CDSECT: u8 = 5;
pub const ENTITY_REF: u8 = 6;
pub const IGNORABLE_WHITESPACE: u8 = 7;
pub const PROCESSING_INSTRUCTION: u8 = 8;
pub const COMMENT: u8 = 9;
pub const DOCDECL: u8 = 10;
pub const ATTRIBUTE: u8 = 15;
pub const TYPE_STRING: u8 = 2 << 4;
pub const TYPE_STRING_INTERNED: u8 = 3 << 4;
pub const TYPE_BYTES_HEX: u8 = 4 << 4;
pub const TYPE_BYTES_BASE64: u8 = 5 << 4;
pub const TYPE_INT: u8 = 6 << 4;
pub const TYPE_INT_HEX: u8 = 7 << 4;
pub const TYPE_LONG: u8 = 8 << 4;
pub const TYPE_LONG_HEX: u8 = 9 << 4;
pub const TYPE_FLOAT: u8 = 10 << 4;
pub const TYPE_DOUBLE: u8 = 11 << 4;
pub const TYPE_BOOLEAN_TRUE: u8 = 12 << 4;
pub const TYPE_BOOLEAN_FALSE: u8 = 13 << 4;
pub struct DataInput<R: Read> {
    reader: R,
    interned_strings: Vec<String>,
    peeked_byte: Option<u8>,
}
impl<R: Read> DataInput<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            interned_strings: Vec::new(),
            peeked_byte: None,
        }
    }
    pub fn read_byte(&mut self) -> Result<u8> {
        if let Some(byte) = self.peeked_byte.take() {
            return Ok(byte);
        }
        let mut buf = [0u8; 1];
        self.reader
            .read_exact(&mut buf)
            .map_err(|_| AbxError::ReadError("byte".to_string()))?;
        Ok(buf[0])
    }
    pub fn peek_byte(&mut self) -> Result<u8> {
        if let Some(byte) = self.peeked_byte {
            return Ok(byte);
        }
        let byte = self.read_byte()?;
        self.peeked_byte = Some(byte);
        Ok(byte)
    }
    pub fn read_short(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        if let Some(byte) = self.peeked_byte.take() {
            buf[0] = byte;
            self.reader
                .read_exact(&mut buf[1..])
                .map_err(|_| AbxError::ReadError("short".to_string()))?;
        } else {
            self.reader
                .read_exact(&mut buf)
                .map_err(|_| AbxError::ReadError("short".to_string()))?;
        }
        Ok(u16::from_be_bytes(buf))
    }
    pub fn read_int(&mut self) -> Result<i32> {
        let mut buf = [0u8; 4];
        let start_idx = if let Some(byte) = self.peeked_byte.take() {
            buf[0] = byte;
            1
        } else {
            0
        };
        self.reader
            .read_exact(&mut buf[start_idx..])
            .map_err(|_| AbxError::ReadError("int".to_string()))?;
        Ok(i32::from_be_bytes(buf))
    }
    pub fn read_long(&mut self) -> Result<i64> {
        let mut buf = [0u8; 8];
        let start_idx = if let Some(byte) = self.peeked_byte.take() {
            buf[0] = byte;
            1
        } else {
            0
        };
        self.reader
            .read_exact(&mut buf[start_idx..])
            .map_err(|_| AbxError::ReadError("long".to_string()))?;
        Ok(i64::from_be_bytes(buf))
    }
    pub fn read_float(&mut self) -> Result<f32> {
        let int_value = self.read_int()? as u32;
        Ok(f32::from_bits(int_value))
    }
    pub fn read_double(&mut self) -> Result<f64> {
        let int_value = self.read_long()? as u64;
        Ok(f64::from_bits(int_value))
    }
    pub fn read_utf(&mut self) -> Result<String> {
        let length = self.read_short()?;
        let mut buffer = vec![0u8; length as usize];
        self.reader
            .read_exact(&mut buffer)
            .map_err(|_| AbxError::ReadError("UTF string".to_string()))?;
        String::from_utf8(buffer)
            .map_err(|_| AbxError::ReadError("UTF string (invalid UTF-8)".to_string()))
    }
    pub fn read_interned_utf(&mut self) -> Result<String> {
        let index = self.read_short()?;
        if index == 0xFFFF {
            let string = self.read_utf()?;
            self.interned_strings.push(string.clone());
            Ok(string)
        } else {
            self.interned_strings
                .get(index as usize)
                .cloned()
                .ok_or(AbxError::InvalidInternedStringIndex(index))
        }
    }
    pub fn read_bytes(&mut self, length: u16) -> Result<Vec<u8>> {
        let mut data = vec![0u8; length as usize];
        self.reader
            .read_exact(&mut data)
            .map_err(|_| AbxError::ReadError("bytes".to_string()))?;
        Ok(data)
    }
    pub fn interned_strings(&self) -> &[String] {
        &self.interned_strings
    }
}
pub fn encode_xml_entities(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
pub struct BinaryXmlDeserializer<R: Read, W: Write> {
    input: DataInput<R>,
    output: W,
}
impl<R: Read, W: Write> BinaryXmlDeserializer<R, W> {
    pub fn new(mut reader: R, output: W) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader
            .read_exact(&mut magic)
            .map_err(|_| AbxError::ReadError("magic header".to_string()))?;
        if magic != PROTOCOL_MAGIC_VERSION_0 {
            return Err(AbxError::InvalidMagicHeader {
                expected: PROTOCOL_MAGIC_VERSION_0,
                actual: magic,
            });
        }
        Ok(Self {
            input: DataInput::new(reader),
            output,
        })
    }
    pub fn deserialize(&mut self) -> Result<()> {
        write!(self.output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        loop {
            match self.process_token() {
                Ok(should_continue) => {
                    if !should_continue {
                        break;
                    }
                }
                Err(AbxError::ReadError(_)) => {
                    break;
                }
                Err(e) => {
                    eprintln!("Warning: Error parsing token: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }
    fn process_token(&mut self) -> Result<bool> {
        let token = self.input.read_byte()?;
        let command = token & 0x0F;
        let type_info = token & 0xF0;
        match command {
            START_DOCUMENT => Ok(true),
            END_DOCUMENT => Ok(false),
            START_TAG => {
                let tag_name = self.input.read_interned_utf()?;
                write!(self.output, "<{}", tag_name)?;
                loop {
                    match self.input.peek_byte() {
                        Ok(next_token) => {
                            if (next_token & 0x0F) == ATTRIBUTE {
                                let _ = self.input.read_byte()?;
                                self.process_attribute(next_token)?;
                            } else {
                                break;
                            }
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
                write!(self.output, ">")?;
                Ok(true)
            }
            END_TAG => {
                let tag_name = self.input.read_interned_utf()?;
                write!(self.output, "</{}>", tag_name)?;
                Ok(true)
            }
            TEXT => {
                if type_info == TYPE_STRING {
                    let text = self.input.read_utf()?;
                    if !text.is_empty() {
                        write!(self.output, "{}", encode_xml_entities(&text))?;
                    }
                }
                Ok(true)
            }
            CDSECT => {
                if type_info == TYPE_STRING {
                    let text = self.input.read_utf()?;
                    write!(self.output, "<![CDATA[{}]]>", text)?;
                }
                Ok(true)
            }
            COMMENT => {
                if type_info == TYPE_STRING {
                    let text = self.input.read_utf()?;
                    write!(self.output, "<!--{}-->", text)?;
                }
                Ok(true)
            }
            PROCESSING_INSTRUCTION => {
                if type_info == TYPE_STRING {
                    let text = self.input.read_utf()?;
                    write!(self.output, "<?{}?>", text)?;
                }
                Ok(true)
            }
            DOCDECL => {
                if type_info == TYPE_STRING {
                    let text = self.input.read_utf()?;
                    write!(self.output, "<!DOCTYPE {}>", text)?;
                }
                Ok(true)
            }
            ENTITY_REF => {
                if type_info == TYPE_STRING {
                    let text = self.input.read_utf()?;
                    write!(self.output, "&{};", text)?;
                }
                Ok(true)
            }
            IGNORABLE_WHITESPACE => {
                if type_info == TYPE_STRING {
                    let text = self.input.read_utf()?;
                    write!(self.output, "{}", text)?;
                }
                Ok(true)
            }
            _ => {
                eprintln!("Warning: Unknown token: {}", command);
                Ok(true)
            }
        }
    }
    fn process_attribute(&mut self, token: u8) -> Result<()> {
        let type_info = token & 0xF0;
        let name = self.input.read_interned_utf()?;
        write!(self.output, " {}=\"", name)?;
        match type_info {
            TYPE_STRING => {
                let value = self.input.read_utf()?;
                write!(self.output, "{}", encode_xml_entities(&value))?;
            }
            TYPE_STRING_INTERNED => {
                let value = self.input.read_interned_utf()?;
                write!(self.output, "{}", encode_xml_entities(&value))?;
            }
            TYPE_INT => {
                let value = self.input.read_int()?;
                write!(self.output, "{}", value)?;
            }
            TYPE_INT_HEX => {
                let value = self.input.read_int()?;
                if value == -1 {
                    write!(self.output, "{}", value)?;
                } else {
                    write!(self.output, "{:x}", value as u32)?;
                }
            }
            TYPE_LONG => {
                let value = self.input.read_long()?;
                write!(self.output, "{}", value)?;
            }
            TYPE_LONG_HEX => {
                let value = self.input.read_long()?;
                if value == -1 {
                    write!(self.output, "{}", value)?;
                } else {
                    write!(self.output, "{:x}", value as u64)?;
                }
            }
            TYPE_FLOAT => {
                let value = self.input.read_float()?;
                if value.fract() == 0.0 && value.is_finite() {
                    write!(self.output, "{:.1}", value)?;
                } else {
                    write!(self.output, "{}", value)?;
                }
            }
            TYPE_DOUBLE => {
                let value = self.input.read_double()?;
                if value.fract() == 0.0 && value.is_finite() {
                    write!(self.output, "{:.1}", value)?;
                } else {
                    write!(self.output, "{}", value)?;
                }
            }
            TYPE_BOOLEAN_TRUE => {
                write!(self.output, "true")?;
            }
            TYPE_BOOLEAN_FALSE => {
                write!(self.output, "false")?;
            }
            TYPE_BYTES_HEX => {
                let length = self.input.read_short()?;
                let bytes = self.input.read_bytes(length)?;
                write!(self.output, "{}", hex::encode(&bytes))?;
            }
            TYPE_BYTES_BASE64 => {
                let length = self.input.read_short()?;
                let bytes = self.input.read_bytes(length)?;
                let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                write!(self.output, "{}", encoded)?;
            }
            _ => {
                return Err(AbxError::UnknownAttributeType(type_info));
            }
        }
        write!(self.output, "\"")?;
        Ok(())
    }
}
