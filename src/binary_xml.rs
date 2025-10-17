use crate::{ATTRIBUTE, COMMENT, DOCDECL, IGNORABLE_WHITESPACE, PROCESSING_INSTRUCTION};
use crate::{AbxError, PROTOCOL_MAGIC_VERSION_0, Result};
use crate::{CDSECT, END_DOCUMENT, END_TAG, ENTITY_REF, START_DOCUMENT, START_TAG, TEXT};
use crate::{TYPE_BOOLEAN_FALSE, TYPE_BOOLEAN_TRUE};
use crate::{TYPE_BYTES_BASE64, TYPE_BYTES_HEX, TYPE_STRING, TYPE_STRING_INTERNED};
use crate::{TYPE_DOUBLE, TYPE_FLOAT, TYPE_INT, TYPE_INT_HEX, TYPE_LONG, TYPE_LONG_HEX};
use base64::Engine;
use hex;
use std::io::{Read, Write};

// ===== DATA INPUT STREAM =====

/// A streaming input reader for binary XML data with peek-ahead capability.
///
/// This struct handles reading various data types from the binary stream and maintains
/// a table of interned strings for efficient string reuse. It supports peeking at the
/// next byte without consuming it, which is essential for lookahead parsing.
///
/// # Type Parameters
///
/// * `R` - Any type implementing `Read` (files, stdin, in-memory buffers, etc.)
///
/// # Examples
///
/// ```ignore
/// use std::io::Cursor;
/// let data = vec![0x41, 0x42, 0x58, 0x00]; // ABX magic header
/// let mut input = DataInput::new(Cursor::new(data));
/// let byte = input.read_byte()?;
/// ```
pub struct DataInput<R: Read> {
    /// The underlying reader for the binary stream
    reader: R,
    /// Cache of interned strings for memory efficiency
    interned_strings: Vec<String>,
    /// Single-byte buffer for peek operations
    peeked_byte: Option<u8>,
}

impl<R: Read> DataInput<R> {
    /// Creates a new `DataInput` from any readable source.
    ///
    /// # Arguments
    ///
    /// * `reader` - Any type implementing `Read` (e.g., `File`, `Stdin`, `Cursor`)
    ///
    /// # Returns
    ///
    /// A new `DataInput` instance ready for reading binary XML data
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            interned_strings: Vec::new(),
            peeked_byte: None,
        }
    }

    /// Reads a single byte from the stream.
    ///
    /// If a byte has been peeked, it returns that byte and clears the peek buffer.
    /// Otherwise, it reads the next byte from the underlying stream.
    ///
    /// # Returns
    ///
    /// * `Ok(u8)` - The next byte in the stream
    /// * `Err(AbxError)` - If the read operation fails
    ///
    /// # Errors
    ///
    /// Returns `AbxError::ReadError` if the underlying stream cannot be read
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

    /// Peeks at the next byte without consuming it.
    ///
    /// This allows lookahead parsing without seeking. The peeked byte is cached
    /// and will be returned by the next call to `read_byte()`.
    ///
    /// # Returns
    ///
    /// * `Ok(u8)` - The next byte that will be read
    /// * `Err(AbxError)` - If the peek operation fails
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let next = input.peek_byte()?; // Look ahead
    /// if next == ATTRIBUTE {
    ///     let byte = input.read_byte()?; // Consume it
    /// }
    /// ```
    pub fn peek_byte(&mut self) -> Result<u8> {
        if let Some(byte) = self.peeked_byte {
            return Ok(byte);
        }

        let byte = self.read_byte()?;
        self.peeked_byte = Some(byte);
        Ok(byte)
    }

    /// Reads a 16-bit unsigned short (big-endian).
    ///
    /// Handles the case where a byte has been peeked by incorporating it
    /// into the short value.
    ///
    /// # Returns
    ///
    /// * `Ok(u16)` - The 16-bit value
    /// * `Err(AbxError)` - If the read fails
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

    /// Reads a 32-bit signed integer (big-endian).
    ///
    /// # Returns
    ///
    /// * `Ok(i32)` - The 32-bit signed integer
    /// * `Err(AbxError)` - If the read fails
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

    /// Reads a 64-bit signed long integer (big-endian).
    ///
    /// # Returns
    ///
    /// * `Ok(i64)` - The 64-bit signed integer
    /// * `Err(AbxError)` - If the read fails
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

    /// Reads a 32-bit IEEE 754 floating-point number.
    ///
    /// # Returns
    ///
    /// * `Ok(f32)` - The floating-point value
    /// * `Err(AbxError)` - If the read fails
    pub fn read_float(&mut self) -> Result<f32> {
        let int_value = self.read_int()? as u32;
        Ok(f32::from_bits(int_value))
    }

    /// Reads a 64-bit IEEE 754 double-precision floating-point number.
    ///
    /// # Returns
    ///
    /// * `Ok(f64)` - The double-precision floating-point value
    /// * `Err(AbxError)` - If the read fails
    pub fn read_double(&mut self) -> Result<f64> {
        let int_value = self.read_long()? as u64;
        Ok(f64::from_bits(int_value))
    }

    /// Reads a UTF-8 encoded string.
    ///
    /// The string is prefixed with a 16-bit length, followed by that many bytes
    /// of UTF-8 encoded text.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The decoded UTF-8 string
    /// * `Err(AbxError)` - If the read fails or the data is not valid UTF-8
    pub fn read_utf(&mut self) -> Result<String> {
        let length = self.read_short()?;
        let mut buffer = vec![0u8; length as usize];
        self.reader
            .read_exact(&mut buffer)
            .map_err(|_| AbxError::ReadError("UTF string".to_string()))?;
        String::from_utf8(buffer)
            .map_err(|_| AbxError::ReadError("UTF string (invalid UTF-8)".to_string()))
    }

    /// Reads a string from the interned string table or adds a new one.
    ///
    /// If the index is `0xFFFF`, a new string is read and added to the intern table.
    /// Otherwise, the string at the given index is retrieved from the table.
    ///
    /// This mechanism reduces memory usage and file size for frequently repeated strings.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The interned string
    /// * `Err(AbxError)` - If the index is invalid or read fails
    ///
    /// # Errors
    ///
    /// Returns `AbxError::InvalidInternedStringIndex` if the index doesn't exist in the table
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

    /// Reads a specified number of raw bytes.
    ///
    /// # Arguments
    ///
    /// * `length` - The number of bytes to read
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - The raw bytes
    /// * `Err(AbxError)` - If the read fails
    pub fn read_bytes(&mut self, length: u16) -> Result<Vec<u8>> {
        let mut data = vec![0u8; length as usize];
        self.reader
            .read_exact(&mut data)
            .map_err(|_| AbxError::ReadError("bytes".to_string()))?;
        Ok(data)
    }

    /// Returns a reference to the interned strings table.
    ///
    /// Useful for debugging or inspection purposes.
    ///
    /// # Returns
    ///
    /// A slice containing all interned strings read so far
    pub fn interned_strings(&self) -> &[String] {
        &self.interned_strings
    }
}

// ===== XML ENTITY ENCODING =====

/// Encodes special XML characters to their entity equivalents.
///
/// This function ensures that XML content is properly escaped to prevent
/// parsing errors and security issues.
///
/// # Arguments
///
/// * `text` - The raw text to encode
///
/// # Returns
///
/// A new `String` with XML entities properly encoded
///
/// # Encoding Rules
///
/// * `&` → `&amp;`
/// * `<` → `&lt;`
/// * `>` → `&gt;`
/// * `"` → `&quot;`
/// * `'` → `&apos;`
///
/// # Examples
///
/// ```ignore
/// let encoded = encode_xml_entities("5 < 10 & 10 > 5");
/// assert_eq!(encoded, "5 &lt; 10 &amp; 10 &gt; 5");
/// ```
pub fn encode_xml_entities(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ===== BINARY XML DESERIALIZER =====

/// Deserializes Android Binary XML (ABX) format to standard XML.
///
/// This struct handles the conversion of the compact binary format used by Android
/// into human-readable XML text. It processes tokens sequentially and writes the
/// corresponding XML syntax to the output writer.
///
/// # Type Parameters
///
/// * `R` - Input source implementing `Read` (files, stdin, buffers, etc.)
/// * `W` - Output destination implementing `Write` (files, stdout, buffers, etc.)
///
/// # Binary Format
///
/// The ABX format consists of:
/// * 4-byte magic header (`ABX\0`)
/// * Token stream with embedded type information
/// * Interned string table for memory efficiency
///
/// # Examples
///
/// ```ignore
/// use std::fs::File;
/// use std::io::BufWriter;
///
/// let input = File::open("input.abx")?;
/// let output = BufWriter::new(File::create("output.xml")?);
///
/// let mut deserializer = BinaryXmlDeserializer::new(input, output)?;
/// deserializer.deserialize()?;
/// ```
pub struct BinaryXmlDeserializer<R: Read, W: Write> {
    /// Input stream reader with interning support
    input: DataInput<R>,
    /// Output XML writer
    output: W,
}

impl<R: Read, W: Write> BinaryXmlDeserializer<R, W> {
    /// Creates a new deserializer and validates the magic header.
    ///
    /// This constructor reads and validates the 4-byte magic header (`ABX\0`)
    /// to ensure the input is a valid ABX file.
    ///
    /// # Arguments
    ///
    /// * `reader` - The input source containing ABX data
    /// * `output` - The output destination for XML text
    ///
    /// # Returns
    ///
    /// * `Ok(BinaryXmlDeserializer)` - A new deserializer ready to process
    /// * `Err(AbxError)` - If the magic header is invalid or read fails
    ///
    /// # Errors
    ///
    /// * `AbxError::InvalidMagicHeader` - If the file doesn't start with `ABX\0`
    /// * `AbxError::ReadError` - If reading the header fails
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

    /// Deserializes the entire binary XML stream to text XML.
    ///
    /// This method processes tokens sequentially until either:
    /// * An `END_DOCUMENT` token is encountered
    /// * An error occurs
    /// * The end of the stream is reached
    ///
    /// The XML declaration is automatically written at the start.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If deserialization completes successfully
    /// * `Err(AbxError)` - If an error occurs during processing
    ///
    /// # Processing
    ///
    /// The deserializer:
    /// 1. Writes the XML declaration
    /// 2. Processes tokens in a loop
    /// 3. Handles errors gracefully (logs warnings and continues or stops)
    /// 4. Stops on `END_DOCUMENT` or stream end
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
                    // End of stream reached
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

    /// Processes a single token from the binary stream.
    ///
    /// Each token consists of:
    /// * 4 bits: command type (START_TAG, END_TAG, TEXT, etc.)
    /// * 4 bits: data type information (for attributes and text)
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Token processed successfully, continue parsing
    /// * `Ok(false)` - END_DOCUMENT encountered, stop parsing
    /// * `Err(AbxError)` - Processing error occurred
    ///
    /// # Token Types
    ///
    /// * `START_TAG` - Opening XML tag (e.g., `<element>`)
    /// * `END_TAG` - Closing XML tag (e.g., `</element>`)
    /// * `TEXT` - Text content
    /// * `CDSECT` - CDATA section
    /// * `COMMENT` - XML comment
    /// * `PROCESSING_INSTRUCTION` - PI (e.g., `<?xml?>`)
    /// * `DOCDECL` - DOCTYPE declaration
    /// * `ENTITY_REF` - Entity reference (e.g., `&nbsp;`)
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

                // Process attributes by peeking ahead
                loop {
                    match self.input.peek_byte() {
                        Ok(next_token) => {
                            if (next_token & 0x0F) == ATTRIBUTE {
                                // Consume the peeked byte
                                let _ = self.input.read_byte()?;
                                self.process_attribute(next_token)?;
                            } else {
                                // Not an attribute, leave it for next iteration
                                break;
                            }
                        }
                        Err(_) => {
                            // End of stream or error
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

    /// Processes an XML attribute and writes it to the output.
    ///
    /// Attributes are encoded with their data type in the upper 4 bits of the token.
    /// This method reads the attribute name and value, then formats them as XML.
    ///
    /// # Arguments
    ///
    /// * `token` - The attribute token byte (contains type information)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Attribute processed and written successfully
    /// * `Err(AbxError)` - Processing error occurred
    ///
    /// # Supported Attribute Types
    ///
    /// * `TYPE_STRING` - Plain UTF-8 string
    /// * `TYPE_STRING_INTERNED` - Reference to interned string
    /// * `TYPE_INT` - 32-bit signed integer (decimal)
    /// * `TYPE_INT_HEX` - 32-bit integer (hexadecimal, except -1)
    /// * `TYPE_LONG` - 64-bit signed integer (decimal)
    /// * `TYPE_LONG_HEX` - 64-bit integer (hexadecimal, except -1)
    /// * `TYPE_FLOAT` - 32-bit floating-point
    /// * `TYPE_DOUBLE` - 64-bit floating-point
    /// * `TYPE_BOOLEAN_TRUE` - Boolean true value
    /// * `TYPE_BOOLEAN_FALSE` - Boolean false value
    /// * `TYPE_BYTES_HEX` - Raw bytes encoded as hexadecimal
    /// * `TYPE_BYTES_BASE64` - Raw bytes encoded as Base64
    ///
    /// # Errors
    ///
    /// Returns `AbxError::UnknownAttributeType` if the type is not recognized
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