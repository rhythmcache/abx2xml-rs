use crate::{BinaryXmlDeserializer, Result};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};

pub struct AbxToXmlConverter;

impl AbxToXmlConverter {
    /// generic conversion for any Read + Write
    pub fn convert<R: Read, W: Write>(reader: R, writer: W) -> Result<()> {
        let mut deserializer = BinaryXmlDeserializer::new(reader, writer)?;
        deserializer.deserialize()
    }

    /// convert file to file
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

    /// convert stdin to stdout
    pub fn convert_stdin_stdout() -> Result<()> {
        let stdin = io::stdin();
        let reader = stdin.lock();

        let stdout = io::stdout();
        let writer = BufWriter::new(stdout.lock());

        Self::convert(reader, writer)
    }

    /// convert stdin to file
    pub fn convert_stdin_to_file(output_path: &str) -> Result<()> {
        let stdin = io::stdin();
        let reader = stdin.lock();

        let output_file = File::create(output_path)?;
        let writer = BufWriter::new(output_file);

        Self::convert(reader, writer)
    }

    /// convert file to stdout
    pub fn convert_file_to_stdout(input_path: &str) -> Result<()> {
        let input_file = File::open(input_path)?;
        let reader = BufReader::new(input_file);

        let writer = io::stdout();

        Self::convert(reader, writer)
    }

    /// in place conversion (read entire file, convert, write back)
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

    /// convert bytes to string
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

    /// convert vec to string
    pub fn convert_vec(abx_data: Vec<u8>) -> Result<String> {
        Self::convert_bytes(&abx_data)
    }
}