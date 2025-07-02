# abx2xml-rs
Rust Library to Decode Android Binary XML ( ABX )


## CLI Installation
```bash
cargo install abx2xml
```

## CLI Usage
```bash
Usage: abx2xml [OPTIONS] <input> [output]

Arguments:
  <input>   Input file path (use '-' for stdin)
  [output]  Output file path (use '-' for stdout)

Options:
  -i, --in-place  Overwrite input file with converted output
```

## Library Usage

```rust
use abx2xml::AbxToXmlConverter;
use std::fs::File;

// Convert file to file
AbxToXmlConverter::convert_file("input.abx", "output.xml")?;

// Convert using readers/writers
let input = File::open("input.abx")?;
let output = File::create("output.xml")?;
AbxToXmlConverter::convert(input, output)?;
```


```rust
use abx2xml::AbxToXmlConverter;

// Convert from byte slice
let abx_data = std::fs::read("input.abx")?;
let xml_string = AbxToXmlConverter::convert_bytes(&abx_data)?;
println!("{}", xml_string);

// Convert from Vec<u8>
let abx_data = std::fs::read("input.abx")?;
let xml_string = AbxToXmlConverter::convert_vec(abx_data)?;
println!("{}", xml_string);
```

```rust
use abx2xml::{BinaryXmlDeserializer, SeekableReader};
use std::io::{stdin, stdout};

// Using the lower-level deserializer directly
let stdin = stdin();
let reader = SeekableReader::new(stdin.lock());
let writer = stdout();

let mut deserializer = BinaryXmlDeserializer::new(reader, writer)?;
deserializer.deserialize()?;
```

### Sources
- [BinaryXmlPullParser.java](https://cs.android.com/android/platform/superproject/+/master:frameworks/base/core/java/com/android/internal/util/BinaryXmlPullParser.java;bpv=0)


### License
This project is licensed under
- Apache License, Version 2.0

