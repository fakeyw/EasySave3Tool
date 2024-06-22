Usage:
```bash
# decrypt es3 file to json-like text
python es3_cipher_tool.py decrypt [input_file] [output_file] [key]
# encrypt back to es3 file
python es3_cipher_tool.py encrypt [input_file] [output_file] [key]
# fix json-like text to parseable json
python es3_cipher_tool.py es3_to_json [input_file] [output_file]
# recovery to json-like format
python es3_cipher_tool.py json_to_es3 [input_file [output_file]
```

Examples:

- `Example.sfh` is a Strike Force Heroes save file

```bash
python es3_cipher_tool.py decrypt Example.sfh Example.sfh.dec ADFT4rq4rFQR
python es3_cipher_tool.py es3_to_json Example.sfh.dec Example.sfh.json
python es3_cipher_tool.py json_to_es3 Example.sfh.json Example-repack.sfh.dec
python es3_cipher_tool.py encrypt Example-repack.sfh.dec Example-repack.sfh ADFT4rq4rFQR
```
