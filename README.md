# Cloud189

A Python SDK for interacting with Cloud189 (天翼云盘).

## Installation

```bash
pip install cloud189
```

## Usage

```python
from cloud189 import Cloud189

# Init & Login the client 
client = Cloud189({
    'username': 'your_username',
    'password': 'your_password'
})

# List files
client.get_all_files(folder_id)

# Upload file
client.upload(file_path, folder_id, rename)

# Delete file
client.delete(file_id, file_name, is_folder=False)

# Get media play url
client.get_play_url(file_id)

# Get cloud disk space info 
client.get_user_size_info()

```

## Features

- Login to Cloud189
- List files and folders
- Upload files
- Delete files/folders

## License

This project is licensed under the MIT License - see the LICENSE file for details. 