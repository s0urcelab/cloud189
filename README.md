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
file_list = client.get_all_files(folder_id)

# Download file
download_url = client.download(file_id)

# Upload file
file_id = client.upload(file_path, folder_id, rename)

# Delete file
client.delete(file_id, file_name, is_folder=False)

# Get media play url
media_url = client.get_play_url(file_id)

# Get cloud disk space info 
info = client.get_disk_space_info()

```

## Features

- Login to Cloud189
- List files and folders
- Download files
- Upload files
- Delete files/folders
- Automatic retry mechanism for token expiration
- Configurable retry count

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
