# Cloud189 天翼云盘SDK

# Requirements
- cryptography==43.0.0
- requests==2.28.2

# Usage
```python
from cloud189.client import Cloud189Client

client189 = Cloud189Client(username='xxxxxx', password='xxxxx')

client189.upload(file_path, file_name, folder_id)
client189.delete(file_id, file_name, is_folder=False)
client189.get_play_url(file_id)
```
