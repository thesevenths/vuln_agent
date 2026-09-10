## WebGoat Java Web 路由索引（185 条）

- **GET**: 53 条
- **ANY**: 18 条
- **POST**: 110 条
- **DELETE**: 2 条
- **PUT**: 2 条

高危路由示例：
- `POST /fileupload` → `FileServer.uploadFile()`
- `GET /jwt` → `JWTController.jwt()`
- `POST /attack` → `HammerHead.attack()`
- `GET /files` → `FileServer.getFiles()`

完整路由列表见 `metadata.java_routes`。