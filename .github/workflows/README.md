# Secure REST API Development and CVE Vulnerability Analysis

## Part 1: Secure REST API
本项目使用 Python/Flask 开发了一个安全的 REST API。
- **端点 1**: `POST /auth/login` - 用户认证，成功返回 JWT token。
- **端点 2**: `GET /api/data` - 受保护的数据接口，必须携带有效 JWT 才能访问。
- **端点 3**: `GET /api/profile` - 获取当前登录用户信息。
- **安全措施**:
  - SQLi 防护：使用参数化查询（`?` 占位符），未使用字符串拼接。
  - XSS 防护：对 API 返回的用户数据使用 `escape()` 进行转义。
  - 认证安全：密码使用 bcrypt 哈希存储；使用 JWT 进行身份校验，并编写了中间件拦截未授权访问。

## Part 2: CI/CD Security Scans
使用 GitHub Actions 配置了自动化的安全扫描，每次 push 触发。
- **SAST**: Bandit（静态代码分析）。
- **SCA**: Safety（依赖库漏洞扫描）。

![CI Success](这里拖入你刚才截的绿勾图，或者把图片放在仓库里引用)
*上图显示了流水线成功运行且生成了 security-reports。*

## Part 3: CVE Vulnerability Reproduction & Remediation

### 1. 漏洞信息
- **CVE ID**: CVE-2017-7529 (Nginx 越界读取内存漏洞)
- **受影响版本**: Nginx 0.5.6 至 1.13.2
- **描述**: Nginx 在处理 HTTP Range 头时存在整数溢出漏洞，攻击者可构造特殊的负数字节范围，读取到服务器缓存中的非预期内存数据（包括 HTTP 响应头等敏感信息）。

### 2. 复现攻击
启动 Vulhub 提供的漏洞环境（Nginx 1.13.2），运行官方提供的 POC 脚本：
`python poc.py http://localhost:8080/`

**攻击结果截图**:
![漏洞复现成功](这里拖入你刚才看到 `HTTP/1.1 200 OK` 的截图)
*截图证明成功越界读取到了服务器的内部响应头信息。*

### 3. 根因分析
该漏洞的根本原因在于 Nginx 的 `ngx_http_range_filter_module` 模块在解析 `Range` 请求头时，未能正确处理负数的偏移量。由于没有进行严格的边界检查，导致整数溢出，攻击者可以通过构造类似于 `bytes=-605,-9223372036854774591` 的恶意请求，使得 Nginx 越界读取缓存文件头部的内容并返回给客户端。

### 4. 修复与验证
**修复方式**: 在 `docker-compose.yml` 中将镜像版本从 `1.13.2` 升级到 `1.13.3`（官方修复版本），然后重新构建容器。

**修复后验证截图**:
![修复后攻击失效](这里拖入你修复后运行脚本的截图)
*截图证明攻击请求不再返回任何内部头部信息，漏洞已被成功消除，且 Nginx 正常服务未受影响。*