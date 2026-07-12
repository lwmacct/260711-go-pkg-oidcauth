# oidcauth

`oidcauth` 为 Go Web 工具提供 OIDC Authorization Code 登录、S256 PKCE、HttpOnly 身份 Cookie 和 API 鉴权 middleware。

包分为两层：

- `pkg/oidcauth`：provider-neutral OIDC 核心，通过 `IdentityMapper` 与 `Authorizer` 接入身份源和授权策略。
- `pkg/oidcauth/dexgithub`：Dex GitHub connector 预设，保留 GitHub 数字用户 ID，并按配置中的 GitHub 用户名授权。

## Dex GitHub

Dex client 使用 public client，无需 client secret：

```yaml
staticClients:
  - id: tool-local
    name: Tool Local
    public: true
    redirectURIs:
      - http://localhost:8080/oidcauth/callback

  - id: tool-production
    name: Tool Production
    public: true
    redirectURIs:
      - https://tool.example.com/oidcauth/callback
      - https://tool-alt.example.com/oidcauth/callback
```

应用接入：

```go
auth, err := dexgithub.New(ctx, dexgithub.Config{
	Issuer:       "https://auth.example.com",
	ClientID:     "tool-local",
	ExternalURLs: []string{"http://localhost:5173"},
	AllowedUsers: []string{"octocat"},
	SessionTTL:   24 * time.Hour,
}, dexgithub.Options{})
if err != nil {
	return err
}

mux.Handle("/oidcauth/", auth.Handler())
mux.Handle("/api/", auth.RequireAccess(api))
```

端点：

```text
GET  /oidcauth/login
GET  /oidcauth/callback
GET  /oidcauth/session
POST /oidcauth/logout
```

`ExternalURLs` 是部署时可信的浏览器 origin 列表。每个 callback 固定派生为
`<external-url>/oidcauth/callback`，Dex client 必须注册全部地址。登录时根据请求 Host 从该白名单选择
`redirect_uri`，回调必须返回发起登录的同一 origin。登录入口可以携带经过严格校验的同源路径，例如
`/oidcauth/login?return_to=%2F%23%2Fsettings`；登录成功后恢复该位置，缺省回到 `/`。

不同注册域名使用独立的 Host-only Cookie，不共享浏览器会话；用户在每个域名首次访问时分别登录。

`RequireAuthenticated` 只验证身份，`RequireAccess` 还执行配置的 `Authorizer`。两者验证成功后都将身份写入 request context：

```go
identity, ok := oidcauth.IdentityFromContext(r.Context())
```

Dex GitHub 身份形状：

```json
{
  "subject": "...",
  "username": "octocat",
  "name": "The Octocat",
  "provider": "github",
  "provider_user_id": "583231",
  "avatar_url": "https://avatars.githubusercontent.com/u/583231?v=4"
}
```

`GET /oidcauth/session` 是状态查询端点，三种正常会话状态都返回 `200`：

```json
{"status":"signed-out"}
```

```json
{"status":"authenticated","access":"denied","identity":{"username":"octocat"}}
```

```json
{"status":"authenticated","access":"granted","identity":{"username":"octocat"}}
```

受 `RequireAccess` 保护的业务端点仍使用 `401` 和 `403` 表达认证、授权失败。OIDC callback 只完成认证；授权失败的身份同样写入 Host-only Cookie，然后由应用展示当前账号和拒绝访问状态。

授权只按规范化 GitHub 用户名匹配 `AllowedUsers`；`provider_user_id` 继续用于身份展示和审计。

## 安全边界

- discovery、JWKS、issuer、audience、expiry 与 nonce 验证；
- state 绑定发起登录的浏览器并只能消费一次；
- Authorization Code Flow 始终使用 S256 PKCE；
- public client 不发送 secret；配置 `ClientSecret` 时使用 confidential client；
- 身份 Cookie 使用 `HttpOnly`、`SameSite=Strict`，HTTPS 时使用 `Secure` 与 `__Host-` 前缀；
- 修改类请求要求 `Origin` 与当前请求 Host 对应的可信 `ExternalURLs` 项精确同源；
- `return_to` 只接受同源绝对路径，并绑定到一次性登录 flow；
- 不保存 access token 或 refresh token；
- 每次请求重新执行授权器，修改白名单后现有 Cookie 立即受新策略约束。

默认 `MemoryFlowStore` 适合单实例工具。多实例部署可以实现 `FlowStore`，共享短期 state、nonce 和 PKCE verifier。

## 验证

```bash
go test ./...
go vet ./...
```
