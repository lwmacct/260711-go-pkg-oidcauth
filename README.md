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
      - http://localhost:8080/auth/callback
    allowedConnectors:
      - github
    ssoSharedWith:
      - "*"
```

应用接入：

```go
auth, err := dexgithub.New(ctx, dexgithub.Config{
	Issuer:        "https://auth.example.com",
	ClientID:      "tool-local",
	CallbackURL:   "http://localhost:8080/auth/callback",
	PublicURL:     "http://localhost:5173",
	AfterLoginURL: "http://localhost:5173/#/console",
	AllowedUsers:  []string{"octocat"},
	SessionTTL:    24 * time.Hour,
}, dexgithub.Options{})
if err != nil {
	return err
}

mux.Handle("/auth/", auth.Handler())
mux.Handle("/api/", auth.RequireUser(api))
```

端点：

```text
GET  /auth/login
GET  /auth/callback
GET  /auth/session
POST /auth/logout
```

`RequireUser` 验证成功后将身份写入 request context：

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

授权只按规范化 GitHub 用户名匹配 `AllowedUsers`；`provider_user_id` 继续用于身份展示和审计。

## 安全边界

- discovery、JWKS、issuer、audience、expiry 与 nonce 验证；
- state 绑定发起登录的浏览器并只能消费一次；
- Authorization Code Flow 始终使用 S256 PKCE；
- public client 不发送 secret；配置 `ClientSecret` 时使用 confidential client；
- 身份 Cookie 使用 `HttpOnly`、`SameSite=Strict`，HTTPS 时使用 `Secure` 与 `__Host-` 前缀；
- 修改类请求要求 `Origin` 与 `PublicURL` 精确同源；
- `AfterLoginURL` 必须与 `PublicURL` 同源；
- 不保存 access token 或 refresh token；
- 每次请求重新执行授权器，修改白名单后现有 Cookie 立即受新策略约束。

默认 `MemoryFlowStore` 适合单实例工具。多实例部署可以实现 `FlowStore`，共享短期 state、nonce 和 PKCE verifier。

## 验证

```bash
go test ./...
go vet ./...
```
