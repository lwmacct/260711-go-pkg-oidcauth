package oidcauth

type SessionStatus string

const (
	SessionStatusAuthenticated SessionStatus = "authenticated"
	SessionStatusForbidden     SessionStatus = "forbidden"
	SessionStatusSignedOut     SessionStatus = "signed-out"
)

type SessionResponse struct {
	Status   SessionStatus `json:"status"`
	Identity *Identity     `json:"identity,omitempty"`
}
