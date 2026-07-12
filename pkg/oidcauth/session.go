package oidcauth

type SessionStatus string
type AccessStatus string

const (
	SessionStatusAuthenticated SessionStatus = "authenticated"
	SessionStatusSignedOut     SessionStatus = "signed-out"

	AccessStatusGranted AccessStatus = "granted"
	AccessStatusDenied  AccessStatus = "denied"
)

type SessionResponse struct {
	Status   SessionStatus `json:"status"`
	Access   AccessStatus  `json:"access,omitempty"`
	Identity *Identity     `json:"identity,omitempty"`
}
