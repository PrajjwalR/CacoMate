package handlers

import (
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shridarpatil/whatomate/internal/models"
	"github.com/valyala/fasthttp"
	"github.com/zerodha/fastglue"
	"golang.org/x/crypto/bcrypt"
)

// CacoSSOClaims are the JWT claims from caco-marketing-tool SSO tokens
type CacoSSOClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// CacoSSO handles the cross-app SSO login from caco-marketing-tool.
// The user is redirected here with a short-lived signed JWT in the query string.
// We validate it, find or create the user, set auth cookies, and redirect to dashboard.
//
// GET /api/auth/caco-sso?token=<signed-jwt>
func (a *App) CacoSSO(r *fastglue.Request) error {
	if a.Config.CacoSSO.Secret == "" {
		a.Log.Error("CacoSSO called but caco_sso.secret is not configured")
		return r.SendErrorEnvelope(fasthttp.StatusServiceUnavailable, "SSO is not configured on this server", nil, "")
	}

	tokenStr := string(r.RequestCtx.QueryArgs().Peek("token"))
	if tokenStr == "" {
		return r.SendErrorEnvelope(fasthttp.StatusBadRequest, "Missing SSO token", nil, "")
	}

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenStr, &CacoSSOClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(a.Config.CacoSSO.Secret), nil
	})
	if err != nil || !token.Valid {
		a.Log.Warn("CacoSSO: invalid or expired token", "error", err)
		return r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Invalid or expired SSO token", nil, "")
	}

	claims, ok := token.Claims.(*CacoSSOClaims)
	if !ok || claims.Email == "" {
		return r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Invalid token claims", nil, "")
	}

	email := strings.ToLower(strings.TrimSpace(claims.Email))

	// Look up the user
	var user models.User
	err = a.DB.Preload("Role").Where("email = ?", email).First(&user).Error
	if err != nil {
		// User doesn't exist yet — auto-create them
		a.Log.Info("CacoSSO: auto-provisioning new user", "email", email)
		user, err = a.provisionCacoUser(email)
		if err != nil {
			a.Log.Error("CacoSSO: failed to provision user", "email", email, "error", err)
			return r.SendErrorEnvelope(fasthttp.StatusInternalServerError, "Failed to provision user account", nil, "")
		}
	}

	if !user.IsActive {
		return r.SendErrorEnvelope(fasthttp.StatusUnauthorized, "Account is disabled", nil, "")
	}

	// Generate Whathub auth tokens and set cookies
	accessToken, err := a.generateAccessToken(&user)
	if err != nil {
		a.Log.Error("CacoSSO: failed to generate access token", "error", err)
		return r.SendErrorEnvelope(fasthttp.StatusInternalServerError, "Failed to generate session", nil, "")
	}

	refreshToken, err := a.generateRefreshToken(&user)
	if err != nil {
		a.Log.Error("CacoSSO: failed to generate refresh token", "error", err)
		return r.SendErrorEnvelope(fasthttp.StatusInternalServerError, "Failed to generate session", nil, "")
	}

	a.setAuthCookies(r, accessToken, refreshToken)

	// Redirect to the Whathub dashboard
	basePath := a.Config.Server.BasePath
	r.RequestCtx.Redirect(basePath+"/", fasthttp.StatusFound)
	return nil
}

// provisionCacoUser creates a new Whathub user for a caco-marketing-tool user.
// It adds them to the default (first) organization with the agent role.
func (a *App) provisionCacoUser(email string) (models.User, error) {
	// Find the default organization (first org created)
	var org models.Organization
	if err := a.DB.Order("created_at ASC").First(&org).Error; err != nil {
		return models.User{}, fmt.Errorf("no organization found: %w", err)
	}

	// Find the default agent role for this org
	var defaultRole models.CustomRole
	if err := a.DB.Where("organization_id = ? AND is_default = ?", org.ID, true).First(&defaultRole).Error; err != nil {
		// Fall back to the system "agent" role
		if err2 := a.DB.Where("organization_id = ? AND name = ? AND is_system = ?", org.ID, "agent", true).First(&defaultRole).Error; err2 != nil {
			return models.User{}, fmt.Errorf("no default role found: %w", err2)
		}
	}

	// Generate a random secure password (user will never need it; they log in via SSO)
	randomPassword := uuid.New().String() + uuid.New().String()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(randomPassword), bcrypt.DefaultCost)
	if err != nil {
		return models.User{}, fmt.Errorf("failed to hash password: %w", err)
	}

	// Derive display name from email (e.g. "john.doe@example.com" → "john.doe")
	fullName := strings.Split(email, "@")[0]

	tx := a.DB.Begin()
	if tx.Error != nil {
		return models.User{}, fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}

	user := models.User{
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   string(hashedPassword),
		FullName:       fullName,
		RoleID:         &defaultRole.ID,
		IsActive:       true,
	}

	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		return models.User{}, fmt.Errorf("failed to create user: %w", err)
	}

	userOrg := models.UserOrganization{
		UserID:         user.ID,
		OrganizationID: org.ID,
		RoleID:         &defaultRole.ID,
		IsDefault:      true,
	}
	if err := tx.Create(&userOrg).Error; err != nil {
		tx.Rollback()
		return models.User{}, fmt.Errorf("failed to create user-org link: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return models.User{}, fmt.Errorf("failed to commit: %w", err)
	}

	user.Role = &defaultRole
	a.Log.Info("CacoSSO: provisioned new user", "email", email, "user_id", user.ID, "org_id", org.ID)
	return user, nil
}

// GenerateCacoSSOToken is a helper to generate a signed SSO token for testing.
// This is only intended for use in development/testing.
func GenerateCacoSSOToken(email, secret string, expiry time.Duration) (string, error) {
	claims := CacoSSOClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "caco-marketing-tool",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
