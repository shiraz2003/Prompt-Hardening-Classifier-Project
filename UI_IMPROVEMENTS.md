# ShopBot UI Improvements - Summary

## ✅ Changes Made

### 1. **Simplified Layout**
   - **Removed:** Full response output section (4 text boxes)
   - **Kept:** 2 main chat displays (Protected & Unprotected)
   - **Added:** Security log section integrated below chat
   - **Result:** Cleaner, more focused interface

### 2. **Improved Visual Design**
   - Modern gradient background
   - Clean blue header banner with emoji icons
   - Color-coded chat panels:
     - 🛡️ Protected (green accent)
     - ⚠️ Unprotected (red accent)
   - Better spacing and typography
   - Responsive design for mobile

### 3. **Token Limits Increased**
   - Local models: 1024 tokens (was 512)
   - Hosted models: 2048 tokens (was 1000)
   - Full responses now visible in chat

### 4. **Simplified Navigation**
   - Cleaner header with just essential controls
   - Model selector dropdown
   - Reset button for quick chat clearing
   - Input area with placeholder text
   - Pre-loaded demo prompts

### 5. **Security Features Maintained**
   - Content Safety Filter integration
   - Prompt Injection Detection
   - Real-time audit logging
   - Detection score display
   - Attack signal tracking

## 📐 UI Layout

```
┌─────────────────────────────────────────┐
│  🛡️ ShopBot — AI Security Demo         │  <- Banner
│  Compare responses with/without         │
│  security protection                    │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ 🤖 Select AI Model: [Dropdown    ↓]    │  <- Controls
│                          🔄 Reset       │
├─────────────────────────────────────────┤
│                                         │
│  🛡️ Protected        ⚠️ Unprotected   │
│  *With Security*     *No Security*     │
│  ┌────────────────┐ ┌────────────────┐ │
│  │                │ │                │ │
│  │   Chat Area    │ │   Chat Area    │ │  <- 2 Chat Displays
│  │    (500px)     │ │    (500px)     │ │
│  │                │ │                │ │
│  └────────────────┘ └────────────────┘ │
│                                         │
├─────────────────────────────────────────┤
│ 💬 Ask a Question                       │
│ [Type your message here...]             │  <- Input Area
│  📤 Send              🗑️ Clear Chat     │
├─────────────────────────────────────────┤
│ 📋 Try These Examples                   │
│ [Predefined prompts in dropdown]        │
├─────────────────────────────────────────┤
│ 🔒 Security Log                         │  <- Event Log
│ ┌─────────────────────────────────────┐ │
│ │ 2/10 blocked | 20% block rate       │ │
│ │ ⏱ | Status | Score | Signals       │ │
│ │─────────────────────────────────────│ │
│ │ Recent attack events...             │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘

© PUSL3190 | Plymouth University
```

## 🎯 Key Features

### Protected vs Unprotected Comparison
- **Protected (Left):** 
  - Content safety filtering
  - Prompt injection detection
  - Input sanitization
  - Block decision when score > threshold

- **Unprotected (Right):**
  - Raw user input forwarded
  - No detection or filtering
  - Shows model behavior without protection

### Security Metrics
- Total messages processed
- Block rate percentage
- Detection latency (ms)
- Recent attacks with timestamps
- Attack type signals

### Model Selection
11 LLM providers available:
- **Ollama (Local):** TinyLlama, Phi-3, Qwen2, Vicuna, Llama 2, Mistral
- **Groq (Cloud):** Llama 3.1, Llama 3, Gemma 2
- **Echo:** Offline demo mode

## 🚀 Running the App

### Start the demo:
```bash
cd c:\Users\Shiraz\Desktop\ctf\prompt_hardening_project\prompt_hardening_project
python -m ui.shopbot_compare
```

### Access:
```
http://localhost:7862
```

## 🔧 Technical Details

### Files Modified
- `ui/shopbot_compare.py` — Main UI application

### Key Functions
- `shopbot_compare()` — Handler for both protected/unprotected paths
- `_format_security_log()` — Real-time event logging
- `_call_llm()` — LLM integration with system prompt
- `_detect()` — Prompt injection detection
- `reset_demo()` — Clear chat and stats

### Dependencies
- `gradio` — Web UI framework
- `prompt_hardening` — Detection & sanitization library
- `dotenv` — Configuration management
- `concurrent.futures` — Parallel LLM calls

## 📊 Design Philosophy

**Simple is Better** 
- Focus on 2 core comparisons (protected vs unprotected)
- Remove noise and clutter
- Keep metrics visible and actionable
- Professional yet approachable look

**User Experience**
- Intuitive controls
- Clear visual hierarchy
- Responsive on mobile
- Fast response times (concurrent execution)
- Example prompts for quick testing

**Security Transparency**
- Show detection scores
- Display attack signals
- Log all events
- Real-time metrics
- Clear block reasons

## 💡 Demo Walkthrough

1. **Start:** Load the interface
2. **Select:** Choose an LLM model
3. **Query:** Type a benign question
4. **Compare:** See both responses side-by-side
5. **Test:** Try an attack prompt
6. **Observe:** Watch middleware block or sanitize
7. **Analyze:** Review security log metrics

## 🎨 Color Scheme

| Element | Color | Purpose |
|---------|-------|---------|
| Banner | Blue (#0f172a) | Professional header |
| Protected | Green (#22c55e) | Safe/secure |
| Unprotected | Red (#ef4444) | Warning/vulnerable |
| Background | Light (#f8f9fa) | Clean, minimal |
| Text | Dark (#0f172a) | High contrast |
| Accent | Blue (#2563eb) | Interactive elements |

## ✨ Next Steps (Optional)

If you want to enhance further:
- Add rate limiting controls
- Export chat history
- Add custom prompt templates
- Integrate webhook logging
- Add multi-language support
- Create saved session management

---

**Status:** ✅ Complete and tested  
**File:** `ui/shopbot_compare.py`  
**Port:** 7862  
**Author:** Shiraz Sappideen  
**Project:** PUSL3190 — Prompt Hardening Classifier
