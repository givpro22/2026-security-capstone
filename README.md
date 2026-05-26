# E2EE Chat (2026 Security Capstone)

종단 간 암호화 채팅 앱 프로토타입. 학습용으로 X25519 + 고정 키 페어로 시작하고, 추후 Double Ratchet / X3DH 로 확장합니다.

## 구조

```
e2ee-chat/
├── backend/        FastAPI + SQLite + WebSocket
└── frontend/       React + Vite + libsodium-wrappers
```

## 보안 모델 (현재 단계)

- 각 클라이언트가 X25519 키페어를 생성합니다.
- **개인키는 브라우저 localStorage 에만 저장**되고 서버로 전송되지 않습니다.
- 공개키만 서버에 업로드되어 상대방이 조회합니다.
- 메시지마다 새로운 랜덤 nonce 를 만들고 `crypto_box_easy` (X25519 + XSalsa20-Poly1305) 로 암호화한 뒤 서버를 통해 중계합니다.
- 서버 DB 에는 ciphertext 와 nonce 만 저장됩니다. 서버는 메시지를 복호화할 수 없습니다.

### 한계 (의도된 단순화)

- **순방향 보안 없음** — 개인키가 유출되면 과거 메시지 전체가 복호화됩니다.
- **비동기 prekey 없음** — 상대가 한 번이라도 공개키를 올린 적이 있어야 메시지 전송 가능.
- 추후 `frontend/src/crypto/ratchet.js` 에 Double Ratchet 을 구현할 예정.

## 실행 방법

### 1) 백엔드

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

서버가 `http://localhost:8000` 에서 뜹니다. SQLite 파일 `chat.db` 는 처음 기동 시 자동 생성됩니다.

### 2) 프론트엔드

```bash
cd frontend
npm install
npm run dev
```

브라우저에서 `http://localhost:5173` 로 접속합니다. Vite 의 proxy 설정으로 `/auth`, `/keys`, `/ws` 요청이 백엔드로 전달됩니다.

### 3) 테스트 시나리오

1. 브라우저 일반 창에서 `alice` 계정으로 회원가입.
2. 시크릿 창에서 `bob` 계정으로 회원가입 (개인키가 분리된 storage 에 저장되도록).
3. 양쪽 모두 로그인 상태에서, alice 사이드바에 bob 이 나타날 때 까지 잠시 대기 (5초 폴링).
4. bob 을 선택하고 메시지 전송 → bob 창에서 실시간 수신 확인.
5. bob 창을 닫고 메시지를 보낸 뒤, bob 으로 재접속 → 큐잉된 메시지 수신 확인.

## API 요약

| Method | Path | 설명 |
|---|---|---|
| POST | `/auth/register` | 회원가입, JWT 발급 |
| POST | `/auth/login` | 로그인, JWT 발급 |
| GET  | `/auth/me` | 본인 프로필 (토큰 필요) |
| POST | `/keys/me` | 공개키 업로드 (토큰 필요) |
| GET  | `/keys/{username}` | 특정 유저 공개키 조회 (토큰 필요) |
| GET  | `/keys` | 공개키 등록된 유저 목록 (토큰 필요) |
| WS   | `/ws?token=...` | 메시지 송수신 채널 |

### WebSocket 메시지 포맷

클라이언트 → 서버 (송신):
```json
{ "type": "message", "to": "bob", "ciphertext": "<base64>", "nonce": "<base64>" }
```

서버 → 클라이언트 (수신):
```json
{ "type": "message", "id": 42, "from": "alice", "ciphertext": "<base64>", "nonce": "<base64>", "created_at": "..." }
```

## 다음 단계 후보

- [ ] Double Ratchet 구현 (forward secrecy)
- [ ] X3DH prekey bundle (오프라인 첫 메시지)
- [ ] 메시지 인증된 발신자 검증 (Ed25519 서명 분리)
- [ ] 그룹 채팅 (sender keys)
- [ ] 개인키 passphrase 보호 (Argon2 derived KEK)
