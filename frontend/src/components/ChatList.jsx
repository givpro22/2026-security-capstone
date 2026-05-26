export default function ChatList({ users, selected, onSelect, me, onLogout }) {
  return (
    <div className="sidebar">
      <div style={{ marginBottom: 12 }}>
        <div style={{ fontWeight: 600 }}>{me.username}</div>
        <button
          onClick={onLogout}
          style={{ marginTop: 4, fontSize: 12, padding: '4px 8px' }}
        >
          로그아웃
        </button>
      </div>
      <div className="muted" style={{ marginBottom: 8 }}>
        대화 상대 ({users.length})
      </div>
      {users.length === 0 && (
        <div className="muted">
          다른 사용자가 회원가입하고 키를 등록하면 여기에 표시됩니다.
        </div>
      )}
      {users.map((u) => (
        <div
          key={u.username}
          className={`user ${selected === u.username ? 'active' : ''}`}
          onClick={() => onSelect(u)}
        >
          {u.username}
        </div>
      ))}
    </div>
  )
}
