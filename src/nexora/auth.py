"""Autenticação do Nexora: cadastro, login e bloqueio de conta."""

import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

MIN_PASSWORD_LENGTH = 8
MAX_FAILED_ATTEMPTS = 3
LOCK_DURATION = timedelta(minutes=10)
HASH_ITERATIONS = 100_000

# Mesma mensagem para e-mail inexistente e senha errada (L3).
GENERIC_ERROR = "E-mail ou senha inválidos."

_DUMMY_SALT = b"\x00" * 16


class AuthError(Exception):
    """Erro base de autenticação."""


class ValidationError(AuthError):
    """Dados de entrada inválidos (e-mail ou senha)."""


class EmailAlreadyRegisteredError(AuthError):
    """Já existe um usuário com esse e-mail."""


class InvalidCredentialsError(AuthError):
    """E-mail ou senha incorretos (sem dizer qual dos dois)."""


class AccountLockedError(AuthError):
    """Conta bloqueada temporariamente por tentativas erradas."""


def validate_email(email):
    """Valida e normaliza o e-mail. Não acessa o banco (L4)."""
    if not isinstance(email, str) or not email.strip():
        raise ValidationError("O e-mail é obrigatório.")
    email = email.strip().lower()
    local, _, domain = email.partition("@")
    if not local or not domain:
        raise ValidationError("E-mail inválido.")
    return email


def _hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, HASH_ITERATIONS
    ).hex()


class AuthService:
    def __init__(self, db_path=":memory:", clock=None):
        # clock é injetável para os testes "passarem o tempo" sem esperar.
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._sessions = {}
        self.connection = sqlite3.connect(db_path)
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT
            )
            """
        )
        self.connection.commit()

    def register(self, email, password):
        """Cadastra um usuário (L1 e L6). A senha é gravada com hash."""
        email = validate_email(email)
        if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
            raise ValidationError(
                f"A senha deve ter pelo menos {MIN_PASSWORD_LENGTH} caracteres."
            )
        salt = secrets.token_bytes(16)
        try:
            self.connection.execute(
                "INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)",
                (email, _hash_password(password, salt), salt.hex()),
            )
            self.connection.commit()
        except sqlite3.IntegrityError:
            raise EmailAlreadyRegisteredError("E-mail já cadastrado.") from None

    def login(self, email, password):
        """Autentica o usuário (L2, L3, L4 e L5). Retorna e-mail e token."""
        email = validate_email(email)
        password = password if isinstance(password, str) else ""
        now = self._clock()

        row = self.connection.execute(
            "SELECT password_hash, salt, failed_attempts, locked_until "
            "FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if row is None:
            _hash_password(password, _DUMMY_SALT)  # custo parecido com o de um usuário real
            raise InvalidCredentialsError(GENERIC_ERROR)

        stored_hash, salt, failed_attempts, locked_until = row

        if locked_until and datetime.fromisoformat(locked_until) > now:
            raise AccountLockedError(
                "Conta bloqueada temporariamente. Tente novamente mais tarde."
            )

        candidate = _hash_password(password, bytes.fromhex(salt))
        if not hmac.compare_digest(candidate, stored_hash):
            failed_attempts += 1
            if failed_attempts >= MAX_FAILED_ATTEMPTS:
                self.connection.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = ? "
                    "WHERE email = ?",
                    ((now + LOCK_DURATION).isoformat(), email),
                )
            else:
                self.connection.execute(
                    "UPDATE users SET failed_attempts = ? WHERE email = ?",
                    (failed_attempts, email),
                )
            self.connection.commit()
            raise InvalidCredentialsError(GENERIC_ERROR)

        self.connection.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL "
            "WHERE email = ?",
            (email,),
        )
        self.connection.commit()

        token = secrets.token_urlsafe(32)
        self._sessions[token] = email
        return {"email": email, "token": token}

    def user_from_token(self, token):
        """Devolve o e-mail do usuário dono do token, ou None."""
        return self._sessions.get(token)
