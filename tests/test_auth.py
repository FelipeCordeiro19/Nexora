
from datetime import datetime, timedelta, timezone

import pytest

from nexora.auth import (
    AccountLockedError,
    AuthService,
    EmailAlreadyRegisteredError,
    InvalidCredentialsError,
    ValidationError,
)

EMAIL = "ana@exemplo.com"
SENHA = "senha-segura-123"
SENHA_ERRADA = "senha-errada-999"


class FakeClock:
    """Relógio controlável: permite 'passar o tempo' sem esperar de verdade."""

    def __init__(self):
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def service(clock):
    return AuthService(clock=clock)


def test_t1_cadastro_valido_grava_senha_com_hash(service):
    service.register(EMAIL, SENHA)

    row = service.connection.execute(
        "SELECT password_hash FROM users WHERE email = ?", (EMAIL,)
    ).fetchone()
    assert row is not None
    assert row[0] != SENHA
    assert SENHA not in row[0]


def test_t2_login_correto_retorna_sucesso(service):
    service.register(EMAIL, SENHA)

    result = service.login(EMAIL, SENHA)

    assert result["email"] == EMAIL
    assert result["token"]
    assert service.user_from_token(result["token"]) == EMAIL


def test_t3_senha_errada_retorna_erro_sem_revelar_o_motivo(service):
    service.register(EMAIL, SENHA)

    with pytest.raises(InvalidCredentialsError) as senha_errada:
        service.login(EMAIL, SENHA_ERRADA)
    with pytest.raises(InvalidCredentialsError) as email_inexistente:
        service.login("outra@exemplo.com", SENHA)

    assert str(senha_errada.value) == str(email_inexistente.value)


@pytest.mark.parametrize(
    "email", [None, "", "   ", "semarroba.com", "@dominio.com", "usuario@"]
)
def test_t4_email_invalido_e_rejeitado_antes_de_consultar_o_banco(service, email):
    service.connection.close()  # qualquer consulta ao banco quebraria

    with pytest.raises(ValidationError):
        service.login(email, SENHA)
    with pytest.raises(ValidationError):
        service.register(email, SENHA)


def test_t5_quarta_tentativa_apos_3_erros_e_recusada_mesmo_com_senha_certa(service):
    service.register(EMAIL, SENHA)

    for _ in range(3):
        with pytest.raises(InvalidCredentialsError):
            service.login(EMAIL, SENHA_ERRADA)

    with pytest.raises(AccountLockedError):
        service.login(EMAIL, SENHA)


def test_t5_conta_desbloqueia_depois_de_10_minutos(service, clock):
    service.register(EMAIL, SENHA)
    for _ in range(3):
        with pytest.raises(InvalidCredentialsError):
            service.login(EMAIL, SENHA_ERRADA)

    clock.advance(minutes=9, seconds=59)
    with pytest.raises(AccountLockedError):
        service.login(EMAIL, SENHA)

    clock.advance(seconds=1)
    assert service.login(EMAIL, SENHA)["email"] == EMAIL


def test_t6_senha_curta_e_rejeitada_no_cadastro(service):
    with pytest.raises(ValidationError):
        service.register(EMAIL, "1234567")  # 7 caracteres
    total = service.connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    assert total == 0

    service.register(EMAIL, "12345678")  # exatamente 8 é aceita


def test_email_duplicado_e_rejeitado(service):
    service.register(EMAIL, SENHA)
    with pytest.raises(EmailAlreadyRegisteredError):
        service.register(EMAIL, SENHA)
