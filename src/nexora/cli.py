"""Interface de linha de comando do Nexora."""

import argparse
import getpass

from nexora.auth import AuthError, AuthService


def main(argv=None):
    parser = argparse.ArgumentParser(prog="nexora", description="Nexora - login")
    parser.add_argument("comando", choices=["cadastrar", "entrar"])
    parser.add_argument("email")
    parser.add_argument("--db", default="nexora.db", help="arquivo do banco SQLite")
    args = parser.parse_args(argv)

    password = getpass.getpass("Senha: ")
    service = AuthService(args.db)

    try:
        if args.comando == "cadastrar":
            service.register(args.email, password)
            print("Usuário cadastrado com sucesso.")
        else:
            result = service.login(args.email, password)
            print(f"Login realizado com sucesso. Token: {result['token']}")
    except AuthError as error:
        print(f"Erro: {error}")
        return 1
    return 0
