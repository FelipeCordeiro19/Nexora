# Nexora

O Nexora é uma plataforma digital de produtividade pessoal que permite aos usuários criar contas, acessar seus ambientes individuais e organizar tarefas, projetos e objetivos em um único lugar.

Esta Sprint 1 entrega a funcionalidade de **login**: cadastro de usuário, autenticação, validação de e-mail, senha mínima e bloqueio de conta após tentativas erradas. O projeto é uma aplicação de linha de comando em Python, com testes automatizados.

## Equipe

| Pessoa | Papel |
|---|---|
| [@FelipeCordeiro19](https://github.com/FelipeCordeiro19) | PO, SM e Developer |

## O que o login faz

- **L1 Cadastro:** e-mail e senha válidos criam o usuário; a senha é gravada com hash (PBKDF2 com salt), nunca em texto puro.
- **L2 Login:** e-mail e senha corretos retornam sucesso e um token que identifica o usuário.
- **L3 Senha errada:** retorna um erro genérico, sem dizer se foi o e-mail ou a senha que falhou.
- **L4 Validação de e-mail:** e-mail vazio ou sem `@` é rejeitado antes de consultar o banco.
- **L5 Bloqueio:** após 3 senhas erradas seguidas, a conta bloqueia por 10 minutos e o login é recusado mesmo com a senha certa.
- **L6 Senha mínima:** senha com menos de 8 caracteres é rejeitada no cadastro.

## Como rodar o projeto

Requisito: Python 3.10 ou superior.

```
python -m pip install -r requirements.txt
python src/main.py cadastrar ana@exemplo.com
python src/main.py entrar ana@exemplo.com
```

A senha é pedida no prompt (não aparece na tela). Os usuários ficam no arquivo `nexora.db`, criado na primeira execução.

## Como rodar os testes

Com um único comando, na raiz do projeto:

```
python -m pytest
```

O resultado esperado é `12 passed`.

## Estrutura

```
src/main.py            ponto de entrada da linha de comando
src/nexora/auth.py     regras de cadastro, login e bloqueio
src/nexora/cli.py      interface de linha de comando
tests/test_auth.py     testes T1 a T6
```

## Planejamento

O planejamento da sprint está no quadro **Nexora - Kanban**, no GitHub Projects deste repositório.
