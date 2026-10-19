# Remove AI Tags by Jair Lima

## Descrição
Aplicativo Windows (Tkinter) que remove metadados de imagens: C2PA / Content Credentials, XMP, EXIF e IPTC.

## Stack
Python 3.10+, Pillow, piexif, tkinterdnd2 (opcional); ExifTool externo (opcional, recomendado).

## Estrutura
- `app.py`: interface e toda a lógica (parser de JPEG e PNG, chamada ao ExifTool, menu de contexto via `winreg`).
- `build.bat`: gera o executável com PyInstaller.

## Comandos
`pip install -r requirements.txt`, `python app.py`, `build.bat`.

## Decisões
- Por padrão grava `nome-limpo.ext` e preserva o original.
- ExifTool é chamado sempre com lista de argumentos (sem shell) e não é distribuído com o repositório.
- O menu de contexto grava só em HKCU (sem administrador).
- O README traz um aviso de uso responsável: remover metadados não torna a imagem "não gerada por IA".

## Estado atual
Versão 2.0, publicada em 2026-10-19 a partir do projeto original do autor.

## Problemas conhecidos
Testado só no Windows. O registro do menu de contexto no primeiro uso depende de o executável estar em `%USERPROFILE%\bin`.
