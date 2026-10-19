# Remove AI Tags by Jair Lima

Aplicativo para Windows que **remove metadados de imagens**, incluindo as marcações de procedência e de IA: C2PA (Content Credentials), XMP, EXIF e IPTC. Tem interface gráfica com arrastar e soltar, processamento em lote e integração opcional com o menu de contexto do Explorer.

## Uso responsável

Remover metadados **não faz** com que uma imagem deixe de ser gerada ou alterada por IA. Muitas plataformas, leis e contratos exigem que esse tipo de conteúdo seja informado como tal. Use a ferramenta para privacidade (por exemplo, apagar localização e dados da câmera) e para limpar arquivos, e **cumpra as regras de divulgação** da plataforma onde for publicar. Não use para enganar pessoas sobre a origem de uma imagem.

## Formatos e métodos

- Formatos: JPG, JPEG, PNG, WEBP, TIFF e BMP.
- Com o **ExifTool** instalado (recomendado), ele limpa todos os metadados. Sem ele, o app usa um parser próprio para JPEG e PNG e o Pillow para os demais formatos.
- Por padrão o original é preservado: o app grava uma cópia ao lado, com o sufixo `-limpo` (por exemplo, `foto-limpo.jpg`). A opção "Sobrescrever original" vem desligada.

## Instalação

```bash
pip install -r requirements.txt
python app.py
```

Para o melhor resultado, instale o [ExifTool](https://exiftool.org) (ele não vem neste repositório): coloque o `exiftool.exe` no `PATH`, em `%USERPROFILE%\bin` ou em `%LOCALAPPDATA%\Programs\ExifTool`.

Para gerar um executável: `build.bat`.

## Menu de contexto do Windows

O app pode registrar a entrada "Remover Tags de IA" no clique direito de imagens. Isso grava chaves em `HKEY_CURRENT_USER\Software\Classes` (sem precisar de administrador) e pode ser desfeito pelo próprio app.

## Segurança

- O app roda localmente e **não envia nenhuma imagem pela rede**.
- Chama o ExifTool sempre com lista de argumentos (sem shell).

## Licença

MIT, veja `LICENSE`.
