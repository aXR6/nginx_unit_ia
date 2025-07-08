import os

# Hide verbose TensorFlow logs before any potential import
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import threading
from werkzeug.serving import make_server
import torch
import logging
from . import config, main, wsgi
from .preload import download_models

logger = logging.getLogger(__name__)

_proxy_thread = None
_panel_server = None
_panel_thread = None


def start_proxy():
    global _proxy_thread
    if _proxy_thread is None or not _proxy_thread.is_alive():
        _proxy_thread = threading.Thread(target=main.start, daemon=True)
        _proxy_thread.start()
        logger.info("Proxy de seguran\u00e7a ativado")
        print("Proxy de seguran\u00e7a ativado.")
    else:
        print("Proxy j\u00e1 em execu\u00e7\u00e3o.")


def stop_proxy():
    global _proxy_thread
    if _proxy_thread and _proxy_thread.is_alive():
        main.stop()
        _proxy_thread.join()
        _proxy_thread = None
        logger.info("Proxy parado")
        print("Proxy parado.")
    else:
        print("Proxy n\u00e3o estava ativo.")


def start_panel():
    global _panel_server, _panel_thread
    if _panel_server is None:
        _panel_server = make_server(
            "0.0.0.0", config.WEB_PANEL_PORT, wsgi.app, threaded=True
        )
        _panel_thread = threading.Thread(target=_panel_server.serve_forever, daemon=True)
        _panel_thread.start()
        logger.info("Painel web iniciado na porta %s", config.WEB_PANEL_PORT)
        print(f"Painel web em http://localhost:{config.WEB_PANEL_PORT}/logs")
    else:
        print("Painel web j\u00e1 em execu\u00e7\u00e3o.")


def stop_panel():
    global _panel_server, _panel_thread
    if _panel_server is not None:
        _panel_server.shutdown()
        _panel_thread.join()
        _panel_server = None
        _panel_thread = None
        logger.info("Painel web parado")
        print("Painel parado.")
    else:
        print("Painel n\u00e3o estava ativo.")


def select_device():
    print("\nEscolha o dispositivo:")
    print("1. CPU")
    print("2. GPU")
    choice = input("Selecione: ")
    if choice == "1":
        device = "cpu"
    elif choice == "2" and torch.cuda.is_available():
        device = "cuda"
    else:
        print("Escolha inv\u00e1lida ou GPU indispon\u00edvel.")
        return
    if _proxy_thread and _proxy_thread.is_alive():
        print("Pare o proxy antes de mudar o dispositivo.")
        return
    config.DEVICE = device
    print(f"Dispositivo selecionado: {config.DEVICE}")


def whitelist_menu():
    from . import db
    while True:
        print("\nGerenciar Whitelist:")
        print("1. Listar IPs")
        print("2. Adicionar IP")
        print("3. Remover IP")
        print("4. Voltar")
        choice = input("Escolha: ")
        if choice == "1":
            ips = db.get_whitelist_ips()
            if not ips:
                print("Nenhum IP cadastrado.")
            else:
                print("IPs na whitelist:")
                for item in ips:
                    print(" -", item["ip"])
        elif choice == "2":
            ip = input("IP a adicionar: ").strip()
            if ip:
                db.add_whitelist_ip(ip)
                print(f"{ip} adicionado à whitelist.")
        elif choice == "3":
            ip = input("IP a remover: ").strip()
            if ip:
                db.remove_whitelist_ip(ip)
                print(f"{ip} removido da whitelist.")
        elif choice == "4":
            break
        else:
            print("Opção inválida.")


def menu():
    print("Verificando modelos, aguarde...")
    download_models()
    print("Modelos prontos.")
    while True:
        running = _proxy_thread is not None and _proxy_thread.is_alive()
        panel = _panel_server is not None
        print("\n1. " + ("Desativar" if running else "Ativar") + " proxy")
        print("2. " + ("Desativar" if panel else "Ativar") + " painel web")
        print("3. Selecionar dispositivo (CPU/GPU)")
        print("4. Gerenciar Whitelist")
        print("5. Sair")
        choice = input("Escolha: ")
        if choice == "1":
            if running:
                stop_proxy()
            else:
                start_proxy()
        elif choice == "2":
            if panel:
                stop_panel()
            else:
                start_panel()
        elif choice == "3":
            select_device()
        elif choice == "4":
            whitelist_menu()
        elif choice == "5":
            if running:
                stop_proxy()
            if panel:
                stop_panel()
            break


if __name__ == "__main__":
    menu()
