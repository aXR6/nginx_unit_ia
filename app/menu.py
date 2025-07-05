import threading
from werkzeug.serving import make_server
import torch
from scapy.all import get_if_list
from . import config
from . import main
from . import wsgi

protection_thread = None
web_server = None
web_thread = None

def start_protection():
    global protection_thread
    if protection_thread is None or not protection_thread.is_alive():
        protection_thread = threading.Thread(target=main.run, daemon=True)
        protection_thread.start()
        print('Prote\u00e7\u00e3o ativada.')
    else:
        print('Prote\u00e7\u00e3o j\u00e1 em execu\u00e7\u00e3o.')

def stop_protection():
    global protection_thread
    if protection_thread and protection_thread.is_alive():
        main.stop()
        protection_thread.join()
        protection_thread = None
        print('Prote\u00e7\u00e3o desativada.')
    else:
        print('Prote\u00e7\u00e3o n\u00e3o estava ativa.')


def start_panel():
    """Start the web panel in a background thread."""
    global web_server, web_thread
    if web_server is None:
        web_server = make_server("0.0.0.0", config.WEB_PANEL_PORT, wsgi.app)
        web_thread = threading.Thread(target=web_server.serve_forever, daemon=True)
        web_thread.start()
        print(f"Painel web em http://localhost:{config.WEB_PANEL_PORT}/logs")
    else:
        print("Painel web j\u00e1 em execu\u00e7\u00e3o.")


def stop_panel():
    """Stop the web panel if running."""
    global web_server, web_thread
    if web_server is not None:
        web_server.shutdown()
        web_thread.join()
        web_server = None
        web_thread = None
        print("Painel web parado.")
    else:
        print("Painel web n\u00e3o estava ativo.")

def select_device():
    print('\nEscolha o dispositivo:')
    print('1. CPU')
    print('2. GPU')
    choice = input('Selecione: ')
    if choice == '1':
        device = 'cpu'
    elif choice == '2':
        if torch.cuda.is_available():
            device = 'cuda'
        else:
            print('GPU n\u00e3o dispon\u00edvel, usando CPU')
            device = 'cpu'
    else:
        print('Escolha inv\u00e1lida.')
        return
    if protection_thread and protection_thread.is_alive():
        print('Pare a prote\u00e7\u00e3o antes de mudar o dispositivo.')
        return
    config.DEVICE = device
    print(f'Dispositivo selecionado: {config.DEVICE}')

def select_interface():
    interfaces = get_if_list()
    print('\nInterfaces dispon\u00edveis:')
    for idx, iface in enumerate(interfaces, 1):
        print(f"{idx}. {iface}")
    choice = input('Selecione a interface: ')
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(interfaces):
            raise ValueError
        if protection_thread and protection_thread.is_alive():
            print('Pare a prote\u00e7\u00e3o antes de mudar a interface.')
            return
        config.NETWORK_INTERFACE = interfaces[idx]
        print(f"Interface selecionada: {config.NETWORK_INTERFACE}")
    except ValueError:
        print('Escolha inv\u00e1lida.')

def menu():
    while True:
        print(f"\nInterface atual: {config.NETWORK_INTERFACE}")
        print(f"Dispositivo atual: {config.DEVICE}")
        running = protection_thread is not None and protection_thread.is_alive()
        panel = web_server is not None
        print('1. ' + ('Desativar' if running else 'Ativar') + ' prote\u00e7\u00e3o')
        print('2. ' + ('Desativar' if panel else 'Ativar') + ' painel web')
        print('3. Selecionar interface de rede')
        print('4. Selecionar dispositivo (CPU/GPU)')
        print('5. Sair')
        choice = input('Escolha: ')
        if choice == '1':
            if running:
                stop_protection()
            else:
                start_protection()
        elif choice == '2':
            if panel:
                stop_panel()
            else:
                start_panel()
        elif choice == '3':
            select_interface()
        elif choice == '4':
            select_device()
        elif choice == '5':
            if running:
                stop_protection()
            if panel:
                stop_panel()
            break

if __name__ == '__main__':
    menu()
