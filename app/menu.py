import threading
from scapy.all import get_if_list
from . import config
from . import main

protection_thread = None

def start():
    global protection_thread
    if protection_thread is None or not protection_thread.is_alive():
        protection_thread = threading.Thread(target=main.run, daemon=True)
        protection_thread.start()
        print('Prote\u00e7\u00e3o ativada.')
    else:
        print('Prote\u00e7\u00e3o j\u00e1 em execu\u00e7\u00e3o.')

def stop():
    global protection_thread
    if protection_thread and protection_thread.is_alive():
        # no simple way to stop sniff; rely on program exit
        print('Pare o container para desativar.')
    else:
        print('Prote\u00e7\u00e3o n\u00e3o estava ativa.')

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
        print('1. Selecionar interface de rede')
        print('2. Ativar prote\u00e7\u00e3o')
        print('3. Desativar prote\u00e7\u00e3o')
        print('4. Sair')
        choice = input('Escolha: ')
        if choice == '1':
            select_interface()
        elif choice == '2':
            start()
        elif choice == '3':
            stop()
        elif choice == '4':
            break

if __name__ == '__main__':
    if config.PROTECTION_ENABLED:
        start()
    menu()
