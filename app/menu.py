import threading
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

def menu():
    while True:
        print('\n1. Ativar prote\u00e7\u00e3o')
        print('2. Desativar prote\u00e7\u00e3o')
        print('3. Sair')
        choice = input('Escolha: ')
        if choice == '1':
            start()
        elif choice == '2':
            stop()
        elif choice == '3':
            break

if __name__ == '__main__':
    if config.PROTECTION_ENABLED:
        start()
    menu()
