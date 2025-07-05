import queue

log_listeners = []
blocked_listeners = []


def register_log_listener():
    q = queue.Queue()
    log_listeners.append(q)
    return q


def unregister_log_listener(q):
    try:
        log_listeners.remove(q)
    except ValueError:
        pass


def notify_log(entry):
    for q in list(log_listeners):
        try:
            q.put_nowait(entry)
        except Exception:
            pass


def register_blocked_listener():
    q = queue.Queue()
    blocked_listeners.append(q)
    return q


def unregister_blocked_listener(q):
    try:
        blocked_listeners.remove(q)
    except ValueError:
        pass


def notify_blocked(entry):
    for q in list(blocked_listeners):
        try:
            q.put_nowait(entry)
        except Exception:
            pass
