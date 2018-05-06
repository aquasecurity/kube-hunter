hooks = {}


def trigger_event(name, item):
    print('Event Lookup: ', name, item)
    if name in hooks:
        for single_hook in hooks[name]:
            print("Event triggerd!", single_hook, item)
            single_hook(item).execute()


def register_event(name, callback):
    print('NEW Event: ', name, callback)
    if name not in hooks:
        # default dict
        hooks[name] = []
    if callback not in hooks[name]:
        hooks[name].append(callback)
