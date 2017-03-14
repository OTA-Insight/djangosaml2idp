def create_identity(user, sp_mapping):
    identity = {}
    for user_attr, out_attr in sp_mapping.items():
        if hasattr(user, user_attr):
            identity[out_attr] = getattr(user, user_attr)
    return identity
