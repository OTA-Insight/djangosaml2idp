

class BaseProcessor(object):
    """
        Processor class is used to determine if a user has access to a client service of this IDP
        and to create the identity dictionary sent to the SP
    """

    def has_access(self, user):
        return True

    def create_identity(self, user, sp_mapping):
        return {
            out_attr: getattr(user, user_attr)
            for user_attr, out_attr in sp_mapping.items()
            if hasattr(user, user_attr)
        }
