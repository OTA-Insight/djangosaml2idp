class BaseProcessor:
    """ Processor class is used to determine if a user has access to a client service of this IDP
        and to construct the identity dictionary which is sent to the SP
    """

    def has_access(self, user):
        """ Check if this user is allowed to use this IDP
        """
        return True

    def enable_multifactor(self, user):
        """ Check if this user should use a second authentication system
        """
        return False

    def create_identity(self, user, sp_mapping):
        """ Generate an identity dictionary of the user based on the given mapping of desired user attributes by the SP
        """
        return {
            out_attr: getattr(user, user_attr)
            for user_attr, out_attr in sp_mapping.items()
            if hasattr(user, user_attr)
        }
