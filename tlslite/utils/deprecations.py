
import warnings
from functools import wraps

def deprecated_params(names, warn="Param name '{old_name}' is deprecated, "
                                  "please use '{new_name}'"):
    """Decorator to translate obsolete names and warn about their use.

    :param dict names: dictionary with pairs of new_name: old_name pairs
        that will be used for translating obsolete param names to new names

    :param str warn: DeprecationWarning format string for informing the user
        what is the current parameter name, uses 'old_name' for the
        deprecated keyword name and 'new_name' for the current one.
        Example: "Old name: {old_name}, use {new_name} instead".
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for new_name, old_name in names.items():
                if old_name in kwargs:
                    if new_name in kwargs:
                        raise TypeError("got multiple values for keyword "
                                        "argument '{0}'".format(new_name))
                    warnings.warn(warn.format(old_name=old_name,
                                              new_name=new_name),
                                  DeprecationWarning,
                                  stacklevel=2)
                    kwargs[new_name] = kwargs.pop(old_name)
            return func(*args, **kwargs)
        return wrapper
    return decorator

