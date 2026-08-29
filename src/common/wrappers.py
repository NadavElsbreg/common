from functools import wraps
import time


from pyparsing import wraps

__all__ = [
    name for name in globals()
    if not name.startswith("_")
    and callable(globals()[name])
]


def baseWrapper(func):
    """A base wrapper function that can be used as a template for other wrappers."""
    def wrapper(*args, **kwargs):
        # Pre-processing code can go here (e.g. logging, input validation)
        print(f"Calling function '{func.__name__}' with args: {args} and kwargs: {kwargs}")
        
        # Call the original function
        result = func(*args, **kwargs)
        
        # Post-processing code can go here (e.g. logging, modifying the result)
        print(f"Function '{func.__name__}' returned: {result}")
        
        return result
    return wrapper


def countTime(func):
    """Decorator to measure the execution time of a function."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"Function '{func.__name__}' executed in {end_time - start_time:.6f} seconds.")
        return result
    return wrapper



def require_Auth(permission_level):
    """Checks if the current user has the required permission level.
    
    Approach 1: Uses string-based permission levels and expects the function
    to receive current_user_permissions as a keyword argument.
    
    Usage:
        @require_auth("admin")
        def my_func(current_user_permissions="user"):
            print("Doing admin stuff")
    """
    def decorate(func):
        try:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Get current user permissions from kwargs or use guest as default. 
                current_user_permissions = str(kwargs.get('current_user_permissions', 'guest')).lower()
                permission_level_str = str(permission_level).lower()
                
                if current_user_permissions == permission_level_str:
                    return func(*args, **kwargs)
                else:
                    print(f"Error: User does not have '{permission_level}' permissions to run '{func.__name__}'")
                    return None
            return wrapper
        except Exception as e:
            print(f"Error in require_Auth: {e}, function: {func.__name__} did not execute.")
            return None
    return decorate


def require_Auth_Numeral(permission_level):
    """Checks if the current user has the required permission level."""
    def decorate(func):
        try:
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Extract current permission from kwargs
                current_permission = kwargs.pop('current_permission', 0)
                
                if current_permission >= permission_level:
                    return func(*args, **kwargs)
                else:
                    print(f"Error: User permission level {current_permission} is insufficient. Required: {permission_level} for '{func.__name__}'")
                    return None
            return wrapper
        except Exception as e:
            print(f"Error in require_Auth_Numeral: {e}, function: {func.__name__} did not execute.")
            return None
    return decorate
