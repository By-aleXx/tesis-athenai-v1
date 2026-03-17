
try:
    import jwt
    print(f"✅ 'jwt' module found: {jwt.__file__}")
except ImportError as e:
    print(f"❌ 'jwt' module NOT found: {e}")

try:
    from auth import auth_manager
    print("✅ Successfully imported 'auth_manager' from 'auth'")
except ImportError as e:
    print(f"❌ ImportError importing 'auth': {e}")
except Exception as e:
    print(f"❌ Other error importing 'auth': {e}")
