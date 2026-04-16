#!/usr/bin/env python3
"""
GAZE Security Platform - Entry Point
"""
from app import create_app, db
from app.models import User, Asset, Assessment, Finding

app = create_app()


@app.shell_context_processor
def make_shell_context():
    """Add objects to flask shell context"""
    return {
        'db': db,
        'User': User,
        'Asset': Asset,
        'Assessment': Assessment,
        'Finding': Finding,
    }


@app.cli.command()
def init_db():
    """Initialize database tables"""
    db.create_all()
    print("Database initialized.")


@app.cli.command()
def create_admin():
    """Create initial admin user"""
    import getpass
    from app.security import AuthService
    
    email = input("Admin email: ").strip().lower()
    first_name = input("First name: ").strip()
    last_name = input("Last name: ").strip()
    
    while True:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        
        if password != confirm:
            print("Passwords don't match. Try again.")
            continue
        
        is_strong, errors = AuthService.check_password_strength(password)
        if not is_strong:
            print("Password not strong enough:")
            for error in errors:
                print(f"  - {error}")
            continue
        
        break
    
    user = User(
        email=email,
        first_name=first_name,
        last_name=last_name,
        role='superadmin',
        is_active=True
    )
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    
    print(f"Admin user created: {email}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
