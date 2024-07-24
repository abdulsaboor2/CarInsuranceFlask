from app import app, db, User
from werkzeug.security import generate_password_hash

# Create the database tables within the application context
with app.app_context():
    db.create_all()

    # Check if the admin user already exists
    if not User.query.filter_by(username='admin').first():
        # Create the admin user
        admin_user = User(
            username='admin',
            password=generate_password_hash('adminpass', method='pbkdf2:sha256'),  # Use 'pbkdf2:sha256'
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created successfully!")
    else:
        print("Admin user already exists.")
