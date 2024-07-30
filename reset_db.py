from app import app, db, User, Record, Contact, InsuranceClaim

# Drop all tables and create them within the application context
with app.app_context():
    # Drop all tables
    db.drop_all()
    
    # Create all tables according to the models
    db.create_all()

    # Add some test data (optional)
    from werkzeug.security import generate_password_hash

    # Add a test admin user
    admin = User(username='admin', email='admin@slys.com', password=generate_password_hash('admin123', method='pbkdf2:sha256'), role='admin')
    db.session.add(admin)

    # Add a test normal user
    user = User(username='user', email='absaboor019@gmail.com', password=generate_password_hash('123', method='pbkdf2:sha256'), role='user')
    db.session.add(user)

    db.session.commit()

    print("Database has been reset and test data added.")
