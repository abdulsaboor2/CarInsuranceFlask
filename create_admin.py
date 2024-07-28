from app import app, db, User
from werkzeug.security import generate_password_hash
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_admin_user(username='admin', password='adminpass'):
    try:
        # Create the database tables within the application context
        with app.app_context():
            db.create_all()

            # Check if the admin user already exists
            if not User.query.filter_by(username=username).first():
                # Create the admin user
                admin_user = User(
                    username=username,
                    password=generate_password_hash(password, method='pbkdf2:sha256'),
                    is_admin=True
                )
                db.session.add(admin_user)
                db.session.commit()
                logger.info("Admin user created successfully!")
            else:
                logger.info("Admin user already exists.")
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")

if __name__ == "__main__":
    create_admin_user()
