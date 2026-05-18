from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import pymysql

# Inicialización de la aplicación
app = Flask(__name__)
app.config['SECRET_KEY'] = 'mi_llave_secreta_super_segura_123'

# CONFIGURACIÓN DE MYSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/flask_crud'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialización de extensiones
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

# Redirección por defecto
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, inicia sesión para acceder a esta página.'
login_manager.login_message_category = 'danger'

# --- MODELO DE LA BASE DE DATOS ---
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer,autoincrement=True, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    update_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- RUTA PRINCIPAL ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# --- RUTAS DE AUTENTICACIÓN (Rutas actualizadas a carpeta 'page/') ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        if user_exists:
            flash('El nombre de usuario o el correo ya están registrados.', 'danger')
            return render_template('page/register.html')
            
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_pw, role='user')
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('¡Cuenta creada exitosamente! Ya puedes iniciar sesión.', 'success')
        return redirect(url_for('login'))
        
    return render_template('page/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email').strip()
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash(f'¡Bienvenido de nuevo, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Correo o contraseña incorrectos.', 'danger')
            
    return render_template('page/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión correctamente.', 'success')
    return redirect(url_for('login'))

# --- RUTAS DEL PANEL Y CRUD (Rutas actualizadas a carpeta 'page/') ---

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users = User.query.all()
        return render_template('page/admin_dashboard.html', users=users)
    return render_template('page/user_meme.html')

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        flash('No tienes permisos.', 'danger')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        role = request.form.get('role')

        # --- VALIDACIÓN ---
        user_exists = User.query.filter((User.username == username) | (User.email == email)).first()
        if user_exists:
            flash('Error: El nombre de usuario o el correo ya están registrados por otra persona.', 'danger')
            return render_template('page/create_user.html') # Lo mantenemos en la página para que corrija
        
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_pw, role=role)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f'¡Usuario {username} creado con éxito!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback() # Si algo falla, limpiamos la sesión
            flash('Ocurrió un error inesperado al guardar en la base de datos.', 'danger')
            return render_template('page/create_user.html')
            
    return render_template('page/create_user.html')

@app.route('/update_user/<int:id>', methods=['POST'])
@login_required
def update_user(id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
        
    user = User.query.get_or_404(id)
    user.username = request.form.get('username').strip()
    user.email = request.form.get('email').strip()
    user.role = request.form.get('role')
    
    db.session.commit()
    flash('Usuario actualizado.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_user/<int:id>', methods=['POST', 'GET'])
@login_required
def delete_user(id):
    if current_user.role != 'admin' or current_user.id == id:
        flash('Acción no permitida.', 'danger')
        return redirect(url_for('dashboard'))
        
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('Usuario eliminado.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/toggle_role')
@login_required
def toggle_role():
    current_user.role = 'admin' if current_user.role == 'user' else 'user'
    db.session.commit()
    flash(f'Rol cambiado a: {current_user.role.upper()}', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(debug=True)