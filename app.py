from flask import Flask, session, render_template, redirect, request, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest
from datetime import datetime
from functools import wraps
import os


# My app setup
app = Flask(__name__)
app.secret_key = 'uma_chave_secreta_e_unica_aqui'
# Usando SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
# Inicializando Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
# Redireciona para esta rota ao acessar página protegida
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, faça login para acessar esta página."

# Inicializando o banco de dados
db = SQLAlchemy(app)


# Função para verificar se a extensão do arquivo é permitida
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Modelo para armazenar os dados do aluno
class Aluno(UserMixin, db.Model):
    __tablename__ = 'aluno'
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(255), nullable=False)
    data_nascimento = db.Column(db.Date, nullable=False)
    numero_bilhete = db.Column(db.String(12), nullable=False, unique=True)
    genero = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    senha = db.Column(db.String(255), nullable=False)
    instituicao_9_classe = db.Column(db.String(255), nullable=False)
    ano_conclusao = db.Column(db.Integer, nullable=False)
    media_final = db.Column(db.Float, nullable=False)
    turno_preferido = db.Column(db.String(10), nullable=False)
    telefone = db.Column(db.String(15), nullable=False)
    municipio = db.Column(db.String(255), nullable=False)
    bairro = db.Column(db.String(255), nullable=False)
    provincia = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    tipo = db.Column(db.String(50), default="aluno", nullable=False)

    # Campos para armazenar os caminhos dos documentos
    frente_bilhete_path = db.Column(db.String(255), nullable=True)
    verso_bilhete_path = db.Column(db.String(255), nullable=True)
    certificado_path = db.Column(db.String(255), nullable=True)

#  Instituicao


class Instituicao(UserMixin, db.Model):
    __tablename__ = 'instituicao'
    id = db.Column(db.Integer, primary_key=True)
    nome_instituicao = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    tipo = db.Column(db.String(50), default="instituicao", nullable=False)
    endereco = db.Column(db.String(255), nullable=True)
    cidade = db.Column(db.String(100), nullable=True)
    provincia = db.Column(db.String(100), nullable=True)
    codigo_postal = db.Column(db.String(20), nullable=True)
    telefone = db.Column(db.String(20), nullable=True)
    descricao = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default="ativo", nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False)
    data_atualizacao = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Campos adicionais para curso e número de vagas
    curso = db.Column(db.String(255), nullable=True)  # Nome do curso oferecido
    # Número de vagas para o curso
    numero_vagas = db.Column(db.Integer, nullable=True)

    # Relacionamento com a tabela Funcionario
    funcionarios = db.relationship(
        'Funcionario', backref='instituicao', lazy=True)

    def __repr__(self):
        return f'<Instituicao {self.nome_instituicao}>'


class Funcionario(db.Model):
    __tablename__ = 'funcionario'
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    senha = db.Column(db.String(256), nullable=False)
    tipo = db.Column(db.String(50), default="instituicao", nullable=False)
    # Cargo do funcionário
    permissao = db.Column(db.String(100), nullable=False)
    telefone = db.Column(db.String(20), nullable=True)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False)

    # Chave estrangeira para o relacionamento com a Instituicao
    instituicao_id = db.Column(db.Integer, db.ForeignKey(
        'instituicao.id'), nullable=False)

    def __repr__(self):
        return f'<Funcionario {self.nome} - {self.cargo}>'


# Admin


class Admin(UserMixin, db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    nome_admin = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    tipo = db.Column(db.String(50), default="admin", nullable=False)
    senha = db.Column(db.String(256), nullable=False)
# Criar um novo admin
# novo_admin = Admin(
# nome_admin="Administrador",
# email="admin@escola.com",
# senha=generate_password_hash("senha_segura123")  # Senha segura com hash
#        )

# Adicionar ao banco de dados
# db.session.add(novo_admin)
# db.session.commit()

# logs do sitema


class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    data_hora = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    mensagem = db.Column(db.String(255), nullable=False)
    # 'informação', 'erro', etc.
    tipo = db.Column(db.String(50), nullable=False)

    # Campos que armazenam o tipo de usuário e o ID do usuário
    # Pode ser aluno, instituição ou admin
    usuario_id = db.Column(db.Integer, nullable=True)
    # 'aluno', 'instituicao', 'admin'
    tipo_usuario = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<Log {self.id} - {self.tipo} - {self.tipo_usuario} - {self.usuario_id}>'

# funcao add log


def adicionar_log(mensagem, tipo='informação', usuario=None, tipo_usuario='desconecido'):
    novo_log = Log(mensagem=mensagem, tipo=tipo, tipo_usuario=tipo_usuario)

    if usuario:
        novo_log.usuario_id = usuario.id  # Aqui você associa o log ao usuário

    db.session.add(novo_log)
    db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    # Recupera o tipo do usuário na sessão
    user_type = session.get('user_type')

    if user_type == "aluno":
        return Aluno.query.get(int(user_id))
    elif user_type == "instituicao":
        return Instituicao.query.get(int(user_id))
    elif user_type == "admin":
        return Admin.query.get(int(user_id))

    return None

# Decorador para Administradores


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.tipo != 'admin':
            flash(
                {'titulo': 'Acesso negado!',
                 'corpo': 'Você não tem permissão para acessar esta página.'})
            return redirect(url_for('index'))  # Redireciona se não for admin
        return f(*args, **kwargs)
    return decorated_function

# Decorador para Instituições


def instituicao_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_type") != "instituicao":
            flash(
                {'titulo': 'Acesso negado!',
                 'corpo': ' Somente instituições podem acessar esta página.'})
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para Alunos


def aluno_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_type") != "aluno":
            flash(
                {'titulo': 'Acesso negado!',
                 'corpo': ' Somente alunos podem acessar esta página.'})
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def index():
    return render_template("index.html")


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        try:
            nome_completo = request.form['nomeCompleto']

            # Validação para data de nascimento
            try:
                data_nascimento = datetime.strptime(
                    request.form['dataNascimento'], '%Y-%m-%d').date()
            except ValueError:
                flash(
                    {'titulo': 'Erro', 'corpo': 'Data de nascimento inválida! Use o formato AAAA-MM-DD.'})
                return redirect(url_for('cadastro'))

            # Coletar outros dados do formulário Preencha
            numero_bilhete = request.form['numeroBilhete'].capitalize()
            genero = request.form['genero']
            email = request.form['email']
            senha = request.form['senha']
            instituicao_9_classe = request.form['instituicao9']
            ano_conclusao = request.form['anoConclusao']
            media_final = request.form['mediaFinal']
            turno_preferido = request.form['turno']
            telefone = request.form['telefone']
            municipio = request.form['municipio']
            bairro = request.form['bairro']
            provincia = request.form['provincia']

            # Hash da senha para segurança
            senha_hash = generate_password_hash(senha)

            # Salvar os dados no banco
            novo_aluno = Aluno(
                nome_completo=nome_completo,
                data_nascimento=data_nascimento,
                numero_bilhete=numero_bilhete,
                genero=genero,
                email=email,
                senha=senha_hash,
                instituicao_9_classe=instituicao_9_classe,
                ano_conclusao=ano_conclusao,
                media_final=media_final,
                turno_preferido=turno_preferido,
                telefone=telefone,
                municipio=municipio,
                bairro=bairro,
                provincia=provincia
            )

            db.session.add(novo_aluno)
            db.session.commit()

            flash({'titulo': 'Cadastro realizado com sucesso!',
                   'corpo': 'Faça login para continuar.'})
            adicionar_log(f'Novo aluno cadastrado: {
                novo_aluno.nome_completo}', tipo='informação', usuario=novo_aluno, tipo_usuario='aluno')
            return redirect(url_for('login'))

        except IntegrityError as e:
            db.session.rollback()
            mensagem = str(e.orig)

            if "UNIQUE constraint" in mensagem:
                if "aluno.email" in mensagem:
                    corpo_mensagem = "Este email já está registrado!"
                elif "aluno.numero_bilhete" in mensagem:
                    corpo_mensagem = "O número do bilhete já está registrado!"
                else:
                    corpo_mensagem = f"Erro no banco de dados: {mensagem}"
            else:
                corpo_mensagem = f"Erro no banco de dados: {mensagem}"

            flash({'titulo': 'Erro no cadastro', 'corpo': corpo_mensagem})
            adicionar_log(f'Erro de banco de dados ao cadastrar aluno: {
                corpo_mensagem}', tipo='erro', usuario=None, tipo_usuario='aluno')
            return redirect(url_for('cadastro'))

        except Exception as e:
            flash({'titulo': 'Erro inesperado',
                   'corpo': f'Erro inesperado: {str(e)}'})
            adicionar_log(f'Erro inesperado ao cadastrar aluno: {
                str(e)}', tipo='erro', usuario=None, tipo_usuario='aluno')
            return redirect(url_for('cadastro'))

    return render_template('cadastro.html')


# Rota para a página de upload
@app.route('/upload/<user_id>', methods=['GET', 'POST'])
@login_required
@aluno_required
def upload(user_id):
    if request.method == 'POST':
        try:
            # Verificar se os arquivos foram enviados
            if 'frente_bilhete' not in request.files or 'verso_bilhete' not in request.files or 'certificado' not in request.files:
                flash(
                    {'titulo': 'Erro',
                        'corpo': 'Faltam arquivos! Por favor, envie todos os arquivos solicitados.'})
                return redirect(url_for('upload', user_id=user_id))

            frente_bilhete = request.files['frente_bilhete']
            verso_bilhete = request.files['verso_bilhete']
            certificado = request.files['certificado']

            # Verificar se os arquivos são válidos
            if (frente_bilhete and allowed_file(frente_bilhete.filename) and
                verso_bilhete and allowed_file(verso_bilhete.filename) and
                    certificado and allowed_file(certificado.filename)):

                # Gerar nomes de arquivos com base no ID do aluno
                frente_filename = f"frente_{user_id}.jpg"
                verso_filename = f"verso_{user_id}.jpg"
                certificado_filename = f"certificado_{user_id}.jpg"

                # Salvar os arquivos com nome seguro
                frente_bilhete.save(os.path.join(
                    app.config['UPLOAD_FOLDER'], frente_filename))
                verso_bilhete.save(os.path.join(
                    app.config['UPLOAD_FOLDER'], verso_filename))
                certificado.save(os.path.join(
                    app.config['UPLOAD_FOLDER'], certificado_filename))

                # Atualizar os caminhos dos documentos no banco de dados
                aluno = Aluno.query.get(user_id)
                aluno.frente_bilhete_path = os.path.join(
                    app.config['UPLOAD_FOLDER'], frente_filename)
                aluno.verso_bilhete_path = os.path.join(
                    app.config['UPLOAD_FOLDER'], verso_filename)
                aluno.certificado_path = os.path.join(
                    app.config['UPLOAD_FOLDER'], certificado_filename)
                db.session.commit()

                adicionar_log(f'Upload de documentos realizado com sucesso para o aluno {
                    current_user.nome_completo}', tipo='informação', usuario=current_user, tipo_usuario='aluno')
                flash({'titulo': 'Sucesso',
                       'corpo': 'Documentos enviados com sucesso!'})
                return redirect(url_for('portal_estudante', aluno=current_user))

            else:
                flash(
                    {'titulo': 'Erro', 'corpo': 'Formato de arquivo inválido! Certifique-se de que os arquivos são do tipo permitido.'})
                adicionar_log(f'Erro ao tentar fazer upload de documentos para o aluno {
                    current_user.nome_completo}: Formato de arquivo inválido.', tipo='erro', usuario=current_user, tipo_usuario='aluno')
                return redirect(url_for('upload', user_id=user_id))

        except Exception as e:
            flash({'titulo': 'Erro Durante o Upload',
                   'corpo': f'Erro inesperado ao processar o upload: {str(e)}'})
            adicionar_log(f'Erro ao tentar fazer upload de documentos para o aluno {
                current_user.nome_completo}: {str(e)}', tipo='erro', usuario=current_user, tipo_usuario='aluno')
            return redirect(url_for('upload', user_id=user_id))

    return render_template('upload.html', user_id=user_id)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('password')

        if not email or not senha:
            flash({
                'titulo': 'Aviso',
                'corpo': 'Preencha todos os campos!'})
            return render_template('login.html')

        # Verifica nas três tabelas
        aluno = Aluno.query.filter_by(email=email).first()
        instituicao = Instituicao.query.filter_by(email=email).first()
        admin = Admin.query.filter_by(email=email).first()

        user = None
        user_type = None

        if aluno and check_password_hash(aluno.senha, senha):
            user = aluno
            user_type = "aluno"
        elif instituicao and check_password_hash(instituicao.senha, senha):
            user = instituicao
            user_type = "instituicao"
        elif admin and check_password_hash(admin.senha, senha):
            user = admin
            user_type = "admin"

        if user:
            session['user_type'] = user_type  # Salva o tipo do usuário
            login_user(user)
            # adicionar_log(f'Usuário {current_user.nome_completo} fez login com sucesso',
            #              tipo='informação', usuario=current_user, tipo_usuario=current_user.tipo)

            flash({
                'titulo': 'Sucesso',
                'corpo': 'Login bem-sucedido!'})

            # Redirecionamento baseado no tipo
            if user_type == "aluno":
                return redirect(url_for('portal_estudante'))
            elif user_type == "instituicao":
                return redirect(url_for('portal_instituicao'))
            elif user_type == "admin":
                return redirect(url_for('painel_admin'))
        else:
            adicionar_log(f'Falha ao tentar login com email: {
                request.form["email"]}', tipo='erro', usuario=None, tipo_usuario='aluno')
            flash({
                'titulo': 'Erro',
                'corpo': 'Credenciais inválidas. Verifique o email e a senha.'})

    return render_template('login.html')


@app.route('/portal_estudante')
@login_required
@aluno_required
def portal_estudante():
    # Página do portal do estudante
    return render_template('portal_estudante.html', aluno=current_user)

# Rota do Painel Admin


@app.route('/painel_admin', methods=['GET', 'POST'])
@login_required
@admin_required
def painel_admin():
    # Pegar o parâmetro de pesquisa
    search = request.args.get('search', '')

    # Buscar alunos com base na pesquisa (caso haja)
    if search:
        alunos = Aluno.query.filter(
            (Aluno.id.like(f"%{search}%")) |
            (Aluno.nome_completo.like(f"%{search}%")) |
            (Aluno.numero_bilhete.like(f"%{search}%"))).all()

    else:
        # Caso não haja pesquisa, listar todos os alunos
        alunos = Aluno.query.all()

    # Buscar logs e contar o total de alunos
    logs_sistema = Log.query.order_by(Log.data_hora.desc()).limit(30).all()
    total_alunos = Aluno.query.count()
    alunos_recentes = Aluno.query.order_by(
        Aluno.created_at.desc()).limit(5).all()

    agora = datetime.now()

    return render_template('painel_admin.html',
                           agora=agora,
                           admin=current_user,
                           alunos=alunos,
                           logs_sistema=logs_sistema,
                           total_alunos=total_alunos,
                           alunos_recentes=alunos_recentes)


@app.route('/atualizar_aluno/<int:aluno_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def atualizar_aluno(aluno_id):
    aluno = Aluno.query.get(aluno_id)

    if not aluno:
        flash('Aluno não encontrado', 'danger')
        redirect(url_for('painel_admin'))

    if request.method == 'POST':
        # Obtendo os dados do formulário
        nome_completo = request.form['nome_completo']
        # Validação para data de nascimento
        try:
            data_nascimento = datetime.strptime(
                request.form['data_nascimento'], '%Y-%m-%d').date()
        except ValueError:
            flash({
                'titulo': 'Erro',
                'corpo': 'Data de nascimento inválida! Por favor, insira no formato correto (AAAA-MM-DD).'})
            return redirect(url_for('painel_admin'))

        numero_bilhete = request.form['numero_bilhete'].capitalize()
        genero = request.form['genero']
        email = request.form['email']
        senha = request.form['senha']  # Se for uma senha vazia, não atualiza
        instituicao_9_classe = request.form['instituicao_9_classe']
        ano_conclusao = request.form['ano_conclusao']
        media_final = request.form['media_final']
        turno_preferido = request.form['turno_preferido']
        telefone = request.form['telefone']
        municipio = request.form['municipio']
        bairro = request.form['bairro']
        provincia = request.form['provincia']

        # Atualizando os dados
        aluno.nome_completo = nome_completo
        aluno.data_nascimento = data_nascimento
        aluno.numero_bilhete = numero_bilhete
        aluno.genero = genero
        aluno.email = email
        aluno.instituicao_9_classe = instituicao_9_classe
        aluno.ano_conclusao = ano_conclusao
        aluno.media_final = media_final
        aluno.turno_preferido = turno_preferido
        aluno.telefone = telefone
        aluno.municipio = municipio
        aluno.bairro = bairro
        aluno.provincia = provincia

        # Verificando se foi inserida uma nova senha
        if senha:
            aluno.senha = generate_password_hash(senha)

        db.session.commit()
        flash({
            'titulo': 'Sucesso',
            'corpo': 'Dados atualizados com sucesso'
        })

        return redirect(url_for('painel_admin') + '#alunos')


@app.route('/deletar_aluno/<int:aluno_id>', methods=['GET'])
def deletar_aluno(aluno_id):
    aluno = Aluno.query.get(aluno_id)

    if not aluno:
        flash('Aluno não encontrado', 'danger')
        return redirect(url_for('painel_admin') + '#alunos')

    try:
        db.session.delete(aluno)  # Deletando o aluno
        db.session.commit()  # Confirmando a exclusão no banco de dados

        flash({
            'titulo': 'Sucesso',
            'corpo': 'Aluno excluído com sucesso'
        })

    except Exception as e:
        db.session.rollback()  # Se ocorrer um erro, faz o rollback

        flash({
            'titulo': 'Erro',
            'corpo': f'Ocorreu um erro ao excluir o aluno: {str(e)}'
        })

    # Depois de deletar,  chamar a função de renderização para painel_admin
    return redirect(url_for('painel_admin') + '#alunos')


@app.route('/instituicao_dashboard')
@login_required
@instituicao_required
def instituicao_dashboard():
    return render_template('instituicao_dashboard.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    # Registrar o log de logout
    # mensagem = f'O usuário {current_user.nome_completo} fez logout'
    # adicionar_log(mensagem=mensagem, tipo='informação',
    #              usuario=current_user, tipo_usuario='aluno')

    # Realizar o logout
    logout_user()

    # Exibir uma mensagem flash e redirecionar para a página de login

    flash({
        'titulo': 'Aviso',
        'corpo': 'Você saiu da sua conta.'
    })

    return redirect(url_for('login'))


# Runner and Debugger
if __name__ in "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
