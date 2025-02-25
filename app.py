from flask import Flask, session, render_template, redirect, request, url_for, flash, send_from_directory, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import BadRequest
from faker import Faker
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

# config do faker
faker = Faker('pt_PT')

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

    # Relacionamento com Inscricao
    inscricoes = db.relationship('Inscricao', backref='aluno_rel', lazy=True)

    # Campos para armazenar os caminhos dos documentos
    frente_bilhete_path = db.Column(db.String(255), nullable=True)
    verso_bilhete_path = db.Column(db.String(255), nullable=True)
    certificado_path = db.Column(db.String(255), nullable=True)


#  Instituicao


class Instituicao(UserMixin, db.Model):
    __tablename__ = 'instituicao'
    id = db.Column(db.Integer, primary_key=True)
    nome_instituicao = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    tipo = db.Column(db.String(50), default="instituicao", nullable=False)
    endereco = db.Column(db.String(255), nullable=True)
    cidade = db.Column(db.String(100), nullable=True)
    provincia = db.Column(db.String(100), nullable=True)
    telefone = db.Column(db.String(20), nullable=True)
    descricao = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default="ativo", nullable=False)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False)
    data_atualizacao = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    inscricoes = db.relationship('Inscricao', backref='instituicao_rel', lazy=True)
    cursos = db.Column(db.String(1000), nullable=True, default="")


    numero_vagas = db.Column(db.Integer, nullable=True)

    # Relacionamento com a tabela Funcionario
    funcionarios = db.relationship(
        'Funcionario', backref='instituicao', lazy=True)

    def __repr__(self):
        return f'<Instituicao {self.nome_instituicao}>'


class Funcionario(UserMixin, db.Model):
    __tablename__ = 'funcionario'
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    senha = db.Column(db.String(256), nullable=False)
    tipo = db.Column(db.String(50), default="funcionario", nullable=False)
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
    nome_completo = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    tipo = db.Column(db.String(50), default="admin", nullable=False)
    senha = db.Column(db.String(256), nullable=False)


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


class InteresseInstituicao(db.Model):
    __tablename__ = 'interesses_instituicoes'
    id = db.Column(db.Integer, primary_key=True)
    nome_instituicao = db.Column(db.String(255), nullable=False)
    nome_responsavel = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    telefone = db.Column(db.String(15), nullable=False)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='pendente')
    documentos = db.relationship('Documento', backref='interesse', lazy=True)


class Documento(db.Model):
    __tablename__ = 'documentos'
    id = db.Column(db.Integer, primary_key=True)
    nome_arquivo = db.Column(db.String(255), nullable=False)
    caminho_arquivo = db.Column(db.String(255), nullable=False)
    interesse_id = db.Column(db.Integer, db.ForeignKey(
        'interesses_instituicoes.id'), nullable=False)

class Inscricao(db.Model):
    __tablename__ = 'inscricoes'
    id = db.Column(db.Integer, primary_key=True)
    aluno_id = db.Column(db.Integer, db.ForeignKey('aluno.id'), nullable=False)
    instituicao_id = db.Column(db.Integer, db.ForeignKey('instituicao.id'), nullable=False)
    curso = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Pendente')
    data_inscricao = db.Column(db.DateTime, default=datetime.utcnow)
    data_atualizacao = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    mensagem_instituicao = db.Column(db.Text, nullable=True)

    # Relacionamentos
    aluno = db.relationship('Aluno', backref='inscricoes_rel', lazy=True)
    instituicao = db.relationship('Instituicao', backref='inscricoes_rel', lazy=True)


    def __repr__(self):
        return f"<Inscricao {self.id} - Aluno: {self.aluno_id} | Escola: {self.instituicao_id}>"


class Mensagem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    mensagem = db.Column(db.Text, nullable=False)
    tipo = db.Column(db.String(20), nullable=False)  # 'suporte' ou 'contato'

    usuario_id = db.Column(db.Integer, nullable=True)  # ID do aluno ou funcionário
    tipo_usuario = db.Column(db.String(20), nullable=True)  # 'aluno' ou 'funcionario'

    lida = db.Column(db.Boolean, default=False)  # Estado da mensagem

    def __repr__(self):
        return f'<Mensagem {self.id} - {self.tipo_usuario} - {"Lida" if self.lida else "Não Lida"}>'


@login_manager.user_loader
def load_user(user_id):
    # Recupera o tipo do usuário na sessão
    user_type = session.get('user_type')

    if user_type == "aluno":
        return Aluno.query.get(int(user_id))
    elif user_type == "funcionario":
        return Funcionario.query.get(int(user_id))
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


def funcionario_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_type") != "funcionario":
            flash(
                {'titulo': 'Acesso negado!',
                 'corpo': ' Somente fúncionarios de instituições podem acessar esta página.'})
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


@app.route('/enviar_mensagem', methods=['POST'])
def enviar_mensagem():
    tipo = request.form.get("tipo")  # "suporte" ou "contato"

    # Se o usuário estiver logado, preenche automaticamente os dados
    if current_user.is_authenticated:
        nome = current_user.nome_completo
        email = current_user.email
        tipo_usuario = current_user.tipo  # 'aluno' ou 'funcionario'
        usuario_id = current_user.id
    else:
        nome = request.form.get("nome")
        email = request.form.get("email")
        tipo_usuario = "visitante"  # Para usuários não autenticados
        usuario_id = 0

    mensagem_texto = request.form.get("mensagem")

    if not mensagem_texto.strip():
        flash("A mensagem não pode estar vazia.", "error")
        return redirect(request.referrer or url_for('index'))

    # Criar e salvar a mensagem no banco de dados
    nova_mensagem = Mensagem(
        nome=nome,
        email=email,
        mensagem=mensagem_texto,
        tipo=tipo,
        usuario_id=usuario_id,
        tipo_usuario=tipo_usuario
    )

    db.session.add(nova_mensagem)
    db.session.commit()

    flash("Mensagem enviada com sucesso!", "success")
    return redirect(request.referrer or url_for('index'))


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
            genero = request.form['genero'].capitalize()
            email = request.form['email']
            senha = request.form['senha']
            instituicao_9_classe = request.form['instituicao9'].capitalize()
            ano_conclusao = request.form['anoConclusao']
            media_final = request.form['mediaFinal']
            turno_preferido = request.form['turno']
            telefone = request.form['telefone']
            municipio = request.form['municipio'].capitalize()
            bairro = request.form['bairro'].capitalize()
            provincia = request.form['provincia'].capitalize()

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
            adicionar_log(f'Novo aluno cadastrado: {novo_aluno.nome_completo}',
                          tipo='informação', usuario=novo_aluno, tipo_usuario='aluno')

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
            adicionar_log(f'Erro de banco de dados ao cadastrar aluno: {corpo_mensagem}',
                          tipo='erro', usuario=None, tipo_usuario='aluno')
            return redirect(url_for('cadastro'))

        except Exception as e:
            flash({'titulo': 'Erro inesperado',
                   'corpo': f'Erro inesperado: {str(e)}'})
            adicionar_log(f'Erro inesperado ao cadastrar aluno: {str(e)}',
                          tipo='erro', usuario=None, tipo_usuario='aluno')
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

                adicionar_log(f'Upload de documentos realizado com sucesso para o aluno {current_user.nome_completo}',
                              tipo='informação', usuario=current_user, tipo_usuario='aluno')
                flash({'titulo': 'Sucesso',
                       'corpo': 'Documentos enviados com sucesso!'})
                return redirect(url_for('portal_estudante', aluno=current_user))

            else:
                flash(
                    {'titulo': 'Erro', 'corpo': 'Formato de arquivo inválido! Certifique-se de que os arquivos são do tipo permitido.'})
                adicionar_log(f'Erro ao tentar fazer upload de documentos para o aluno {current_user.nome_completo} - Formato de arquivo inválido.',
                              tipo='erro', usuario=current_user, tipo_usuario='aluno')
                return redirect(url_for('upload', user_id=user_id))

        except Exception as e:
            flash({'titulo': 'Erro Durante o Upload',
                   'corpo': f'Erro inesperado ao processar o upload: {str(e)}'})
            adicionar_log(f'Erro ao tentar fazer upload de documentos para o aluno {current_user.nome_completo}: {str(e)}',
                          tipo='erro', usuario=current_user, tipo_usuario='aluno')
            return redirect(url_for('upload', user_id=user_id))

    return render_template('upload.html', user_id=user_id)

# Login route


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
        funcionario = Funcionario.query.filter_by(email=email).first()
        admin = Admin.query.filter_by(email=email).first()

        user = None
        user_type = None

        if aluno and check_password_hash(aluno.senha, senha):
            user = aluno
            user_type = "aluno"
        elif funcionario and check_password_hash(funcionario.senha, senha):
            user = funcionario
            user_type = "funcionario"
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
            elif user_type == "funcionario":
                return redirect(url_for('portal_instituicao'))
            elif user_type == "admin":
                return redirect(url_for('painel_admin'))
        else:
            adicionar_log(
                f"Falha ao tentar login com email: {request.form['email']}", tipo='erro', usuario=None, tipo_usuario='desconhecido')

            flash({
                'titulo': 'Erro',
                'corpo': 'Credenciais inválidas. Verifique o email e a senha.'})

    return render_template('login.html')

# Função para verificar se o aluno tem todos os documentos
def verificar_documentos_completos(aluno):
    return (
        aluno.frente_bilhete_path is not None and
        aluno.verso_bilhete_path is not None and
        aluno.certificado_path is not None
    )

# Rota para listar as inscrições e escolas
@app.route('/portal_estudante')
@aluno_required
@login_required
def portal_estudante():
    # Verifica se o usuário é um aluno
    aluno = Aluno.query.filter_by(id=current_user.id).first()
    if not aluno:
        flash('Apenas alunos podem acessar esta página.', 'danger')
        return redirect(url_for('index'))

    # Verifica se os documentos estão completos
    documentos_completos = verificar_documentos_completos(aluno)

    # Busca as inscrições do aluno usando o novo backref
    inscricoes = aluno.inscricoes_rel  # Alterado de 'inscricoes' para 'inscricoes_rel'

    # Busca todas as escolas disponíveis
    escolas = Instituicao.query.all()

    return render_template(
        'portal_estudante.html',
        documentos_completos=documentos_completos,
        inscricoes=inscricoes,
        escolas=escolas,
        aluno=current_user
    )

@app.route('/editar_perfil', methods=['GET', 'POST'])
@aluno_required
@login_required
def editar_perfil():
    aluno = Aluno.query.get(current_user.id)

    if request.method == 'POST':
        # Obtenha os dados do formulário
        email = request.form.get('email')
        telefone = request.form.get('telefone')
        senha = request.form.get('senha')

        # Atualize apenas os campos que podem ser editados
        aluno.email = email
        aluno.telefone = telefone

        # Verifique se o campo de senha foi preenchido
        if senha:
            aluno.senha = generate_password_hash(senha)

        # Salve as alterações no banco de dados
        db.session.commit()
        flash('Informações atualizadas com sucesso!', 'success')
        return redirect(url_for('editar_perfil'))

    return redirect(url_for('portal_estudante'))

# Rota para criar uma inscrição
@app.route('/criar_inscricao', methods=['POST'])
@aluno_required
@login_required
def criar_inscricao():
    aluno = Aluno.query.filter_by(id=current_user.id).first()
    if not aluno:
        flash('Apenas alunos podem fazer inscrições.', 'danger')
        return redirect(url_for('portal_estudante') + '#inscricoes')

    if not verificar_documentos_completos(aluno):
        flash('Complete todos os documentos para fazer a inscrição.', 'danger')
        return redirect(url_for('portal_estudante') + '#inscricoes')

    escola_id = request.form.get('escola')
    curso = request.form.get('curso')  # Pegar o curso selecionado no formulário

    escola = Instituicao.query.get(escola_id)
    if not escola:
        flash('Escola inválida.', 'danger')
        return redirect(url_for('portal_estudante') + '#inscricoes')

    # Contar quantas inscrições esse aluno já tem na escola
    total_inscricoes = Inscricao.query.filter_by(aluno_id=aluno.id, instituicao_id=escola_id).count()

    if total_inscricoes >= 2:
        flash('Você já atingiu o limite de inscrições para esta escola.', 'warning')
        return redirect(url_for('portal_estudante') + '#inscricoes')

    # Criar a nova inscrição
    nova_inscricao = Inscricao(
        aluno_id=aluno.id,
        instituicao_id=escola_id,
        curso=curso,
        status='Pendente'
    )
    db.session.add(nova_inscricao)
    db.session.commit()

    flash('Inscrição realizada com sucesso!', 'success')
    return redirect(url_for('portal_estudante') + '#inscricoes')




# Rota para cancelar uma inscrição
@app.route('/cancelar_inscricao/<int:inscricao_id>', methods=['POST'])
@login_required
@aluno_required
def cancelar_inscricao(inscricao_id):
    # Verifica se a inscrição é do aluno logado e se está pendente
    inscricao = Inscricao.query.filter_by(
        id=inscricao_id,
        aluno_id=current_user.id,
        status='Pendente'
    ).first()

    if not inscricao:
        flash('Inscrição não encontrada ou não pode ser cancelada.', 'danger')
        return redirect(url_for('portal_estudante') + '#inscricoes')

    # Deleta a inscrição
    db.session.delete(inscricao)
    db.session.commit()

    flash('Inscrição cancelada com sucesso.', 'success')
    return redirect(url_for('portal_estudante') + '#inscricoes')


#@app.route('/portal_estudante')
#@login_required
#@aluno_required
#def portal_estudante():
    # Página do portal do estudante
    #return render_template('portal_estudante.html', aluno=current_user)

# Rota do Painel Admin
# Rota do Painel Admin
@app.route('/painel_admin', methods=['GET', 'POST'])
@login_required
@admin_required
def painel_admin():
    # Verifica se há dados salvos na sessão
    alunos = []
    search = ''

    if 'alunos' in session:
        alunos_ids = session.pop('alunos')  # Remove os dados após usar
        alunos = Aluno.query.filter(Aluno.id.in_(alunos_ids)).all()

    if 'search' in session:
        search = session.pop('search')

    # Se não houver dados na sessão, lista todos
    if not alunos:
        alunos = Aluno.query.all()

    logs_sistema = Log.query.order_by(Log.data_hora.desc()).limit(30).all()
    total_alunos = Aluno.query.count()
    total_instituicoes = Instituicao.query.count()

    alunos_recentes = Aluno.query.order_by(
        Aluno.created_at.desc()).limit(5).all()
    instituicoes = Instituicao.query.all()

    por_concluir = InteresseInstituicao.query.filter_by(
        status='pendente').all()
    nao_concluir = InteresseInstituicao.query.filter_by(
        status='concluido').all()
    agora = datetime.now()

    # Mensagens no painel administrativo
    mensagens_nao_lidas = Mensagem.query.filter_by(lida=False).all()
    total_mensagens_nao_lidas = Mensagem.query.filter_by(lida=False).count()
    mensagens_lidas = Mensagem.query.filter_by(lida=True).all()

    return render_template('painel_admin.html',
                           agora=agora,
                           admin=current_user,
                           alunos=alunos,
                           search=search,
                           logs_sistema=logs_sistema,
                           total_alunos=total_alunos,
                           alunos_recentes=alunos_recentes,
                           por_concluir=por_concluir,
                           nao_concluir=nao_concluir,
                           total_instituicoes=total_instituicoes,
                           instituicoes=instituicoes,
                           mensagens_nao_lidas=mensagens_nao_lidas,
                           mensagens_lidas=mensagens_lidas,
                           total_mensagens_nao_lidas=total_mensagens_nao_lidas
                           )


# Marcar mensagem como lida/não lida
@app.route('/marcar_mensagem/<int:mensagem_id>', methods=['POST'])
@login_required
@admin_required
def marcar_mensagem(mensagem_id):
    mensagem = Mensagem.query.get(mensagem_id)

    if not mensagem:
        flash({'titulo': 'Erro', 'corpo': 'Mensagem não encontrada.'}, 'danger')
        return redirect(url_for('painel_admin') + '#mensagens')

    # Alterna entre lida e não lida
    mensagem.lida = not mensagem.lida
    db.session.commit()

    flash({'titulo': 'Sucesso', 'corpo': 'Status da mensagem atualizado.'})
    return redirect(url_for('painel_admin') + '#mensagens')


# Deletar mensagem
@app.route('/deletar_mensagem/<int:mensagem_id>', methods=['POST'])
@login_required
@admin_required
def deletar_mensagem(mensagem_id):
    mensagem = Mensagem.query.get(mensagem_id)

    if not mensagem:
        flash({'titulo': 'Erro', 'corpo': 'Mensagem não encontrada.'}, 'danger')
        return redirect(url_for('painel_admin') + '#mensagens')

    db.session.delete(mensagem)
    db.session.commit()

    flash({'titulo': 'Sucesso', 'corpo': 'Mensagem excluída com sucesso.'})
    return redirect(url_for('painel_admin') + '#mensagens')


@app.route('/buscar_alunos', methods=['GET'])
@login_required
@admin_required
def buscar_alunos():
    search = request.args.get('search', '')

    alunos = Aluno.query.filter(
        (Aluno.id.like(f"%{search}%")) |
        (Aluno.nome_completo.like(f"%{search}%")) |
        (Aluno.numero_bilhete.like(f"%{search}%"))
    ).all() if search else Aluno.query.all()

    # Salvar na sessão sem remover após o primeiro uso
    session['alunos'] = [aluno.id for aluno in alunos]
    session['search'] = search

    return redirect(url_for('painel_admin') + '#alunos')


@app.route('/atualizar_aluno/<int:aluno_id>', methods=['POST'])
@login_required
@admin_required
def atualizar_aluno(aluno_id):
    aluno = Aluno.query.filter_by(id=aluno_id).first_or_404()

    try:
        aluno.nome_completo = request.form['nome_completo']
        aluno.numero_bilhete = request.form['numero_bilhete'].capitalize()
        aluno.genero = request.form['genero']
        aluno.email = request.form['email']
        aluno.instituicao_9_classe = request.form['instituicao_9_classe']
        aluno.ano_conclusao = request.form['ano_conclusao']
        aluno.media_final = request.form['media_final']
        aluno.turno_preferido = request.form['turno_preferido']
        aluno.telefone = request.form['telefone']
        aluno.municipio = request.form['municipio']
        aluno.bairro = request.form['bairro']
        aluno.provincia = request.form['provincia']

        # Atualizar data de nascimento
        try:
            aluno.data_nascimento = datetime.strptime(
                request.form['data_nascimento'], '%Y-%m-%d').date()
        except ValueError:
            flash('Erro: Data de nascimento inválida. Use o formato AAAA-MM-DD.', 'danger')
            return redirect(url_for('painel_admin') + '#alunos')

        # Atualizar senha se fornecida
        senha = request.form.get('senha')
        if senha:
            aluno.senha = generate_password_hash(senha)

        db.session.commit()
        flash('Dados do aluno atualizados com sucesso!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao atualizar o aluno: {str(e)}', 'danger')

    return redirect(url_for('painel_admin') + '#alunos')


@app.route('/deletar_aluno/<int:aluno_id>', methods=['POST'])
@login_required
@admin_required
def deletar_aluno(aluno_id):
    aluno = Aluno.query.filter_by(id=aluno_id).first_or_404()

    try:
        db.session.delete(aluno)
        db.session.commit()
        flash('Aluno excluído com sucesso!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir aluno: {str(e)}', 'danger')

    return redirect(url_for('painel_admin') + '#alunos')


@app.route('/portal_instituicao')
@login_required
@funcionario_required
def portal_instituicao():
    """Portal da Instituição: mostra detalhes e inscrições de alunos"""
    instituicao = Instituicao.query.filter_by(id=current_user.instituicao_id).first()
    funcionarios = Funcionario.query.filter_by(instituicao_id=current_user.instituicao_id).all()
    senha_padrao = check_password_hash(current_user.senha, "12345")

    # Obtendo filtros da URL
    media_min = request.args.get('media_min', type=float)
    idade_min = request.args.get('idade_min', type=int)
    status_filtro = request.args.get('status')

    # Buscar apenas alunos com inscrições nesta instituição
    inscricoes_query = Inscricao.query.filter_by(instituicao_id=current_user.instituicao_id)

    # Aplicando filtros
    if media_min:
        inscricoes_query = inscricoes_query.join(Aluno).filter(Aluno.media_final >= media_min)
    if idade_min:
        ano_atual = datetime.now().year
        inscricoes_query = inscricoes_query.join(Aluno).filter((ano_atual - Aluno.data_nascimento.year) >= idade_min)
    if status_filtro and status_filtro != "Todos":
        inscricoes_query = inscricoes_query.filter_by(status=status_filtro)

    inscricoes = inscricoes_query.all()

    return render_template(
        'portal_instituicao.html',
        user=current_user,
        instituicao=instituicao,
        funcionarios=funcionarios,
        senha_padrao=senha_padrao,
        inscricoes=inscricoes
    )

@app.route('/atualizar_inscricao/<int:inscricao_id>', methods=['POST'])
@login_required
@funcionario_required
def atualizar_inscricao(inscricao_id):
    inscricao = Inscricao.query.get_or_404(inscricao_id)

    # Verifica se a inscrição pertence à instituição do usuário logado
    if inscricao.instituicao_id != current_user.instituicao_id:
        flash("Você não tem permissão para modificar esta inscrição.", "danger")
        return redirect(url_for('portal_instituicao'))

    acao = request.form.get('acao')
    mensagem = request.form.get('mensagem')  # Captura a mensagem do formulário

    if acao == "aceitar":
        inscricao.status = "Aceito"
        flash("Inscrição aceita com sucesso!", "success")
    elif acao == "rejeitar":
        inscricao.status = "Rejeitado"
        flash("Inscrição rejeitada.", "warning")

    # Salva a mensagem se houver
    if mensagem:
        inscricao.mensagem_instituicao = mensagem
        flash("Mensagem enviada com sucesso!", "info")

    db.session.commit()
    return redirect(url_for('portal_instituicao'))


@app.route('/funcionario/editar_perfil', methods=['POST'])
@login_required
@funcionario_required
def funcionario_editar_perfil():
    email = request.form.get('email')
    telefone = request.form.get('telefone')
    nova_senha = request.form.get('nova_senha')
    confirmar_senha = request.form.get('confirmar_senha')

    # Verifica se o email já pertence a outro usuário
    if Funcionario.query.filter(Funcionario.email == email, Funcionario.id != current_user.id).first():
        flash("Este email já está em uso.", "danger")
        return redirect(url_for('portal_instituicao'))

    # Atualiza email e telefone
    current_user.email = email
    current_user.telefone = telefone

    # Se a senha foi fornecida, verifica e altera
    if nova_senha:
        if nova_senha != confirmar_senha:
            flash("As senhas não coincidem.", "danger")
            return redirect(url_for('portal_instituicao'))

        if check_password_hash(current_user.senha, nova_senha):
            flash("Escolha uma senha diferente da atual.", "warning")
            return redirect(url_for('portal_instituicao'))

        current_user.senha = generate_password_hash(nova_senha)

    # Salvar mudanças no banco de dados
    db.session.commit()

    flash("Perfil atualizado com sucesso!", "success")
    return redirect(url_for('portal_instituicao'))

@app.route('/criar_funcionario', methods=['POST'])
@login_required
@funcionario_required
def criar_funcionario():
    """Permite que um funcionário Master crie novos funcionários para sua instituição."""
    if current_user.permissao != 'master':
        flash("Apenas funcionários Master podem criar novos funcionários!", "danger")
        return redirect(url_for('portal_instituicao'))

    nome_completo = request.form['nome_completo']
    email = request.form['email']
    senha_padrao = "12345"
    senha_hash = generate_password_hash(senha_padrao)
    telefone = request.form.get('telefone', '')
    permissao = request.form['permissao']

    # Verifica se o email já existe
    if Funcionario.query.filter_by(email=email).first():
        flash("Já existe um funcionário com este email!", "danger")
        return redirect(url_for('portal_instituicao'))



    novo_funcionario = Funcionario(
        nome_completo=nome_completo,
        email=email,
        senha=senha_hash,
        telefone=telefone,
        permissao=permissao,
        instituicao_id=current_user.instituicao_id  # Define a instituição do Master
    )

    db.session.add(novo_funcionario)
    db.session.commit()

    flash("Funcionário criado com sucesso!", "success")
    return redirect(url_for('portal_instituicao'))


@app.route('/remover_funcionario/<int:funcionario_id>', methods=['POST'])
@login_required
@funcionario_required
def remover_funcionario(funcionario_id):
    """Permite que um funcionário Master remova funcionários da sua instituição."""
    if current_user.permissao != 'master':
        flash("Apenas funcionários Master podem remover funcionários!", "danger")
        return redirect(url_for('portal_instituicao'))

    funcionario = Funcionario.query.get(funcionario_id)

    if not funcionario or funcionario.instituicao_id != current_user.instituicao_id:
        flash("Funcionário não encontrado ou não pertence à sua instituição!", "danger")
        return redirect(url_for('portal_instituicao'))

    db.session.delete(funcionario)
    db.session.commit()

    flash("Funcionário removido com sucesso!", "success")
    return redirect(url_for('portal_instituicao'))

@app.route('/editar_instituicao/<int:instituicao_id>', methods=['POST'])
@login_required
@funcionario_required
def editar_instituicao(instituicao_id):
    if current_user.permissao != 'master':
        flash("Você não tem permissão para editar esta instituição.", "danger")
        return redirect(url_for('portal_instituicao'))

    instituicao = Instituicao.query.get_or_404(instituicao_id)

    instituicao.nome_instituicao = request.form.get('nome_instituicao')
    instituicao.email = request.form.get('email')
    instituicao.endereco = request.form.get('endereco')
    instituicao.cidade = request.form.get('cidade')
    instituicao.provincia = request.form.get('provincia')
    instituicao.telefone = request.form.get('telefone')
    instituicao.descricao = request.form.get('descricao')
    instituicao.numero_vagas = request.form.get('numero_vagas')
    instituicao.status = request.form.get('status')
    instituicao.cursos = request.form.get('cursos')

    db.session.commit()
    flash("Informações da instituição atualizadas com sucesso!", "success")
    return redirect(url_for('portal_instituicao'))


@app.route('/instituicoes')
def instituicoes():
    return render_template('txt_instituicoes.html')


@app.route('/instituicoes/interesse', methods=['GET', 'POST'])
def interesse():
    if request.method == 'POST':
        nome_instituicao = request.form['nome_instituicao']
        nome_responsavel = request.form['nome_responsavel']
        email = request.form['email']
        telefone = request.form['telefone']

        # Salva o interesse no banco de dados
        novo_interesse = InteresseInstituicao(
            nome_instituicao=nome_instituicao,
            nome_responsavel=nome_responsavel,
            email=email,
            telefone=telefone
        )
        db.session.add(novo_interesse)
        db.session.commit()

        # Diretório para salvar os documentos
        upload_folder = os.path.join(
            app.config['UPLOAD_FOLDER'], str(novo_interesse.id))
        os.makedirs(upload_folder, exist_ok=True)

        # Salvar e renomear os documentos
        for file in request.files.getlist('documentos'):
            if file and file.filename.endswith('.pdf'):
                # Renomeia com o nome da instituição e um índice para evitar conflitos
                index = request.files.getlist('documentos').index(file) + 1
                nome_limpo = nome_instituicao.replace(' ', '_').lower()
                novo_nome = f"{nome_limpo}_{index}.pdf"
                caminho_arquivo = os.path.join(upload_folder, novo_nome)
                file.save(caminho_arquivo)

                # Salva as informações no banco de dados
                novo_documento = Documento(
                    nome_arquivo=novo_nome,
                    caminho_arquivo=caminho_arquivo,
                    interesse_id=novo_interesse.id
                )
                db.session.add(novo_documento)

        db.session.commit()

        flash('Cadastro realizado com sucesso!', 'success')
        return redirect(url_for('index'))

    return redirect(url_for('instituicoes'))


@app.route('/admin/download/<int:interesse_id>/<string:arquivo>', methods=['GET'])
@admin_required
@login_required
def baixar_documento(interesse_id, arquivo):
    try:
        # Define o diretório base usando o interesse_id
        directory = os.path.join('static', 'uploads', str(interesse_id))
        return send_from_directory(directory=directory, path=arquivo, as_attachment=True)
    except FileNotFoundError:
        abort(404)


@app.route('/admin/concluir/<int:id>', methods=['POST'])
@admin_required
@login_required
def marcar_concluido(id):
    interesse = InteresseInstituicao.query.get_or_404(id)
    interesse.status = 'concluido'
    db.session.commit()
    flash('Demonstração de interesse marcada como concluída.', 'success')
    return redirect(url_for('painel_admin') + '#DemonstraçõesDeInteresse')


@app.route('/remover_interesse/<int:id>', methods=['POST'])
@admin_required
@login_required
def remover_interesse(id):
    interesse = InteresseInstituicao.query.get_or_404(id)

    for documento in interesse.documentos:
        db.session.delete(documento)

    db.session.delete(interesse)
    db.session.commit()

    flash('Interesse e documentos excluídos com sucesso!', 'success')
    return redirect(url_for('painel_admin') + '#DemonstraçõesDeInteresse')


@app.route('/criar_instituicao', methods=['GET', 'POST'])
@admin_required
@login_required
def criar_instituicao():
    if request.method == 'POST':
        nome_instituicao = request.form['nome_instituicao']
        email_instituicao = request.form['email_instituicao']
        nome_master = request.form['nome_master']
        email_master = request.form['email_master']
        senha_padrao = "12345"
        senha_hash = generate_password_hash(senha_padrao)
        telefone_master = request.form['telefone_master']

        # Verifica se o email do master já existe
        existe_master = Funcionario.query.filter_by(email=email_master).first()
        if existe_master:
            flash('Já existe um funcionário com este email!', 'danger')
            return redirect(url_for('painel_admin') + '#criar-instituicoes')

        # Cria a Instituição
        instituicao = Instituicao(
            nome_instituicao=nome_instituicao, email=email_instituicao)
        db.session.add(instituicao)
        db.session.commit()  # Confirma para obter o ID da instituição

        # Cria o Funcionário Master
        master = Funcionario(
            nome_completo=nome_master,
            email=email_master,
            senha=senha_hash,
            telefone=telefone_master,
            permissao='master',
            instituicao_id=instituicao.id
        )
        db.session.add(master)
        db.session.commit()

        flash('Instituição e Master criados com sucesso!', 'success')
        return redirect(url_for('painel_admin') + '#criar-instituicoes')

    return redirect(url_for('painel_admin') + '#criar-instituicoes')
# Debug


def criar_aluno_aleatorio():
    nome_completo = faker.name()
    data_nascimento = faker.date_of_birth(minimum_age=15, maximum_age=20)

    # Número do bilhete: 9 números + 2 letras + 3 números
    numeros_iniciais = faker.random_number(digits=9, fix_len=True)
    letras = faker.random_uppercase_letter() + faker.random_uppercase_letter()
    numeros_finais = faker.random_number(digits=3, fix_len=True)
    numero_bilhete = f"{numeros_iniciais}{letras}{numeros_finais}"

    genero = faker.random_element(elements=('Masculino', 'Feminino'))
    email = faker.unique.email()
    senha = generate_password_hash('12345')  # Senha padrão com hash
    instituicao_9_classe = faker.company()
    ano_conclusao = faker.random_int(min=2000, max=2025)
    media_final = round(faker.pyfloat(min_value=10.0, max_value=20.0), 2)
    turno_preferido = faker.random_element(
        elements=('Manhã', 'Tarde', 'Noite'))

    # Telefone: 9 dígitos começando com 9
    telefone = f"9{faker.random_number(digits=8, fix_len=True)}"

    provincias = [
        'Bengo', 'Benguela', 'Bié', 'Cabinda', 'Cuando', 'Cuanza Norte', 'Cuanza Sul',
        'Cubango', 'Cunene', 'Huambo', 'Huila', 'Icole Bengo', 'Luanda', 'Lunda Sul',
        'Lunda Norte', 'Malanje', 'Moxico', 'Moxico Leste', 'Namibe', 'Uíge', 'Zaire'
    ]
    municipio = faker.city()
    bairro = faker.street_name()
    provincia = faker.random_element(
        elements=provincias)

    # Criação do objeto Aluno
    novo_aluno = Aluno(
        nome_completo=nome_completo,
        data_nascimento=data_nascimento,
        numero_bilhete=numero_bilhete,
        genero=genero,
        email=email,
        senha=senha,
        instituicao_9_classe=instituicao_9_classe,
        ano_conclusao=ano_conclusao,
        media_final=media_final,
        turno_preferido=turno_preferido,
        telefone=telefone,  # Agora com o formato correto
        municipio=municipio,
        bairro=bairro,
        provincia=provincia
    )

    # Adiciona ao banco de dados
    db.session.add(novo_aluno)
    db.session.commit()

    return  # Retorna o nome do aluno criado para exibir como feedback


def criar_instituicao_aleatoria():
    """Cria uma instituição fictícia e um funcionário Master associado"""
    nome_instituicao = faker.company() + " Escola Secundaria"
    email_instituicao = faker.unique.email()

    nome_master = faker.name()
    email_master = faker.unique.email()
    senha_master = "12345"  # Pode ser gerada dinamicamente
    senha_hash = generate_password_hash(senha_master)
    telefone_master = f"9{faker.random_number(digits=8, fix_len=True)}"

    # Verifica se já existe um funcionário com esse email
    if Funcionario.query.filter_by(email=email_master).first():
        flash("Erro ao gerar instituição: email do master já existe!", "danger")
        return

    # Criar a instituição
    instituicao = Instituicao(
        nome_instituicao=nome_instituicao,
        email=email_instituicao
    )
    db.session.add(instituicao)
    db.session.commit()  # Para obter o ID da instituição

    # Criar o funcionário Master
    master = Funcionario(
        nome_completo=nome_master,
        email=email_master,
        senha=senha_hash,
        telefone=telefone_master,
        permissao="master",
        instituicao_id=instituicao.id
    )
    db.session.add(master)
    db.session.commit()

    flash(f"Instituição '{nome_instituicao}' e Master '{nome_master}' criados!", "success")


debug_buttons = [
    "Criar admin",
    "Criar 1 aluno",
    "Criar 10 aluno",
    "Criar 50 aluno",
    "Criar 1 instituição",
    "Por definir",
    "Por definir",
    "Por definir",
    "Por definir",
    "Por definir"
]


@app.route('/debug')
def debug():
    return render_template('debug.html', debug_buttons=debug_buttons)


@app.route('/debug_action/<int:action_id>', methods=['POST'])
def debug_action(action_id):
    # Obtém o nome da ação baseado no ID
    action_name = debug_buttons[action_id - 1]
    flash({'titulo': 'debug', 'corpo': f"Ação {action_name} executada com sucesso!"})

    # Aqui você pode adicionar a lógica específica para cada ação
    if action_id == 1:
        # Criar um novo admin
        novo_admin = Admin(
            nome_completo="Administrador",
            email="admin@escola.com",
            senha=generate_password_hash(
                "12345")  # Senha segura com hash
        )
        db.session.add(novo_admin)
        db.session.commit()

        pass
    elif action_id == 2:
        criar_aluno_aleatorio()
        pass
    elif action_id == 3:
        for _ in range(10):
            criar_aluno_aleatorio()
        pass
    elif action_id == 4:
        for _ in range(50):
            criar_aluno_aleatorio()
        pass
    elif action_id == 5:
        criar_instituicao_aleatoria()
        pass

    # Redireciona de volta para o painel de debug
    return redirect(url_for('debug'))


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
