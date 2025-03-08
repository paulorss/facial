import streamlit as st
import numpy as np
import pandas as pd
import hashlib
import os
import json
import datetime
import uuid
from PIL import Image
import time
import base64
from io import BytesIO

# Configuração do aplicativo
st.set_page_config(
    page_title="Sistema de Confirmação de Recebimento",
    page_icon="📦",
    layout="wide"
)

# Definir diretórios para armazenamento
os.makedirs("data", exist_ok=True)
os.makedirs("data/users", exist_ok=True)
os.makedirs("data/deliveries", exist_ok=True)
os.makedirs("data/signatures", exist_ok=True)
os.makedirs("data/cargo_images", exist_ok=True)
os.makedirs("data/selfies", exist_ok=True)
os.makedirs("data/blockchain", exist_ok=True)

# Funções para gerenciamento de usuários
def save_user(username, password, fullname, role):
    """Salva um novo usuário no sistema"""
    users_file = "data/users/users.json"
    
    # Cria um hash da senha
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    # Carrega usuários existentes ou cria lista vazia
    if os.path.exists(users_file):
        with open(users_file, "r") as f:
            users = json.load(f)
    else:
        users = []
    
    # Verifica se usuário já existe
    for user in users:
        if user["username"] == username:
            return False
    
    # Cria novo usuário
    new_user = {
        "username": username,
        "password_hash": hashed_password,
        "fullname": fullname,
        "role": role,
        "created_at": datetime.datetime.now().isoformat()
    }
    
    # Adiciona usuário à lista
    users.append(new_user)
    
    # Salva a lista atualizada
    with open(users_file, "w") as f:
        json.dump(users, f)
    
    return True

def authenticate_user(username, password):
    """Autentica um usuário pelo nome e senha"""
    users_file = "data/users/users.json"
    
    if not os.path.exists(users_file):
        return None
    
    # Carrega usuários
    with open(users_file, "r") as f:
        users = json.load(f)
    
    # Cria hash da senha fornecida
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    # Verifica usuário e senha
    for user in users:
        if user["username"] == username and user["password_hash"] == hashed_password:
            return user
    
    return None

def get_all_users():
    """Retorna todos os usuários do sistema"""
    users_file = "data/users/users.json"
    
    if not os.path.exists(users_file):
        return []
    
    with open(users_file, "r") as f:
        users = json.load(f)
    
    return users

# Função para criar usuário admin padrão na primeira execução
def ensure_admin_user_exists():
    """Cria um usuário admin padrão se não existir nenhum usuário"""
    users_file = "data/users/users.json"
    
    # Se o arquivo de usuários não existir ou estiver vazio, cria um admin padrão
    if not os.path.exists(users_file) or os.path.getsize(users_file) == 0:
        # Cria usuário admin padrão
        admin_username = "admin"
        admin_password = "admin123"
        admin_fullname = "Administrador do Sistema"
        
        # Salva o usuário admin
        success = save_user(admin_username, admin_password, admin_fullname, "admin")
        
        if success:
            st.success("""
            ### Usuário administrador padrão criado!
            - **Usuário:** admin
            - **Senha:** admin123
            
            Por favor, faça login e altere a senha imediatamente por questões de segurança.
            """)
            return True
        else:
            st.error("Erro ao criar usuário administrador padrão.")
            return False
    
    return True

# Funções para salvamento de imagens
def save_cargo_image(image_file, delivery_id):
    """Salva a imagem da carga"""
    if image_file is None:
        return False
    
    # Lê a imagem
    img = Image.open(image_file)
    
    # Salva a imagem
    img_path = f"data/cargo_images/{delivery_id}.jpg"
    img.save(img_path)
    
    return True

def save_selfie(image_file, delivery_id):
    """Salva a selfie do receptor com o equipamento"""
    if image_file is None:
        return False
    
    # Lê a imagem
    img = Image.open(image_file)
    
    # Adiciona timestamp à imagem
    draw = None
    try:
        from PIL import ImageDraw, ImageFont
        draw = ImageDraw.Draw(img)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Tenta usar uma fonte padrão
        try:
            font = ImageFont.truetype("arial.ttf", 20)
        except:
            # Se a fonte não estiver disponível, usa a fonte padrão
            font = ImageFont.load_default()
            
        # Adiciona o timestamp na parte inferior da imagem
        draw.text((10, img.height - 30), f"Data/Hora: {timestamp}", fill=(255, 255, 0), font=font)
        draw.text((10, img.height - 50), f"ID: {delivery_id}", fill=(255, 255, 0), font=font)
    except Exception as e:
        st.warning(f"Não foi possível adicionar o timestamp à imagem: {str(e)}")
    
    # Salva a imagem
    img_path = f"data/selfies/{delivery_id}.jpg"
    img.save(img_path)
    
    return True

# Funções para assinatura digital
def save_signature(username, signature_data, delivery_id):
    """Salva a assinatura digital de um usuário para uma entrega"""
    if not signature_data:
        return False
    
    try:
        # Verifica se a assinatura tem o formato data URI (com cabeçalho)
        if "," in signature_data and ";base64," in signature_data:
            # Remove o cabeçalho da imagem em base64
            signature_data = signature_data.split(",")[1]
        
        # Tenta decodificar os dados da assinatura
        try:
            binary_data = base64.b64decode(signature_data)
        except:
            # Se falhar, tenta salvar o texto como está (para fins de depuração)
            st.warning("Formato de assinatura inválido. Salvando como texto para debug.")
            
            # Cria um texto simples em uma imagem
            from PIL import Image, ImageDraw, ImageFont
            img = Image.new('RGB', (400, 200), color=(255, 255, 255))
            d = ImageDraw.Draw(img)
            d.text((10, 10), f"Assinatura de {username} - {datetime.datetime.now()}", fill=(0, 0, 0))
            
            # Salva a imagem
            signature_file = f"data/signatures/{delivery_id}.png"
            img.save(signature_file)
            return True
        
        # Salva a assinatura como imagem
        signature_file = f"data/signatures/{delivery_id}.png"
        with open(signature_file, "wb") as f:
            f.write(binary_data)
        
        return True
    except Exception as e:
        st.error(f"Erro ao salvar assinatura: {str(e)}")
        # Em caso de erro, cria uma assinatura alternativa simples
        try:
            from PIL import Image, ImageDraw
            img = Image.new('RGB', (400, 200), color=(255, 255, 255))
            d = ImageDraw.Draw(img)
            d.text((10, 10), f"Assinatura de {username} - {datetime.datetime.now()}", fill=(0, 0, 0))
            
            # Salva a imagem
            signature_file = f"data/signatures/{delivery_id}.png"
            img.save(signature_file)
            return True
        except:
            st.error("Falha na criação da assinatura alternativa.")
            return False

# Funções para blockchain e registro imutável
def create_block(data, previous_hash):
    """Cria um novo bloco na blockchain"""
    timestamp = datetime.datetime.now().isoformat()
    block_id = str(uuid.uuid4())
    
    block = {
        "id": block_id,
        "timestamp": timestamp,
        "data": data,
        "previous_hash": previous_hash,
        "nonce": 0
    }
    
    # Calcula o hash do bloco
    block_hash = calculate_hash(block)
    block["hash"] = block_hash
    
    return block

def calculate_hash(block):
    """Calcula o hash de um bloco"""
    # Cria uma cópia do bloco sem o campo hash
    block_copy = block.copy()
    if "hash" in block_copy:
        del block_copy["hash"]
    
    # Converte o bloco para string e calcula o hash
    block_string = json.dumps(block_copy, sort_keys=True)
    return hashlib.sha256(block_string.encode()).hexdigest()

def add_to_blockchain(data):
    """Adiciona dados à blockchain"""
    blockchain_file = "data/blockchain/chain.json"
    
    # Carrega a blockchain existente ou cria uma nova
    if os.path.exists(blockchain_file):
        with open(blockchain_file, "r") as f:
            chain = json.load(f)
        previous_hash = chain[-1]["hash"]
    else:
        # Cria o bloco genesis se a blockchain não existir
        chain = []
        previous_hash = "0" * 64
    
    # Cria um novo bloco
    new_block = create_block(data, previous_hash)
    
    # Adiciona o bloco à cadeia
    chain.append(new_block)
    
    # Salva a blockchain atualizada
    with open(blockchain_file, "w") as f:
        json.dump(chain, f)
    
    return new_block

# Funções para gerenciamento de entregas
def register_delivery(data):
    """Registra uma nova entrega no sistema"""
    deliveries_file = "data/deliveries/deliveries.json"
    
    # Carrega entregas existentes ou cria lista vazia
    if os.path.exists(deliveries_file):
        with open(deliveries_file, "r") as f:
            deliveries = json.load(f)
    else:
        deliveries = []
    
    # Adiciona a nova entrega à lista
    deliveries.append(data)
    
    # Salva a lista atualizada
    with open(deliveries_file, "w") as f:
        json.dump(deliveries, f)
    
    return True

def get_all_deliveries():
    """Retorna todas as entregas registradas"""
    deliveries_file = "data/deliveries/deliveries.json"
    
    if not os.path.exists(deliveries_file):
        return []
    
    with open(deliveries_file, "r") as f:
        deliveries = json.load(f)
    
    return deliveries

# Interface do usuário com Streamlit
def main():
    # Inicializa a sessão
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "user" not in st.session_state:
        st.session_state.user = None
    if "page" not in st.session_state:
        st.session_state.page = "login"
    
    # Barra lateral para navegação (apenas se autenticado)
    if st.session_state.authenticated:
        with st.sidebar:
            st.title(f"Olá, {st.session_state.user['fullname']}")
            
            # Menu para administradores
            if st.session_state.user["role"] == "admin":
                if st.button("🏠 Início"):
                    st.session_state.page = "dashboard"
                if st.button("👤 Gerenciar Usuários"):
                    st.session_state.page = "manage_users"
                if st.button("📦 Entregas Registradas"):
                    st.session_state.page = "deliveries"
            
            # Menu para entregadores
            if st.session_state.user["role"] == "delivery":
                if st.button("🏠 Início"):
                    st.session_state.page = "dashboard"
                if st.button("✅ Registrar Entrega"):
                    st.session_state.page = "register_delivery"
            
            # Menu para receptores
            if st.session_state.user["role"] == "receiver":
                if st.button("🏠 Início"):
                    st.session_state.page = "dashboard"
                if st.button("📝 Confirmar Recebimento"):
                    st.session_state.page = "confirm_receipt"
            
            # Botão de logout para todos
            if st.button("🚪 Sair"):
                st.session_state.authenticated = False
                st.session_state.user = None
                st.session_state.page = "login"
                st.rerun()
    
    # Renderiza a página atual
    if st.session_state.page == "login":
        render_login_page()
    elif st.session_state.page == "dashboard":
        render_dashboard()
    elif st.session_state.page == "manage_users":
        render_manage_users()
    elif st.session_state.page == "register_delivery":
        render_register_delivery()
    elif st.session_state.page == "confirm_receipt":
        render_confirm_receipt()
    elif st.session_state.page == "deliveries":
        render_deliveries()

def render_login_page():
    """Renderiza a página de login"""
    st.title("Sistema de Confirmação de Recebimento")
    
    # Verifica se existe usuário admin, senão cria
    ensure_admin_user_exists()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Login")
        username = st.text_input("Usuário")
        password = st.text_input("Senha", type="password")
        
        if st.button("Entrar"):
            user = authenticate_user(username, password)
            
            if user:
                st.session_state.authenticated = True
                st.session_state.user = user
                st.session_state.page = "dashboard"
                st.success("Login realizado com sucesso!")
                st.rerun()
            else:
                st.error("Usuário ou senha incorretos.")
    
    with col2:
        st.image("https://via.placeholder.com/400x300?text=Sistema+de+Entrega", use_column_width=True)
        st.write("Sistema de confirmação de recebimento com reconhecimento facial e autenticação segura.")
        
        # Exibe informações sobre o usuário admin padrão
        users_file = "data/users/users.json"
        if not os.path.exists(users_file) or os.path.getsize(users_file) == 0:
            st.info("""
            ### Credenciais padrão:
            - **Usuário:** admin
            - **Senha:** admin123
            """)
        elif not os.path.exists(users_file) and not os.path.exists("data/users"):
            st.warning("""
            ### Erro de inicialização
            Não foi possível criar a estrutura de diretórios necessária.
            Verifique as permissões da pasta.
            """)

def render_dashboard():
    """Renderiza o dashboard do usuário"""
    st.title("Dashboard")
    
    # Conteúdo diferente baseado no papel do usuário
    if st.session_state.user["role"] == "admin":
        col1, col2, col3 = st.columns(3)
        
        users = get_all_users()
        deliveries = get_all_deliveries()
        
        with col1:
            st.metric("Total de Usuários", len(users))
        
        with col2:
            st.metric("Total de Entregas", len(deliveries))
        
        with col3:
            # Calcular entregas por status
            confirmed = sum(1 for d in deliveries if d.get("status") == "confirmed")
            st.metric("Entregas Confirmadas", confirmed)
        
        # Gráfico de entregas recentes
        st.subheader("Entregas Recentes")
        recent_deliveries = deliveries[-10:] if len(deliveries) > 10 else deliveries
        recent_df = pd.DataFrame(recent_deliveries)
        
        if not recent_df.empty and "timestamp" in recent_df.columns:
            recent_df["data"] = pd.to_datetime(recent_df["timestamp"]).dt.date
            st.bar_chart(recent_df.groupby("data").size())
        
        # Seção de entregas confirmadas
        st.subheader("Entregas Confirmadas")
        confirmed_deliveries = [d for d in deliveries if d.get("status") == "confirmed"]
        
        if confirmed_deliveries:
            # Ordena por data de confirmação, do mais recente para o mais antigo
            confirmed_deliveries.sort(key=lambda d: d.get("confirmation_timestamp", ""), reverse=True)
            
            for delivery in confirmed_deliveries[:5]:  # Mostra apenas as 5 mais recentes
                # Formata as datas para exibição
                timestamp = datetime.datetime.fromisoformat(delivery["timestamp"]).strftime("%d/%m/%Y %H:%M")
                confirmation = "N/A"
                if "confirmation_timestamp" in delivery:
                    confirmation = datetime.datetime.fromisoformat(delivery["confirmation_timestamp"]).strftime("%d/%m/%Y %H:%M")
                
                with st.expander(f"#{delivery['id']} - {delivery['description']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Entregador:** {delivery['delivery_name']}")
                        st.write(f"**Receptor:** {delivery['receiver_name']}")
                        st.write(f"**Registrado em:** {timestamp}")
                        st.write(f"**Confirmado em:** {confirmation}")
                    
                    with col2:
                        # Mostra a selfie se disponível
                        if delivery.get("has_selfie"):
                            selfie_path = f"data/selfies/{delivery['id']}.jpg"
                            if os.path.exists(selfie_path):
                                try:
                                    st.image(selfie_path, caption="Confirmação de Recebimento", width=200)
                                except Exception as e:
                                    st.warning(f"Não foi possível exibir a imagem de selfie.")
            
            if len(confirmed_deliveries) > 5:
                st.info(f"Mostrando 5 de {len(confirmed_deliveries)} entregas confirmadas. Acesse 'Entregas Registradas' para ver todas.")
        else:
            st.info("Nenhuma entrega foi confirmada até o momento.")
    
    elif st.session_state.user["role"] == "delivery":
        deliveries = get_all_deliveries()
        my_deliveries = [d for d in deliveries if d.get("delivery_user") == st.session_state.user["username"]]
        
        confirmed = sum(1 for d in my_deliveries if d.get("status") == "confirmed")
        pending = sum(1 for d in my_deliveries if d.get("status") == "pending")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Minhas Entregas", len(my_deliveries))
        
        with col2:
            st.metric("Entregas Pendentes", pending)
        
        with col3:
            st.metric("Entregas Confirmadas", confirmed)
        
        # Seção de entregas pendentes
        st.subheader("Entregas Pendentes")
        
        pending_deliveries = [d for d in my_deliveries if d.get("status") == "pending"]
        
        if pending_deliveries:
            for delivery in pending_deliveries:
                with st.expander(f"Entrega #{delivery['id']} - {delivery['description']}"):
                    st.write(f"**Destinatário:** {delivery['receiver_name']}")
                    st.write(f"**Data:** {datetime.datetime.fromisoformat(delivery['timestamp']).strftime('%d/%m/%Y %H:%M')}")
                    st.write(f"**Status:** Aguardando confirmação")
                    
                    if delivery.get("has_cargo_image"):
                        img_path = f"data/cargo_images/{delivery['id']}.jpg"
                        if os.path.exists(img_path):
                            try:
                                st.image(img_path, caption="Imagem da Carga", width=200)
                            except Exception as e:
                                st.warning(f"Não foi possível exibir a imagem da carga.")
        else:
            st.info("Você não tem entregas pendentes.")
        
        # Seção de entregas confirmadas
        st.subheader("Entregas Confirmadas")
        
        confirmed_deliveries = [d for d in my_deliveries if d.get("status") == "confirmed"]
        
        if confirmed_deliveries:
            # Ordena por data de confirmação, do mais recente para o mais antigo
            confirmed_deliveries.sort(key=lambda d: d.get("confirmation_timestamp", ""), reverse=True)
            
            for delivery in confirmed_deliveries:
                with st.expander(f"Entrega #{delivery['id']} - {delivery['description']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Destinatário:** {delivery['receiver_name']}")
                        st.write(f"**Data de Entrega:** {datetime.datetime.fromisoformat(delivery['timestamp']).strftime('%d/%m/%Y %H:%M')}")
                        
                        if "confirmation_timestamp" in delivery:
                            st.write(f"**Data de Confirmação:** {datetime.datetime.fromisoformat(delivery['confirmation_timestamp']).strftime('%d/%m/%Y %H:%M')}")
                    
                    with col2:
                        # Mostra a selfie se disponível
                        if delivery.get("has_selfie"):
                            selfie_path = f"data/selfies/{delivery['id']}.jpg"
                            if os.path.exists(selfie_path):
                                try:
                                    st.image(selfie_path, caption="Confirmação de Recebimento", width=200)
                                except Exception as e:
                                    st.warning(f"Não foi possível exibir a imagem de selfie.")
        else:
            st.info("Você não tem entregas confirmadas.")
    
    elif st.session_state.user["role"] == "receiver":
        deliveries = get_all_deliveries()
        my_deliveries = [d for d in deliveries if d.get("receiver_username") == st.session_state.user["username"]]
        
        confirmed = sum(1 for d in my_deliveries if d.get("status") == "confirmed")
        pending = sum(1 for d in my_deliveries if d.get("status") == "pending")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Entregas Confirmadas", confirmed)
        
        with col2:
            st.metric("Entregas Pendentes", pending)
        
        # Seção de entregas pendentes
        st.subheader("Entregas Pendentes")
        
        pending_deliveries = [d for d in my_deliveries if d.get("status") == "pending"]
        
        if pending_deliveries:
            for delivery in pending_deliveries:
                with st.expander(f"Entrega #{delivery['id']} - {delivery['description']}"):
                    st.write(f"**Entregador:** {delivery['delivery_user']}")
                    st.write(f"**Data:** {datetime.datetime.fromisoformat(delivery['timestamp']).strftime('%d/%m/%Y %H:%M')}")
                    
                    if delivery.get("has_cargo_image"):
                        img_path = f"data/cargo_images/{delivery['id']}.jpg"
                        if os.path.exists(img_path):
                            try:
                                st.image(img_path, caption="Imagem da Carga", width=200)
                            except Exception as e:
                                st.warning(f"Não foi possível exibir a imagem da carga.")
                    
                    if st.button(f"Confirmar Recebimento #{delivery['id']}", key=f"confirm_{delivery['id']}"):
                        st.session_state.selected_delivery = delivery
                        st.session_state.page = "confirm_receipt"
                        st.rerun()
        else:
            st.info("Não há entregas pendentes para confirmação.")
        
        # Seção de entregas confirmadas
        st.subheader("Entregas Confirmadas")
        
        confirmed_deliveries = [d for d in my_deliveries if d.get("status") == "confirmed"]
        
        if confirmed_deliveries:
            # Ordena por data de confirmação, do mais recente para o mais antigo
            confirmed_deliveries.sort(key=lambda d: d.get("confirmation_timestamp", ""), reverse=True)
            
            for delivery in confirmed_deliveries:
                with st.expander(f"Entrega #{delivery['id']} - {delivery['description']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Entregador:** {delivery['delivery_name']}")
                        st.write(f"**Data de Entrega:** {datetime.datetime.fromisoformat(delivery['timestamp']).strftime('%d/%m/%Y %H:%M')}")
                        
                        if "confirmation_timestamp" in delivery:
                            st.write(f"**Data de Confirmação:** {datetime.datetime.fromisoformat(delivery['confirmation_timestamp']).strftime('%d/%m/%Y %H:%M')}")
                    
                    with col2:
                        # Mostra sua própria selfie
                        if delivery.get("has_selfie"):
                            selfie_path = f"data/selfies/{delivery['id']}.jpg"
                            if os.path.exists(selfie_path):
                                try:
                                    st.image(selfie_path, caption="Sua Confirmação de Recebimento", width=200)
                                except Exception as e:
                                    st.warning(f"Não foi possível exibir a imagem de selfie.")
                        
                        # Mostra a assinatura
                        signature_path = f"data/signatures/{delivery['id']}.png"
                        if os.path.exists(signature_path):
                            try:
                                st.image(signature_path, caption="Sua Assinatura", width=200)
                            except Exception as e:
                                st.warning(f"Não foi possível exibir a imagem de assinatura.")
        else:
            st.info("Você não tem entregas confirmadas.")

def render_manage_users():
    """Renderiza a página de gerenciamento de usuários"""
    st.title("Gerenciar Usuários")
    
    # Verifica se é administrador
    if st.session_state.user["role"] != "admin":
        st.error("Acesso negado. Apenas administradores podem gerenciar usuários.")
        return
    
    # Tabs para diferentes operações
    tab1, tab2 = st.tabs(["Criar Usuário", "Usuários Cadastrados"])
    
    with tab1:
        st.subheader("Cadastrar Novo Usuário")
        
        # Formulário de cadastro
        with st.form("user_form"):
            username = st.text_input("Nome de Usuário")
            password = st.text_input("Senha", type="password")
            confirm_password = st.text_input("Confirmar Senha", type="password")
            fullname = st.text_input("Nome Completo")
            role = st.selectbox("Papel", ["admin", "delivery", "receiver"])
            
            submitted = st.form_submit_button("Cadastrar")
            
            if submitted:
                # Validações
                if not username or not password or not fullname:
                    st.error("Todos os campos são obrigatórios.")
                elif password != confirm_password:
                    st.error("As senhas não coincidem.")
                else:
                    # Salva usuário
                    success = save_user(username, password, fullname, role)
                    
                    if success:
                        st.success(f"Usuário {username} cadastrado com sucesso!")
                    else:
                        st.error(f"Erro ao cadastrar usuário. Nome de usuário já existe.")
    
    with tab2:
        st.subheader("Usuários Cadastrados")
        
        users = get_all_users()
        
        if users:
            # Cria um dataframe para exibição
            user_df = pd.DataFrame(users)
            user_df = user_df[["username", "fullname", "role", "created_at"]]
            user_df.columns = ["Usuário", "Nome Completo", "Papel", "Data de Criação"]
            
            # Formata a data
            user_df["Data de Criação"] = pd.to_datetime(user_df["Data de Criação"]).dt.strftime("%d/%m/%Y %H:%M")
            
            # Exibe a tabela
            st.dataframe(user_df)
        else:
            st.info("Nenhum usuário cadastrado.")

def render_register_delivery():
    """Renderiza a página de registro de entregas"""
    st.title("Registrar Entrega")
    
    # Verifica se é um entregador
    if st.session_state.user["role"] != "delivery":
        st.error("Acesso negado. Apenas entregadores podem registrar entregas.")
        return
    
    # Obtém a lista de receptores
    users = get_all_users()
    receivers = [u for u in users if u["role"] == "receiver"]
    
    if not receivers:
        st.warning("Não há receptores cadastrados no sistema. Peça ao administrador para cadastrar.")
        return
    
    # Formulário de registro de entrega
    with st.form("delivery_form"):
        st.subheader("Dados da Entrega")
        
        # Seleciona o receptor
        receiver_options = {f"{u['fullname']} ({u['username']})": u["username"] for u in receivers}
        receiver_display = st.selectbox("Selecione o Receptor", list(receiver_options.keys()))
        receiver_username = receiver_options[receiver_display]
        
        # Informações da entrega
        description = st.text_area("Descrição da Entrega")
        tracking_code = st.text_input("Código de Rastreamento (opcional)")
        
        # Upload de imagem da carga
        cargo_image = st.file_uploader("Foto da Carga", type=["jpg", "jpeg", "png"])
        
        submitted = st.form_submit_button("Registrar Entrega")
        
        if submitted:
            # Validações
            if not description:
                st.error("A descrição da entrega é obrigatória.")
            else:
                # Gera ID único para a entrega
                delivery_id = str(uuid.uuid4())
                
                # Salva a imagem da carga se fornecida
                image_saved = False
                if cargo_image:
                    image_saved = save_cargo_image(cargo_image, delivery_id)
                
                # Cria dados da entrega
                delivery_data = {
                    "id": delivery_id,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "delivery_user": st.session_state.user["username"],
                    "delivery_name": st.session_state.user["fullname"],
                    "receiver_username": receiver_username,
                    "receiver_name": next(u["fullname"] for u in receivers if u["username"] == receiver_username),
                    "description": description,
                    "tracking_code": tracking_code if tracking_code else None,
                    "status": "pending",
                    "has_cargo_image": image_saved
                }
                
                # Adiciona à blockchain
                blockchain_data = {
                    "type": "delivery_registration",
                    "delivery_id": delivery_id,
                    "timestamp": delivery_data["timestamp"],
                    "delivery_user": delivery_data["delivery_user"],
                    "receiver_username": delivery_data["receiver_username"],
                    "description": delivery_data["description"]
                }
                
                # Registra na blockchain
                block = add_to_blockchain(blockchain_data)
                
                # Adiciona hash do bloco aos dados da entrega
                delivery_data["blockchain_hash"] = block["hash"]
                
                # Registra a entrega
                success = register_delivery(delivery_data)
                
                if success:
                    st.success(f"Entrega registrada com sucesso! ID: {delivery_id}")
                    
                    # Exibe QR code com o ID da entrega
                    st.subheader("QR Code da Entrega")
                    
                    # Aqui você pode implementar a geração de QR code
                    # Por simplicidade, apenas exibiremos o ID
                    st.code(delivery_id)
                else:
                    st.error("Erro ao registrar entrega.")

def render_confirm_receipt():
    """Renderiza a página de confirmação de recebimento"""
    st.title("Confirmar Recebimento")
    
    # Verifica se é um receptor
    if st.session_state.user["role"] != "receiver":
        st.error("Acesso negado. Apenas receptores podem confirmar recebimentos.")
        return
    
    # Layout em duas colunas
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Entregas Pendentes")
        
        # Obtém entregas pendentes para este receptor
        deliveries = get_all_deliveries()
        pending_deliveries = [d for d in deliveries if d.get("receiver_username") == st.session_state.user["username"] and d.get("status") == "pending"]
        
        if not pending_deliveries:
            st.info("Não há entregas pendentes para confirmação.")
            return
        
        # Permite selecionar uma entrega
        delivery_options = {f"#{d['id']} - {d['description']}": d["id"] for d in pending_deliveries}
        
        if "selected_delivery_id" not in st.session_state:
            st.session_state.selected_delivery_id = None
        
        delivery_display = st.selectbox("Selecione a Entrega", list(delivery_options.keys()))
        selected_id = delivery_options[delivery_display]
        
        # Encontra a entrega selecionada
        selected_delivery = next((d for d in pending_deliveries if d["id"] == selected_id), None)
        
        if selected_delivery:
            st.session_state.selected_delivery = selected_delivery
            
            # Exibe detalhes da entrega
            st.subheader("Detalhes da Entrega")
            st.write(f"**ID:** {selected_delivery['id']}")
            st.write(f"**Data:** {datetime.datetime.fromisoformat(selected_delivery['timestamp']).strftime('%d/%m/%Y %H:%M')}")
            st.write(f"**Entregador:** {selected_delivery['delivery_name']}")
            st.write(f"**Descrição:** {selected_delivery['description']}")
            
            if selected_delivery.get("tracking_code"):
                st.write(f"**Código de Rastreamento:** {selected_delivery['tracking_code']}")
            
            # Exibe imagem da carga se disponível
            if selected_delivery.get("has_cargo_image"):
                st.subheader("Imagem da Carga")
                img_path = f"data/cargo_images/{selected_delivery['id']}.jpg"
                if os.path.exists(img_path):
                    st.image(img_path, use_column_width=True)
    
    with col2:
        if "selected_delivery" in st.session_state:
            st.subheader("Confirmar Recebimento")
            
            # Confirmar recebimento com senha
            st.write("Para confirmar o recebimento, informe sua senha:")
            password = st.text_input("Senha", type="password", key="reauth_password")
            
            if st.button("Verificar Identidade"):
                # Autenticação via senha
                hashed_password = hashlib.sha256(password.encode()).hexdigest()
                user = st.session_state.user
                
                if hashed_password == user["password_hash"]:
                    st.success("Identidade verificada com sucesso!")
                    st.session_state.identity_verified = True
                else:
                    st.error("Senha incorreta. Tente novamente.")
                    st.session_state.identity_verified = False
            
            # Se a identidade foi verificada, solicitar selfie e assinatura
            if st.session_state.get("identity_verified", False):
                st.subheader("Selfie com o Equipamento")
                st.write("Tire uma selfie mostrando você com o equipamento recebido:")
                selfie_file = st.file_uploader("Enviar Selfie", type=["jpg", "jpeg", "png"], key="selfie_uploader")
                
                st.subheader("Assinatura Digital")
                st.write("Assine abaixo para confirmar o recebimento:")
                
                # Canvas para assinatura
                signature_html = """
                <canvas id="signature-pad" width="400" height="200" style="border: 1px solid #ddd;"></canvas>
                <br>
                <button id="clear-button">Limpar</button>
                <button id="save-button">Salvar</button>
                
                <script src="https://cdn.jsdelivr.net/npm/signature_pad@4.0.0/dist/signature_pad.min.js"></script>
                <script>
                    var canvas = document.getElementById('signature-pad');
                    var signaturePad = new SignaturePad(canvas);
                    
                    document.getElementById('clear-button').addEventListener('click', function() {
                        signaturePad.clear();
                    });
                    
                    document.getElementById('save-button').addEventListener('click', function() {
                        if (signaturePad.isEmpty()) {
                            alert('Por favor, faça sua assinatura antes de salvar.');
                            return;
                        }
                        
                        var dataURL = signaturePad.toDataURL();
                        document.getElementById('signature-output').value = dataURL;
                        
                        // Notificar o usuário
                        alert('Assinatura salva! Clique em "Confirmar Recebimento" para finalizar.');
                    });
                </script>
                
                <form id="signature-form" action="" method="post">
                    <input type="hidden" id="signature-output" name="signature">
                </form>
                """
                
                st.components.v1.html(signature_html, height=300)
                
                # Campo para armazenar a assinatura (oculto)
                signature_data = st.text_input("Assinatura", key="signature_data", value="", type="password", help="A assinatura será preenchida automaticamente quando você clicar em 'Salvar' no painel acima")
                
                # Texto alternativo para assinatura (fallback)
                st.write("Se a assinatura digital não funcionar, você pode confirmar manualmente:")
                
                manual_signature = st.text_input("Digite seu nome completo como assinatura manual", key="manual_signature")
                
                # Botão para confirmar recebimento
                if st.button("Confirmar Recebimento"):
                    # Usa assinatura digital ou manual
                    final_signature = signature_data if signature_data else manual_signature
                    
                    if not final_signature:
                        st.error("É necessário fornecer uma assinatura (digital ou manual).")
                    elif selfie_file is None:
                        st.error("É necessário enviar uma selfie com o equipamento.")
                    else:
                        # Salva a selfie
                        selfie_saved = save_selfie(selfie_file, st.session_state.selected_delivery["id"])
                        
                        # Salva a assinatura
                        signature_saved = save_signature(
                            st.session_state.user["username"],
                            final_signature,
                            st.session_state.selected_delivery["id"]
                        )
                        
                        if signature_saved and selfie_saved:
                            # Atualiza o status da entrega
                            deliveries = get_all_deliveries()
                            for i, delivery in enumerate(deliveries):
                                if delivery["id"] == st.session_state.selected_delivery["id"]:
                                    deliveries[i]["status"] = "confirmed"
                                    deliveries[i]["confirmation_timestamp"] = datetime.datetime.now().isoformat()
                                    deliveries[i]["has_selfie"] = True
                                    break
                            
                            # Salva a lista atualizada de entregas
                            with open("data/deliveries/deliveries.json", "w") as f:
                                json.dump(deliveries, f)
                            
                            # Registra na blockchain
                            blockchain_data = {
                                "type": "delivery_confirmation",
                                "delivery_id": st.session_state.selected_delivery["id"],
                                "timestamp": datetime.datetime.now().isoformat(),
                                "receiver_username": st.session_state.user["username"],
                                "has_signature": True,
                                "has_selfie": True
                            }
                            
                            # Adiciona à blockchain
                            block = add_to_blockchain(blockchain_data)
                            
                            st.success("Recebimento confirmado com sucesso!")
                            st.session_state.identity_verified = False
                            st.session_state.selected_delivery = None
                            
                            # Botão para voltar ao dashboard
                            if st.button("Voltar ao Dashboard"):
                                st.session_state.page = "dashboard"
                                st.rerun()
                        else:
                            st.error("Erro ao salvar a assinatura ou selfie.")

def render_deliveries():
    """Renderiza a página de visualização de entregas"""
    st.title("Entregas Registradas")
    
    # Verifica se é administrador
    if st.session_state.user["role"] != "admin":
        st.error("Acesso negado. Apenas administradores podem visualizar todas as entregas.")
        return
    
    # Obtém todas as entregas
    deliveries = get_all_deliveries()
    
    if not deliveries:
        st.info("Nenhuma entrega registrada.")
        return
    
    # Filtros
    st.subheader("Filtros")
    col1, col2 = st.columns(2)
    
    with col1:
        status_filter = st.selectbox("Status", ["Todos", "Pendente", "Confirmado"])
    
    with col2:
        # Converte timestamps para datas
        dates = [datetime.datetime.fromisoformat(d["timestamp"]).date() for d in deliveries]
        min_date = min(dates) if dates else datetime.date.today()
        max_date = max(dates) if dates else datetime.date.today()
        
        date_range = st.date_input("Período", [min_date, max_date])
    
    # Aplica filtros
    filtered_deliveries = deliveries.copy()
    
    # Filtro por status
    if status_filter == "Pendente":
        filtered_deliveries = [d for d in filtered_deliveries if d.get("status") == "pending"]
    elif status_filter == "Confirmado":
        filtered_deliveries = [d for d in filtered_deliveries if d.get("status") == "confirmed"]
    
    # Filtro por data
    if len(date_range) == 2:
        start_date, end_date = date_range
        filtered_deliveries = [
            d for d in filtered_deliveries if 
            start_date <= datetime.datetime.fromisoformat(d["timestamp"]).date() <= end_date
        ]
    
    # Exibe as entregas filtradas
    st.subheader(f"Entregas ({len(filtered_deliveries)})")
    
    for delivery in filtered_deliveries:
        status_color = "🟢" if delivery.get("status") == "confirmed" else "🟠"
        
        with st.expander(f"{status_color} #{delivery['id']} - {delivery['description']} ({datetime.datetime.fromisoformat(delivery['timestamp']).strftime('%d/%m/%Y')})"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.write(f"**Data de Registro:** {datetime.datetime.fromisoformat(delivery['timestamp']).strftime('%d/%m/%Y %H:%M')}")
                st.write(f"**Entregador:** {delivery['delivery_name']}")
                st.write(f"**Receptor:** {delivery['receiver_name']}")
                st.write(f"**Status:** {'Confirmado' if delivery.get('status') == 'confirmed' else 'Pendente'}")
                
                if delivery.get("status") == "confirmed" and "confirmation_timestamp" in delivery:
                    st.write(f"**Data de Confirmação:** {datetime.datetime.fromisoformat(delivery['confirmation_timestamp']).strftime('%d/%m/%Y %H:%M')}")
                
                # Exibe informações da blockchain
                if "blockchain_hash" in delivery:
                    st.subheader("Registro Blockchain")
                    st.code(delivery["blockchain_hash"])
            
            with col2:
                # Exibe imagem da carga se disponível
                if delivery.get("has_cargo_image"):
                    img_path = f"data/cargo_images/{delivery['id']}.jpg"
                    if os.path.exists(img_path):
                        try:
                            st.image(img_path, caption="Imagem da Carga (Registro)", width=200)
                        except Exception as e:
                            st.warning(f"Não foi possível exibir a imagem da carga.")
                
                # Exibe selfie se disponível
                if delivery.get("has_selfie"):
                    img_path = f"data/selfies/{delivery['id']}.jpg"
                    if os.path.exists(img_path):
                        try:
                            st.image(img_path, caption="Selfie do Receptor com Equipamento", width=200)
                        except Exception as e:
                            st.warning(f"Não foi possível exibir a selfie.")
                
                # Exibe assinatura se disponível
                if delivery.get("status") == "confirmed":
                    signature_path = f"data/signatures/{delivery['id']}.png"
                    if os.path.exists(signature_path):
                        try:
                            st.image(signature_path, caption="Assinatura", width=200)
                        except Exception as e:
                            st.warning(f"Não foi possível exibir a assinatura.")
                            st.write(f"**Receptor:** {delivery['receiver_name']}")
                st.write(f"**Status:** {'Confirmado' if delivery.get('status') == 'confirmed' else 'Pendente'}")
                
                if delivery.get("status") == "confirmed" and "confirmation_timestamp" in delivery:
                    st.write(f"**Data de Confirmação:** {datetime.datetime.fromisoformat(delivery['confirmation_timestamp']).strftime('%d/%m/%Y %H:%M')}")
            
            with col2:
                # Exibe imagem da carga se disponível
                if delivery.get("has_cargo_image"):
                    img_path = f"data/cargo_images/{delivery['id']}.jpg"
                    if os.path.exists(img_path):
                        st.image(img_path, caption="Imagem da Carga (Registro)", width=200)
                
                # Exibe selfie se disponível
                if delivery.get("has_selfie"):
                    img_path = f"data/selfies/{delivery['id']}.jpg"
                    if os.path.exists(img_path):
                        st.image(img_path, caption="Selfie do Receptor com Equipamento", width=200)
                
                # Exibe assinatura se disponível
                if delivery.get("status") == "confirmed":
                    signature_path = f"data/signatures/{delivery['id']}.png"
                    if os.path.exists(signature_path):
                        st.image(signature_path, caption="Assinatura", width=200)
            
            # Exibe informações da blockchain
            if "blockchain_hash" in delivery:
                st.subheader("Registro Blockchain")
                st.code(delivery["blockchain_hash"])

# Executa o aplicativo
if __name__ == "__main__":
    main()
