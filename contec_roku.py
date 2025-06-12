# This program works well with SQLALCHEMY

import os
import time
import pandas as pd
import numpy as np
import streamlit as st
import bcrypt
import plotly.graph_objects as go
import plotly.figure_factory as ff
import plotly.express as px
import matplotlib.pyplot as plt
from matplotlib import font_manager
from datetime import datetime, timedelta
from st_aggrid import GridOptionsBuilder, AgGrid
from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool
from cachetools import TTLCache, cached
from streamlit_extras.app_logo import add_logo 
from dotenv import load_dotenv


# -----------------------------------------------------------------
load_dotenv()  # This loads the .env file
#-----------------------------------------------------------------

# Database configuration
class Database:
    _engine = None
    
    @classmethod
    def get_engine(cls):
        if cls._engine is None:
            try:
                # Get AWS RDS configuration
                aws_config = {
                    'host': os.getenv('DB_HOST'),
                    'user': os.getenv('DB_USER'),
                    'password': os.getenv('DB_PASSWORD'),
                    'database': os.getenv('DB_NAME'),
                    'port': os.getenv('DB_PORT', '3306'),
                }
                
                # Validate all required fields are present
                if not all(aws_config.values()):
                    missing = [k for k, v in aws_config.items() if not v]
                    raise ValueError(f"Missing AWS RDS configuration: {', '.join(missing)}")
                
                # Create connection string
                connection_str = (
                    f"mysql+mysqlconnector://{aws_config['user']}:{aws_config['password']}"
                    f"@{aws_config['host']}:{aws_config['port']}/{aws_config['database']}"
                )
                
                cls._engine = create_engine(
                    connection_str,
                    poolclass=QueuePool,
                    pool_size=10,
                    pool_recycle=3600,
                    connect_args={
                        'connect_timeout': 10,
                        'ssl_ca': '/path/to/aws-rds-combined-ca-bundle.pem'  # If using SSL
                    }
                )
                
                # Test connection immediately
                with cls._engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                
                #st.success("Successfully connected to AWS RDS MySQL!")
                
            except Exception as e:
                st.error(f"AWS RDS Connection Failed: {str(e)}")
                st.error("2. Security group allows your IP")
                st.error("Please verify:")
                st.error("1. Credentials in .env are correct")
                st.error("3. AWS RDS instance is running")

                raise
                
        return cls._engine
    
# Initialize cache
cache = TTLCache(maxsize=100, ttl=1800)

# Page configuration
st.set_page_config(
    page_title="Contec",
    page_icon="🌀",
    layout='wide',
    initial_sidebar_state="expanded"
)
st.markdown("""<style>footer {visibility: hidden;}</style>""", unsafe_allow_html=True)

# Simple Authentication Logic
class Authentication:
    def __init__(self):
        try:
            self.engine = Database.get_engine()
            self.initialize_database()  # Now properly defined below
            
        except Exception as e:
            st.error(f"Authentication system initialization failed: {str(e)}")
            self.engine = None
            raise

    def initialize_database(self):
        """Ensure required database tables and admin user exist"""
        if not self.engine:
            raise ValueError("Database engine not available")
            
        try:
            with self.engine.connect() as conn:
                # Create users table if not exists
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS user_roku (
                        username VARCHAR(50) PRIMARY KEY,
                        password_hash VARCHAR(255) NOT NULL,
                        is_admin BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
                
                # Check if admin exists
                result = conn.execute(text(
                    "SELECT 1 FROM user_roku WHERE username = 'admin'"
                ))
                if not result.fetchone():
                    # Create default admin
                    hashed = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt())
                    conn.execute(text(
                        "INSERT INTO user_roku (username, password_hash, is_admin) "
                        "VALUES ('admin', :password, TRUE)"
                    ), {'password': hashed.decode('utf-8')})
                    
                conn.commit()
                
        except Exception as e:
            st.error(f"Failed to initialize database: {str(e)}")
            raise
    
    def hash_password(self, password):
        """Hash a password for storing."""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))
    
    def check_credentials(self, username, password):
        """Check if username and password are correct"""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text(
                    "SELECT password_hash, is_admin FROM user_roku WHERE username = :username"
                ), {'username': username})
                user = result.fetchone()
                if user and self.verify_password(user[0], password):
                    return {'authenticated': True, 'is_admin': user[1]}
        except Exception as e:
            st.error(f"Database error: {str(e)}")
        return {'authenticated': False, 'is_admin': False}
    
    def create_user(self, username, password, is_admin=False):
        """Create a new user"""
        try:
            hashed_password = self.hash_password(password)
            with self.engine.connect() as conn:
                conn.execute(text(
                    "INSERT INTO user_roku (username, password_hash, is_admin) "
                    "VALUES (:username, :password, :is_admin)"
                ), {
                    'username': username,
                    'password': hashed_password,
                    'is_admin': is_admin
                })
                conn.commit()
            return True, "User created successfully"
        except Exception as e:
            return False, f"Error creating user: {str(e)}"
    
    def delete_user(self, username):
        """Delete a user"""
        try:
            with self.engine.connect() as conn:
                conn.execute(text(
                    "DELETE FROM user_roku WHERE username = :username"
                ), {'username': username})
                conn.commit()
            return True, "User deleted successfully"
        except Exception as e:
            return False, f"Error deleting user: {str(e)}"
    
    def update_password(self, username, new_password):
        """Update user password"""
        try:
            hashed_password = self.hash_password(new_password)
            with self.engine.connect() as conn:
                conn.execute(text(
                    "UPDATE user_roku SET password_hash = :password WHERE username = :username"
                ), {
                    'username': username,
                    'password': hashed_password
                })
                conn.commit()
            return True, "Password updated successfully"
        except Exception as e:
            return False, f"Error updating password: {str(e)}"
    
    def list_users(self):
        """List all users"""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text("SELECT username, is_admin FROM user_roku"))
                return result.fetchall()
        except Exception as e:
            st.error(f"Error listing user_roku: {str(e)}")
            return []
        
    cache = TTLCache(maxsize=100, ttl=1800)
    def login_page(self):
        """Render the login page"""
        col1, col2, col3 = st.columns(3)
        with col3:
            new_title = '<p style="font-family:sans-serif;text-align:left; color:#1c03fc; font-size: 25px;">🔒 Login </p>'
            st.markdown(new_title, unsafe_allow_html=True)
            
            username = st.text_input("User Name"  ,placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            with st.spinner("loading"):
                st.write("")
            if st.button("Login"):
                result = self.check_credentials(username, password)
                if result['authenticated']:
                    st.session_state['authenticated'] = True
                    st.session_state['username'] = username
                    st.session_state['is_admin'] = result['is_admin']
                    with st.spinner("Loading data..."):
                        st.write("")
                        # st.success("Logged in successfully!")
                    # st.rerun()
                else:
                    st.error("Invalid credentials!")
                    st.rerun()
       
          
        with col1:
            st.write("A product of")
            st.image("C:/clak/_app/_roku_run/contec.png", width=175)
            
            

#------------------------------------------------------------------------------------------------------------------
    cache = TTLCache(maxsize=100, ttl=1800)
    def user_management_page(self):
        """Simple user management page for admin"""
        if not st.session_state.get('is_admin'):
            st.error("Admin privileges required")
            return
        
        st.title("User Management")
        
        # Create new user
        with st.expander("Create New User"):
            with st.form("create_user_form"):
                col1, col2 = st.columns(2)
                with col1:
                    new_username = st.text_input("Username")
                with col2:
                    new_password = st.text_input("Password", type="password")
                is_admin = st.checkbox("Admin User")
                
                if st.form_submit_button("Create User"):
                    success, message = self.create_user(new_username, new_password, is_admin)
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
        
        # List all users with delete option
        st.subheader("Current Users")
        users = self.list_users()
        if users:
            for username, is_admin in users:
                with st.expander(f"{username} {'(Admin)' if is_admin else ''}"):
                    with st.form(f"edit_user_{username}"):
                        new_password = st.text_input("New Password", type="password", key=f"pw_{username}")
                        if st.form_submit_button("Update Password") and new_password:
                            success, message = self.update_password(username, new_password)
                            if success:
                                st.success(message)
                            else:
                                st.error(message)

                        #if st.form_submit_button("Delete User", key=f"del_{username}"):
                    with st.form(key=f"delete_form_{username}"):
                        submit = st.form_submit_button(label=f"Delete User {username}")
                        if submit:
                            # Handle deletion
                    #if st.button("Delete User", key=f"del_{username}"):
                            success, message = self.delete_user(username)
                            if success:
                                st.success(message)
                                st.rerun()
                            else:
                                st.error(message)
        else:
            st.warning("No users found")

# -----------------------------------------------------------------------------------------------------
# Application Pages (your existing ContecApp class remains unchanged)
class ContecApp:
    # ... (all your existing methods remain exactly the same)
    @cached(cache=TTLCache(maxsize=2,ttl=1800))
    def fetch_data(self, query, **params):
        engine = Database.get_engine()
        with engine.connect() as connection:
            df = pd.read_sql(text(query), connection, params=params)
        return df

    def home_page(self):
        st.markdown(
            '<p style="font-family:sans-serif;text-align:center; color:#42b6f5; font-size: 25px;">✨ CONTEC CHENNAI LOCATION ✨</p>',
            unsafe_allow_html=True
        )
        st.divider()
        st.subheader("Analysis on Roku Data")
        pan1, pan2 = st.columns(2)
        with pan1:
            st.write("")
            st.write("")
            st.write("✔️...Roku Monthly Revenue Histogram as week wise")
            st.write("✔️...Roku Weekly comparision with Quantity and Amount")
            st.write("✔️...Roku Servicecode wise weekly Data view")
            st.write("✔️...A Statistical view of Roku 2025 Data ")
            st.write("✔️...An Analysis on Roku 2025 Dataset")
            
        with pan2:
        #st.image('C:/clak/_deployment/contec_roku/contec_Lisbon.jpg',width=800)
            def simulation_graph(data):
                # Creates a small-sized plotly graph object
                fig = go.Figure(data=[go.Scatter(x=data['time'], y=data['value'])])
                fig.update_layout(
                    xaxis_title="Time",
                    yaxis_title="Value",
                    width=400,  # Set width
                    height=300  # Set height
                )
                return fig

            def graph():
                # Generate sample simulation data (replace with your actual simulation logic)
                time_steps = np.arange(0, 20, 0.1)
                values = [np.random.normal(loc=5, scale=1.5) for _ in time_steps]
                simulation_data = {'time': time_steps, 'value': values}
                # Display the small graph
                st.plotly_chart(simulation_graph(simulation_data), use_container_width=False)
            
            if __name__ == "__main__":
                graph()
        
        

#--------------------------------------------------------------------------------------------------------------------------------------------
    @cached(cache=TTLCache(maxsize=2,ttl=1800))
    def alfa(self):
        st.markdown(
            '<p style="font-family:sans-serif;text-align:center; color:#83e6e6; font-size: 25px;">MONTH-WISE-REVENUE-GRAPH</p>',
            unsafe_allow_html=True
        )
        
        col1, col2, col3 = st.columns(3)
        with col1:
            year = st.number_input("📅 Year", min_value=2000, max_value=2100, value=datetime.now().year)
        with col2:
            month = st.selectbox("Month", list(range(1, 13)), format_func=lambda x: datetime(2000, x, 1).strftime('%B'))
        with col3:
            invoice_code = st.text_input("🔑 Invoice Code", value="ROKU")

        @cached(cache=TTLCache(maxsize=2,ttl=1800))
        def fetch_weekly_data(invoice_code, year, month):
            query = """
                SELECT
                    WEEK(tid.reportdate, 0) AS week_number,
                    DATE_FORMAT(MIN(tid.reportdate), '%Y-%m-%d') AS start_date,
                    DATE_FORMAT(MAX(tid.reportdate), '%Y-%m-%d') AS end_date,
                    ROUND(SUM(tid.amount),2) AS total_amount
                FROM
                    Billing.tdi_invoice_details tid
                WHERE
                    YEAR(tid.reportdate) = :year
                    AND MONTH(tid.reportdate) = :month
                    AND invoice_code = :invoice_code
                GROUP BY
                    WEEK(tid.reportdate, 0)
                ORDER BY
                    WEEK(tid.reportdate, 0);
            """
            return self.fetch_data(query, 
                invoice_code=invoice_code,
                year=year,
                month=month
            )
        with st.spinner("Loading data..."):
            weekly_data = fetch_weekly_data(invoice_code, year, month)
        
        if not weekly_data.empty:
            st.markdown(
                f"<h4 style='text-align: center; font-family: Arial, sans-serif; font-weight: bold; color:#4242cf;'>📅 {datetime(2000, month, 1).strftime('%B')} {year} - Metrics</h4>",
                unsafe_allow_html=True
            )
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=weekly_data['week_number'],
                y=weekly_data['total_amount'],
                mode='lines+markers',
                name='Current Week',
                line=dict(color='blue', width=3),
                marker=dict(size=6, color='blue', symbol='circle')
            ))
            
            previous_week_amounts = [0] + weekly_data['total_amount'].tolist()[:-1]
            fig.add_trace(go.Scatter(
                x=weekly_data['week_number'],
                y=previous_week_amounts,
                mode='lines+markers',
                name='Previous Week',
                line=dict(color='red', width=3, dash='dash'),
                marker=dict(size=6, color='red', symbol='circle')
            ))
            
            fig.update_layout(
                title='📊 Current vs Previous Week Comparison',
                xaxis_title='Week Number',
                yaxis_title='Total Amount',
                template='plotly_white',
                font=dict(family='Arial, sans-serif', size=12, color='#2C3E50'),
                legend=dict(x=0.02, y=0.98, borderwidth=1),
                height=450
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("⚠️ No data found for the selected filters.")
    #---------------------------------------------------------------------------------------------------------------------------------------------
    def beta(self):
        st.markdown(
            "<h3 style='text-align: center; font-family: Arial, sans-serif; font-weight: bold; color:#0cb3f0;'>📊Roku Week-Wise Data</h3>",
            unsafe_allow_html=True
        )

        @cached(cache=TTLCache(maxsize=2,ttl=1800))
        def fetch_weekly_data(invoice_code, year, month):
            query = """
                SELECT
                    WEEK(tid.reportdate, 0) - WEEK(DATE(CONCAT(:year, '-01-01')), 0) + 1 AS week_number,
                    DATE_FORMAT(STR_TO_DATE(CONCAT(YEAR(tid.reportdate), WEEK(tid.reportdate, 0), ' Sunday'), '%X%V %W'), '%Y-%m-%d') AS start_date,
                    DATE_FORMAT(MAX(tid.reportdate), '%Y-%m-%d') AS end_date,
                    ROUND(SUM(tid.amount),2) AS total_amount,
                    SUM(tid.qty) AS total_quantity
                FROM
                    Billing.tdi_invoice_details tid
                WHERE
                    YEAR(tid.reportdate) = :year
                    AND MONTH(tid.reportdate) = :month
                    AND invoice_code = :invoice_code
                GROUP BY
                    WEEK(tid.reportdate, 0)
                ORDER BY
                    WEEK(tid.reportdate, 0);
            """
            return self.fetch_data(query, 
                invoice_code=invoice_code,
                year=year,
                month=month
            )

        col1, col2, col3 = st.columns(3)
        with col1:
            year = st.number_input("📅 Year", min_value=2000, max_value=2100, value=datetime.now().year)
        with col2:
            month = st.selectbox(".Month", list(range(1, 13)), format_func=lambda x: datetime(2000, x, 1).strftime('%B'))
        with col3:
            invoice_code = st.text_input("🔑 Invoice Code", value="ROKU")
        st.divider()
        
        with st.spinner("Loading data..."):
            weekly_data = fetch_weekly_data(invoice_code, year, month)
        
        if not weekly_data.empty:
            st.markdown(
                f"<h4 style='text-align: center; font-family: Arial, sans-serif; font-weight: bold; color: #0cb3f0;'>📅 {datetime(2000, month, 1).strftime('%B')} {year} - Weekly Metrics</h4>",
                unsafe_allow_html=True
            )
            
            card_style = """
                <style>
                    .metric-card {
                        background-color:#7ad7ff;
                        border-radius: 14px;
                        padding: 24px;
                        margin: 14px;
                        box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.2);
                        text-align: left;
                        font-family: Arial, sans-serif;
                    }
                    .metric-header {
                        font-size: 14px;
                        font-weight: bold;
                        color: #333;
                    }
                    .metric-value {
                        font-size: 14px;
                        font-weight: bold;
                        color: #c9497a;
                    }
                </style>
            """
            st.markdown(card_style, unsafe_allow_html=True)
            
            for index, row in weekly_data.iterrows():
                week_number = row["week_number"]
                start_date = row["start_date"]
                end_date = row["end_date"]
                total_qty = f"{row['total_quantity']:,.0f}"
                total_amount = float(row['total_amount'])
                prev_amount = float(weekly_data.iloc[index - 1]['total_amount']) if index > 0 else total_amount
                
                col1, col2, col3 = st.columns([1, 1, 2])
                with col1:
                    st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-header"> Week {week_number}📦</div>
                            <div class="metric-value">Units: {total_qty}</div>
                        </div>
                    """, unsafe_allow_html=True)
                with col2:
                    st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-header"> Week {week_number}💰</div>
                            <div class="metric-value">Amount: {total_amount}</div>
                        </div>
                    """, unsafe_allow_html=True)
                st.markdown("<hr>", unsafe_allow_html=True)
                with col3:
                    wave_fig = go.Figure()
                    wave_fig.add_trace(go.Scatter(
                        x=[start_date, end_date],
                        y=[prev_amount, total_amount],
                        mode="lines+markers",
                        name=f"Comparison - Week {week_number}",
                        line=dict(shape="spline", color="#1f77b4", width=3),
                        marker=dict(size=4, symbol="circle", color="#1f77b4"),
                    ))
                    wave_fig.update_layout(
                        title=f'compared with week {week_number - 1}📊 ',
                        xaxis_title='Date',
                        yaxis_title='Amount',
                        template="plotly_white",
                        height=250,
                        font=dict(family="Arial, sans-serif", size=12, color="#2C3E50")
                    )
                    st.plotly_chart(wave_fig, use_container_width=True)
                st.markdown("<hr>", unsafe_allow_html=True)
                time.sleep(1)
        else:
            st.warning("⚠️ No data found for the selected filters.")
#-----------------------------------------------------------------------------------------------------------------------
    @cached(cache=TTLCache(maxsize=2,ttl=1800))  # ROKU SERVICECODE DATA CARDS
    def charlie(self):
        @cached(cache=TTLCache(maxsize=2,ttl=1800))
        def fetch_data(from_date, to_date):
            query = f"""
                SELECT reportdate, servicecode, (PartDescription) AS Auth_Number, Model, qty, rate, 
                ROUND(amount, 2) AS amount
                FROM 
                Billing.tdi_invoice_details
                WHERE invoice_code = 'ROKU'
                AND reportdate BETWEEN :from_date AND :to_date;
            """
            return self.fetch_data(query, 
                from_date=from_date,
                to_date=to_date
            )

        new_title = '<p style="font-family:sans-serif;text-align:center; color:#5142f5; font-size: 25px;">🌍 ROKU SERVICECODE DATA 🌍</p>'
        st.markdown(new_title, unsafe_allow_html=True)
        st.markdown("#### Select your week between")
        
        col1, col2 = st.columns(2)
        with col1:
            from_date = st.date_input("From Date", value=datetime(2025, 1, 1))
        with col2:
            to_date = st.date_input("To Date", value=datetime.today())

        with st.spinner("Loading data..."):
            df = fetch_data(from_date, to_date)
        
        if "selected_service" not in st.session_state:
            st.session_state.selected_service = None
        
        if not df.empty:
            
            def calculate_metrics(df):
                df = df.copy()
                df['reportdate'] = pd.to_datetime(df['reportdate'])
                df['WeekStart'] = df['reportdate'] - pd.to_timedelta(df['reportdate'].dt.weekday + 1, unit='d')
                weekly_metrics = df.groupby(['servicecode', 'WeekStart']).agg({'qty': 'sum', 'amount': 'sum'}).reset_index()
                return weekly_metrics
            
            weekly_metrics = calculate_metrics(df)
            
            if st.session_state.selected_service is None:
                st.markdown("##### Metrics of the week")
                cols = st.columns(3)
                for idx, row in weekly_metrics.iterrows():
                    with cols[idx % 3]:
                        card = st.container()
                        card.markdown(
                        f"""
                        <div style='border:2px solid #4CAF50; box-shadow: 2px 2px 10px rgba(0, 0, 0, 0.1); padding:10px; border-radius:10px; text-align:center;'>
                            <h4 style='color:#20b6c7;'>{row['servicecode']}</h4>
                            <p style='color:#60eb8a ;'>Qty: {row['qty']}</p>
                            <p style='color:#eef7da;'>Amount: {round(row['amount'], 2)}</p>
                            <button onclick="window.location.href='?selected_service={row['servicecode']}'">👇</button>
                        </div>
                        """,
                        unsafe_allow_html=True
                        )

                       
                        if st.button(f"View {row['servicecode']} Data", key=idx):
                            st.session_state.selected_service = row['servicecode']
                            st.rerun()
            else:
                selected_service = st.session_state.selected_service
                selected_data = df[df['servicecode'] == selected_service]
                st.subheader(f"{selected_service} Data")
                AgGrid(selected_data)
                if st.button("Back"):
                    st.session_state.selected_service = None
                    st.rerun()
        else:
            st.warning("No data found for the selected date range.")
#--------------------------------------------------------------------------------------------------------------------------------
    @cached(cache=TTLCache(maxsize=2,ttl=1800)) # ROKU STATISTICS 
    def delta(self):
        @cached(cache=TTLCache(maxsize=2,ttl=1800))
        def fetch_statistical_data():
            query = f"""
                select date_format(reportdate,'%Y-%m-%d')Reportdate, servicecode, Model, 
                qty,rate,ROUND(amount,2)AS amount, date_format(TestDate,'%y-%m-%d')TestDate,FailureDescription,
                Invoice_Reference, PartDescription
                from Billing.tdi_invoice_details tid 
                where invoice_code = 'roku'
                and reportdate >= '2025-01-01' 
            """
            return self.fetch_data(query)
        with st.spinner("Loading data..."): 
            df = fetch_statistical_data()
        
        st.markdown(
            '<p style="font-family:sans-serif;text-align:center; color:#2803fc; font-size: 25px;">📊✨ ROKU DATA SET ✨📊</p>',
            unsafe_allow_html=True
        )
        st.header("Roku Statistics")
        st.divider()
        
        if not df.empty:
            df['Reportdate'] = pd.to_datetime(df['Reportdate'])
            df['Week'] = df['Reportdate'].dt.isocalendar().week
            df['Month'] = df['Reportdate'].dt.month
            df['Quarter'] = df['Reportdate'].dt.quarter
            df['HalfYear'] = (df['Reportdate'].dt.month - 1) // 6 + 1
            
            col1,col2 = st.columns(2)
            with col1:
                time_period = st.selectbox("Select Time Period", ["Weekly", "Monthly", "Quarterly", "Half-Yearly"])
                
                if time_period == "Weekly":
                    grouped_data = df.groupby(['Week', 'servicecode']).agg({'qty': 'sum', 'amount': 'sum'}).reset_index()
                elif time_period == "Monthly":
                    grouped_data = df.groupby(['Month', 'servicecode']).agg({'qty': 'sum', 'amount': 'sum'}).reset_index()
                elif time_period == "Quarterly":
                    grouped_data = df.groupby(['Quarter', 'servicecode']).agg({'qty': 'sum', 'amount': 'sum'}).reset_index()
                elif time_period == "Half-Yearly":
                    grouped_data = df.groupby(['HalfYear', 'servicecode']).agg({'qty': 'sum', 'amount': 'sum'}).reset_index()
                
                grid_options = GridOptionsBuilder.from_dataframe(grouped_data)
                grid_options.configure_default_column(
                    enablePivot=True, enableValue=True, enableRowGroup=True, sortable=True, filterable=True)
                grid_options.configure_pagination(paginationAutoPageSize=True)
                AgGrid(grouped_data, gridOptions=grid_options.build())
            with col2:
                Graph = st.selectbox("Select Histogram",["Pie_Chart", "Line_Chart", "Bar_Chart", "Scatter_Chart"])
                if Graph == "Pie_Chart":
                    st.plotly_chart(px.pie(grouped_data, values='amount', names='servicecode', title='Proportion of Amount by Servicecode'), use_container_width=True)
                elif Graph == 'Line_Chart':
                    st.plotly_chart(px.line(grouped_data, x=grouped_data.columns[0], y='amount', color='servicecode', markers=True), use_container_width=True)
                elif Graph == 'Bar_Chart':
                    st.plotly_chart(px.bar(grouped_data, y=grouped_data.columns[0], x='amount', color='servicecode', barmode='group', orientation='h'), use_container_width=True)
                elif Graph == 'Scatter_Chart':
                    st.plotly_chart(px.scatter(grouped_data, x=grouped_data.columns[0], y='amount', color='servicecode'), use_container_width=True)

            st.divider()
            st.markdown("### ROKU DATA SET  - 2025")
            grid_options = GridOptionsBuilder.from_dataframe(df)
            grid_options.configure_default_column(
                enablePivot=True, enableValue=True, enableRowGroup=True, sortable=True, filterable=True)
            grid_options.configure_pagination(paginationAutoPageSize=True)
            AgGrid(df, gridOptions=grid_options.build())
            st.divider()
    #-------------------------------------------------------------------------------------------------------------------------------------------
    @cached(cache=TTLCache(maxsize=2,ttl=1800))  # Roku Analysis
    def echo(self):
        st.markdown(
            '<p style="font-family:sans-serif;text-align:center; color:#3bc0f5; font-size: 30px;">📊ANALYSIS ON ROKU DATA📊</p>',
            unsafe_allow_html=True
        )
        st.divider()
        #st.header("📊 Roku Analysis")
        

        @cached(cache=TTLCache(maxsize=2,ttl=1800))
        def fetch_roku_data():
            engine = Database.get_engine()
            if engine:
                try:
                    query = """
                            SELECT reportdate, servicecode, Model, rate, qty, amount 
                            FROM Billing.tdi_invoice_details 
                            WHERE invoice_code = 'Roku'
                            AND reportdate >= '2025-01-01'
                        """
                    df = pd.read_sql(text(query), engine)
                    return df
                except Exception as e:
                    st.error(f"Error while fetching data from MySQL: {e}")
                    return None
            return None

        # Fetch data
        with st.spinner("Loading data..."):
            df = fetch_roku_data()
            
        if df is not None:
            try:
                # Convert columns to appropriate types
                df['reportdate'] = pd.to_datetime(df['reportdate'], errors='coerce')
                df['qty'] = pd.to_numeric(df['qty'], errors='coerce')
                df['amount'] = pd.to_numeric(df['amount'], errors='coerce')
                df['rate'] = pd.to_numeric(df['rate'], errors='coerce')

                # Drop rows with missing important values
                df.dropna(subset=['reportdate', 'qty', 'amount', 'rate'], inplace=True)

                # Add date parts
                df['Week'] = df['reportdate'].dt.isocalendar().week
                df['Month'] = df['reportdate'].dt.month
                df['Quarter'] = df['reportdate'].dt.quarter
                df['Year'] = df['reportdate'].dt.year

            except Exception as e:
                st.error(f"Error processing data: {e}")
            else:
                required_cols = ['reportdate', 'servicecode', 'Model', 'rate', 'qty', 'amount']
                if not all(col in df.columns for col in required_cols):
                    st.error(f"❌ Database table must contain these columns: {', '.join(required_cols)}")
                    st.divider()
                else:
                    # Display data summary
                    st.subheader("📌Data Summary")
                    col_summary1, col_summary2,col_summary3 = st.columns(3)
                    with col_summary1:
                        st.metric("Total Records", len(df))
                    with col_summary3:
                        st.metric("Total Revenue", f"${df['amount'].sum():,.2f}")
                    with col_summary2:
                        st.metric("Total Quantity", f"{df['qty'].sum():,}")
                    st.divider()
                        
                    # Tabs layout
                    tab1, tab2, tab3 = st.tabs(["📌 Summary", "📈 Trend Analysis", "📅 Time-based Insights"])
                    st.divider()

                    with tab1:
                        st.subheader("📌 High & Low Revenue Models")
                            
                        # Calculate metrics
                        total_revenue = df['amount'].sum()
                        total_qty = df['qty'].sum()
                        avg_rate = df['rate'].mean()
                            
                        # Create metric columns
                        col_metrics1, col_metrics2, col_metrics3 = st.columns(3)
                        with col_metrics3:
                            st.metric("Total Revenue", f"${total_revenue:,.2f}")
                        with col_metrics2:
                            st.metric("Total Quantity", f"{total_qty:,}")
                        with col_metrics1:
                            st.metric("Average Rate", f"${avg_rate:,.2f}")
                            st.divider()

                        col1, col2 = st.columns(2)

                        with col1:
                            # Highest 3 Models by Quantity
                            top_qty = df.groupby("Model")["qty"].sum().sort_values(ascending=False).head(3)
                            st.write("### 🔼 Highest 3 Models by Quantity")
                            
                            # Configure AgGrid
                            gb_qty = GridOptionsBuilder.from_dataframe(
                                top_qty.reset_index().rename(columns={'qty': 'Total Quantity'})
                            )
                            gb_qty.configure_column("Model", headerName="Model", width=150)
                            gb_qty.configure_column("Total Quantity", 
                                                headerName="Total Quantity", 
                                                type=["numericColumn", "numberColumnFilter"],
                                                width=120)
                            gb_qty.configure_default_column(
                                resizable=True,
                                filterable=True,
                                sortable=True,
                                editable=False
                            )
                            grid_options_qty = gb_qty.build()
                            
                            AgGrid(
                                top_qty.reset_index().rename(columns={'qty': 'Total Quantity'}),
                                gridOptions=grid_options_qty,
                                height=120,
                                theme='streamlit',
                                fit_columns_on_grid_load=True
                            )
                            
                            # Highest 3 Models by Revenue
                            top_amount = df.groupby("Model")["amount"].sum().sort_values(ascending=False).head(3)
                            st.write("### 🔼 Highest 3 Models by Revenue")
                            
                            # Configure AgGrid
                            gb_amount = GridOptionsBuilder.from_dataframe(
                                top_amount.reset_index().rename(columns={'amount': 'Total Revenue ($)'})
                            )
                            gb_amount.configure_column("Model", headerName="Model", width=150)
                            gb_amount.configure_column("Total Revenue ($)",
                                                    headerName="Total Revenue ($)",
                                                    type=["numericColumn", "numberColumnFilter"],
                                                    width=150,
                                                    valueFormatter="value.toLocaleString('en-US', {style: 'currency', currency: 'USD', minimumFractionDigits: 2})")
                            gb_amount.configure_default_column(
                                resizable=True,
                                filterable=True,
                                sortable=True,
                                editable=False
                            )
                            grid_options_amount = gb_amount.build()
                            
                            AgGrid(
                                top_amount.reset_index().rename(columns={'amount': 'Total Revenue ($)'}),
                                gridOptions=grid_options_amount,
                                height=120,
                                theme='streamlit',
                                fit_columns_on_grid_load=True
                            )
                        
                                                        
                        with col2:
                            # Least 3 Models by Quantity
                            bottom_qty = df.groupby("Model")["qty"].sum().sort_values(ascending=True).head(3)
                            st.write("### 🔽 Least 3 Models by Quantity")
                            
                            # Configure AgGrid
                            gb_bottom_qty = GridOptionsBuilder.from_dataframe(
                                bottom_qty.reset_index().rename(columns={'qty': 'Total Quantity'})
                            )
                            gb_bottom_qty.configure_column("Model", headerName="Model", width=150)
                            gb_bottom_qty.configure_column("Total Quantity", 
                                                        headerName="Total Quantity", 
                                                        type=["numericColumn", "numberColumnFilter"],
                                                        width=120)
                            gb_bottom_qty.configure_default_column(
                                resizable=True,
                                filterable=True,
                                sortable=True,
                                editable=False
                            )
                            grid_options_bottom_qty = gb_bottom_qty.build()
                            
                            AgGrid(
                                bottom_qty.reset_index().rename(columns={'qty': 'Total Quantity'}),
                                gridOptions=grid_options_bottom_qty,
                                height=120,
                                theme='streamlit',
                                fit_columns_on_grid_load=True
                            )
                            
                            # Least 3 Models by Revenue
                            bottom_amount = df.groupby("Model")["amount"].sum().sort_values(ascending=True).head(3)
                            st.write("### 🔽 Least 3 Models by Revenue")
                            
                            # Configure AgGrid
                            gb_bottom_amount = GridOptionsBuilder.from_dataframe(
                                bottom_amount.reset_index().rename(columns={'amount': 'Total Revenue ($)'})
                            )
                            gb_bottom_amount.configure_column("Model", headerName="Model", width=150)
                            gb_bottom_amount.configure_column("Total Revenue ($)",
                                                            headerName="Total Revenue ($)",
                                                            type=["numericColumn", "numberColumnFilter"],
                                                            width=150,
                                                            valueFormatter="value.toLocaleString('en-US', {style: 'currency', currency: 'USD', minimumFractionDigits: 2})")
                            gb_bottom_amount.configure_default_column(
                                resizable=True,
                                filterable=True,
                                sortable=True,
                                editable=False
                            )
                            grid_options_bottom_amount = gb_bottom_amount.build()
                            
                            AgGrid(
                                bottom_amount.reset_index().rename(columns={'amount': 'Total Revenue ($)'}),
                                gridOptions=grid_options_bottom_amount,
                                height=120,
                                theme='streamlit',
                                fit_columns_on_grid_load=True
                            )

                    with tab2:
                        st.subheader("📈 Revenue & Quantity Trends")
                        st.divider()
                            
                        # Calculate daily trends
                        revenue_trend = df.groupby("reportdate")["amount"].sum()
                        qty_trend = df.groupby("reportdate")["qty"].sum()
                            
                        # Create metric columns for trends
                        col_trend1, col_trend2 = st.columns(2)

                        with col_trend1:
                            st.metric("Peak Revenue Per Day", 
                                    f"${revenue_trend.max():,.2f}", 
                                    revenue_trend.idxmax().strftime('%Y-%m-%d'))
                        with col_trend2:
                            st.metric("Peak Quantity Per Day", 
                                    f"{qty_trend.max():,}", 
                                    qty_trend.idxmax().strftime('%Y-%m-%d'))
                        st.divider()

                        # Service code analysis
                        col_service1, col_service2 = st.columns(2)
                        with col_service1:
                            st.write("### �️ Most Frequent ServiceCode")
                            freq_service = df['servicecode'].value_counts().head(10)
                            st.dataframe(freq_service.reset_index().rename(
                                columns={'index': 'ServiceCode', 'servicecode': 'Count'}))

                        with col_service2:
                            st.write("### 💰 Highest Revenue-Generating ServiceCode")
                            revenue_service = df.groupby("servicecode")["amount"].sum().sort_values(ascending=False).head(10)
                            st.dataframe(revenue_service.reset_index().rename(
                                columns={'amount': 'Total Revenue ($)'}))

                         # Average rate analysis
                        avg_rate = df.groupby("Model")["rate"].mean().sort_values(ascending=False)
                        st.write("### 🧮 Average Rate per Model")
                        st.dataframe(avg_rate.reset_index().rename(columns={'rate': 'Average Rate ($)'}))
                        st.divider()

                        st.subheader("Plot Trend")
                        # Plot trends
                        fig, ax = plt.subplots(figsize=(12, 5))
                        revenue_trend.plot(ax=ax, label="Revenue", color='green')
                        qty_trend.plot(ax=ax, label="Quantity", color='blue')
                        ax.legend()
                        ax.set_title("📆 Daily Revenue & Quantity Trend")
                        ax.set_ylabel("Amount / Quantity")
                        st.pyplot(fig)

                       

                        
                    with tab3:
                        st.subheader("📅 Model Analysis")
                        st.divider()
                        
                        # Custom CSS for styled dataframes
                        st.markdown("""
                        <style>
                            /* Style column headers */
                            .st.dataframe thead th {
                                background-color: #add8e6 !important;  /* Light blue */
                                color: black !important;
                                text-align: center !important;
                            }
                            
                            /* Style index header */
                            .st.dataframe thead th:first-child {
                                background-color: #add8e6 !important;  /* Light blue */
                                color: black !important;
                                text-align: center !important;
                            }
                            
                            /* Center all data cells */
                            .st.dataframe td {
                                text-align: center !important;
                            }
                            
                            /* Center index cells */
                            .st.dataframe th.index_name {
                                text-align: center !important;
                            }
                            
                            /* Center index values */
                            .st.dataframe td.index_column {
                                text-align: center !important;
                            }
                        </style>
                        """, unsafe_allow_html=True)
                        
                    # Time-based model occurrence
                    # Weekly counts
                    # Group data
                        weekly_model = df.groupby(["Year", "Week", "Model"]).size().reset_index(name='count')
                        # Sort and filter top 10
                        top10_weekly_model = weekly_model.sort_values(by="count", ascending=False).head(10)
                        # Display with AgGrid
                        st.write("### 📆 Weekly Occurrences (Top 10)")
                        # Set AgGrid options
                        gb = GridOptionsBuilder.from_dataframe(top10_weekly_model)
                        gb.configure_default_column(cellStyle={'textAlign': 'center'})
                        gb.configure_grid_options(domLayout='autoHeight')
                        gridOptions = gb.build()
                        AgGrid(top10_weekly_model, gridOptions=gridOptions, height=400, fit_columns_on_grid_load=True)
                    

                        # Group by Year, Month, and Model
                        monthly_model = df.groupby(["Year", "Month", "Model"]).size().reset_index(name='count')
                        # Sort and filter top 10
                        top10_monthly_model = monthly_model.sort_values(by='count', ascending=False).head(10)
                        # Display header
                        st.write("### 📆 Monthly Occurrences (Top 10)")
                        # Build grid options
                        gb = GridOptionsBuilder.from_dataframe(top10_monthly_model)
                        # Center align both cells and headers
                        gb.configure_default_column(
                            cellStyle={'textAlign': 'center'},
                            headerStyle={'textAlign': 'left'}
                        )
                        # Other grid settings
                        gb.configure_grid_options(domLayout='autoHeight')
                        gridOptions = gb.build()

                        # Display the AgGrid
                        AgGrid(top10_monthly_model, gridOptions=gridOptions, height=400, fit_columns_on_grid_load=True)
                        #---------------------------------------------------------------------
                        quarterly_model = df.groupby(["Year", "Quarter", "Model"]).size().reset_index(name='count')
                        st.write("### 📆 Quarterly Occurrences (Top 10)")

                        gb = GridOptionsBuilder.from_dataframe( quarterly_model)
                        gb.configure_default_column(cellStyle={'textAlign': 'center'})
                        gb.configure_grid_options(domLayout='normal')
                        gridOptions = gb.build()
                        AgGrid( quarterly_model, gridOptions=gridOptions, height=400, fit_columns_on_grid_load=True)
                        
                        # Revenue share pie chart
                        st.write("### 📊 Revenue Share by Top 10 Models")
                        revenue_share = df.groupby("Model")["amount"].sum().sort_values(ascending=False).head(10)
                        
                        col_pie1, col_pie2 = st.columns([1, 2])
                        
                        
                        with col_pie1:
                            st.dataframe(
                            revenue_share.reset_index()
                            .rename(columns={'amount': 'Total Revenue ($)'})
                            .style
                            .format({'Total Revenue ($)': '{:,.2f}'})  # Format to 2 decimal places
                            .set_properties(**{'text-align': 'center'}),
                            use_container_width=True
                        )

                        with col_pie2:
                            fig2, ax2 = plt.subplots()
                            ax2.pie(revenue_share, labels=revenue_share.index, autopct='%1.1f%%', startangle=140)
                            ax2.axis('equal')
                            st.pyplot(fig2)

# ---------------------------------------------------------------------------------------------------------------------------

# Main Application Execution
class AppExe:
    def __init__(self):
        try:
            self.auth = Authentication()
            self.app = ContecApp()
        except Exception as e:
            st.error(f"Application initialization failed: {str(e)}")
            st.stop()  # Prevent further execution
        
    @cached(cache=TTLCache(maxsize=2, ttl=1800))
    def run(self):
        if 'authenticated' not in st.session_state:
            st.session_state['authenticated'] = False
        
        if not st.session_state['authenticated']:
            self.auth.login_page()
        else:
            with st.sidebar:
                #st.image("C:/clak/_app/_roku_run/contec.png", width=200)
                st.image("C:/clak/_alfa_projects/contec_roku/contec.png", width=175)
                
                
                # Add user management option for admins
                if st.session_state.get('is_admin'):
                    if st.sidebar.button("👑 User Management"):
                        st.session_state['current_page'] = 'user_management'
                
                st.sidebar.header("Roku_Data")
                options = st.sidebar.selectbox(
                    "Select_Service:",
                    ["Home_Page","1️⃣Monthly_Revenue_Graph", "2️⃣Weekly_Revenue_Data", "3️⃣Weekly_Services_Data", 
                     "4️⃣Statistical_Data","5️⃣Analysis_Data"])
                
                st.sidebar.button("Logout", on_click=lambda: [
                    st.session_state.update({
                        'authenticated': False,
                        'username': None,
                        'is_admin': False,
                        'current_page': None
                    }),
                    #st.rerun() # experimental_rerun on callback() no op
                ])
            
            # Check if we're on the user management page
            if st.session_state.get('current_page') == 'user_management':
                self.auth.user_management_page()
            else:
                # Your existing page routing
                if options == "Home_Page":
                    self.app.home_page()
                elif options == "1️⃣Monthly_Revenue_Graph":
                    self.app.alfa()
                elif options == "2️⃣Weekly_Revenue_Data":
                    self.app.beta()
                elif options == "3️⃣Weekly_Services_Data":
                    self.app.charlie()
                elif options == "4️⃣Statistical_Data":
                    self.app.delta()
                elif options == "5️⃣Analysis_Data":
                    self.app.echo()

if __name__ == "__main__":
    AppExe().run()
