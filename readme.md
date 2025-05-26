ECOCHAIN: Plant Trees, Grow a Greener FutureECOCHAIN is a decentralized platform designed to encourage and facilitate afforestation efforts to combat climate change. It connects individuals and investors with tree-planting projects, leveraging blockchain technology for transparency and accountability.Table of ContentsAbout ECOCHAINFeaturesCelo Wallet IntegrationGetting StartedPrerequisitesInstallationDatabase SetupRunning the ApplicationUsageRegular UsersInvestorsProject StructureAbout ECOCHAINECOCHAIN aims to make a tangible impact on climate change by promoting tree planting globally. Our platform offers a transparent way to track every tree planted, engage with a community of like-minded individuals, and for investors, to fund impactful environmental projects while tracking their contributions.FeaturesUser & Investor Dashboards: Personalized dashboards for both regular users and investors to track their activities and impact.Transparent Tree Tracking: Utilizes blockchain principles (simulated via verify_utils in this example) to ensure verification and transparency of afforestation efforts.Community Engagement: Connect with a global community dedicated to environmental action.Real-World Impact: Direct contribution to carbon sequestration, biodiversity, and ecosystem restoration.Role-Based Access: Separate login and signup flows, and protected dashboards for regular users and investors.Wallet Linking: Seamless integration for linking Celo wallets to user accounts for enhanced functionality (e.g., potential future token rewards or investment tracking).Support System: Contact and issue reporting features for user assistance.Celo Wallet IntegrationECOCHAIN integrates with Celo wallets to provide secure authentication and to potentially enable future blockchain-based features such as transparent tracking of tree planting, token rewards, or investment transactions.How it works:Wallet Verification API (/api/verify): When a user or investor wishes to link their Celo wallet, the application sends a message to their wallet for signature.Signature Verification: The signed message, along with the wallet address, is sent to the /api/verify endpoint. The verify_signature utility (assumed to be implemented in verify_utils.py) validates this signature against the wallet address and message.Account Linking/Login: Upon successful verification, the wallet address is securely linked to the user's ECOCHAIN account. If the user is logging in via wallet, they are authenticated and redirected to their respective dashboard (user or investor).This integration ensures a secure and decentralized way for users to interact with the platform, leveraging the power of the Celo blockchain.Getting StartedThese instructions will get you a copy of the project up and running on your local machine for development and testing purposes.PrerequisitesBefore you begin, ensure you have the following installed:Python 3.xpip (Python package installer)Flask: pip install FlaskFlask-SQLAlchemy: pip install Flask-SQLAlchemyFlask-Login: pip install Flask-LoginFlask-CORS: pip install Flask-CORSWerkzeug: (Usually installed with Flask, but ensure werkzeug.security is available for hashing)verify_utils.py: This file is crucial for Celo wallet signature verification. You'll need to provide your own implementation for verify_signature within this file, as it depends on Celo's specific signature verification logic (e.g., using web3.py with Celo's chain ID). A placeholder verify_utils.py might look like this:# verify_utils.py
def verify_signature(address, signature, message):
    # This is a placeholder. You need to implement actual Celo signature verification logic here.
    # This typically involves using a web3 library (e.g., web3.py) and Celo-specific utilities.
    # For demonstration purposes, this will always return True.
    print(f"Verifying signature for address: {address}, message: {message}, signature: {signature}")
    # In a real application, you would use web3.eth.account.recover_message
    # and compare the recovered address with the provided address.
    return True
InstallationClone the repository (if applicable):git clone [your-repo-url]
cd ecochain-app
Install Python dependencies:pip install -r requirements.txt # (if you create one)
# or manually:
pip install Flask Flask-SQLAlchemy Flask-Login Flask-CORS Werkzeug
Database SetupThe application uses SQLite, and the database file (Ecochain.db) will be created automatically.Ensure app.py is configured:app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Ecochain.db'
Create database tables:Run app.py once. The with app.app_context(): db.create_all() block will create the necessary tables, including the users table with the role column.Note: If you had an existing Ecochain.db without the role column, you might need to delete it or use a Flask-Migrate tool to apply schema changes.Running the Applicationpython app.py
The application will typically run on http://127.0.0.1:5000/.UsageRegular UsersSign Up: Navigate to /create-account to create a new user account.Login: Access /login to log in with your email and password.Dashboard: After logging in, you will be redirected to /dashboard to view your tree planting progress and activities.Wallet Linking: You can link your Celo wallet from your profile to enable blockchain-related features.InvestorsRegister: Go to /investor-signup to create an investor account.Login: Use /investor-login to access your investor dashboard.Investor Dashboard: After logging in, you will be redirected to /investor-dashboard to manage your investments and view project reports.Wallet Linking: It is highly recommended to link your Celo wallet for investment tracking and potential token interactions.Project Structure.
├── app.py                  # Main Flask application file
├── templates/              # HTML templates
│   ├── index.html          # Landing page
│   ├── login.html          # Regular user login form
│   ├── register.html       # Regular user signup form
│   ├── dashboard.html      # Regular user dashboard
│   ├── investor_login.html # Investor login form
│   ├── investor_signup.html# Investor signup form
│   ├── investor_dashboard.html # Investor dashboard
│   ├── wallet.html         # Wallet linking page
│   ├── help.html           # Help/Report Issue form
│   ├── 401.html            # Unauthorized error page
│   └── 404.html            # Not Found error page
├── static/                 # Static assets (CSS, JS, images)
│   ├── css/
│   │   └── styles.css
│   └── js/
│       └── scripts.js
└── verify_utils.py         # Utility for Celo signature verification (needs implementation)
