import random
import time
from datetime import datetime
import hashlib

# Simulated database of users
users_db = {
    'vamsi': {'password': 'vamsi123', 'role': 'admin', 'location': 'NY', 'status': 'active'},
    'shiva': {'password': 'shiva123', 'role': 'user', 'location': 'NY', 'status': 'inactive'},
    'raju': {'password': 'raju123', 'role': 'user', 'location': 'NY', 'status': 'active'},
    'akash': {'password': 'akash123', 'role': 'admin', 'location': 'INDIA', 'status': 'inactive'},
    'yashwanth': {'password': 'yashwanth123', 'role': 'user', 'location': 'INDIA', 'status': 'active'},
}

# Simulated resources with access control
resources = {
    'admin_dashboard': ['admin'],
    'user_data': ['user', 'admin'],
}

# Log for monitoring
activity_log = []

def log_activity(user, action):
    """Logs user activities for monitoring purposes."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    activity_log.append({'timestamp': timestamp, 'user': user, 'action': action})

# 1) Identity and Access Management (IAM) Module
def authenticate(username, password):
    """Authenticates the user using IAM principles."""
    user = users_db.get(username)
    if user and user['password'] == password:
        if user['status'] == 'active':
            log_activity(username, 'Authenticated')
            return username
        else:
            print("User account is inactive.")
    else:
        print("Invalid username or password.")
    return None

# 2) Network Segmentation Module
def authorize(user, resource):
    """Checks if the user is authorized to access the resource."""
    user_role = users_db[user]['role']
    allowed_roles = resources.get(resource, [])
    
    if user_role in allowed_roles:
        log_activity(user, f'Accessed {resource}')
        return True
    else:
        log_activity(user, f'Access denied for {resource}')
        print(f"Access denied: User '{user}' does not have permission to access '{resource}'.")
        return False

# 3) Data Encryption Module
def encrypt_data(data):
    """Encrypts data using a simple hashing technique for demonstration."""
    return hashlib.sha256(data.encode()).hexdigest()

# 4) Real-Time Threat Detection and Monitoring Module
def monitor_user_activity():
    """Simulates monitoring user activity."""
    print("\nActivity Log:")
    for entry in activity_log:
        print(f"[{entry['timestamp']}] User: {entry['user']}, Action: {entry['action']}")

# 5) Access Control Policies and Continuous Verification Module
def verify_user_location(user, expected_location):
    """Checks if the user is accessing from an expected location."""
    if users_db[user]['location'] != expected_location:
        print(f"Location mismatch: User '{user}' is in '{users_db[user]['location']}' instead of '{expected_location}'.")
        log_activity(user, 'Location verification failed')
        return False
    log_activity(user, 'Location verified')
    return True

# 6) Audit and Compliance Module
def audit_log():
    """Audit the activity log."""
    print("\nAudit Log:")
    for entry in activity_log:
        print(f"[{entry['timestamp']}] User: {entry['user']}, Action: {entry['action']}")

def continuous_evaluation(user):
    """Periodically check user's status and location during the session."""
    while True:
        # Simulate time interval for evaluation (e.g., every 10 seconds)
        time.sleep(20)
        print(f"\nContinuous evaluation for user '{user}'...")
        # Check if the user is still in the expected location
        if not verify_user_location(user, users_db[user]['location']):
            print("Access terminated due to location mismatch.")
            return False  # Terminate the session if the location is not verified

def main():
    """Main function to run the Zero Trust simulation."""
    print("Welcome to the Zero Trust Architecture Simulation!")
    
    # User input for authentication
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    authenticated_user = authenticate(username, password)
    
    if authenticated_user:
        print(f"Welcome, {authenticated_user}!")
        
        # Initial location verification
        if not verify_user_location(authenticated_user, 'NY'):
            return
        
        # Start continuous evaluation in a separate thread
        import threading
        evaluation_thread = threading.Thread(target=continuous_evaluation, args=(authenticated_user,))
        evaluation_thread.daemon = True  # Allow the thread to exit when the main program does
        evaluation_thread.start()

        while True:
            resource = input("Enter the resource you want to access (admin_dashboard/user_data) or 'exit' to quit: ")
            if resource.lower() == 'exit':
                break
            authorize(authenticated_user, resource)

    monitor_user_activity()
    audit_log()

if __name__ == "__main__":
    main()
