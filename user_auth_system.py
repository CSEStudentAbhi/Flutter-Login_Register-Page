import os
import hashlib
import re

class UserAuthSystem:
    def __init__(self, filename="users.txt"):
        self.filename = filename
        self.users = {}
        self.load_users()
    
    def load_users(self):
        """Load existing users from the text file"""
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as file:
                    for line in file:
                        line = line.strip()
                        if line and ':' in line:
                            username, password_hash = line.split(':', 1)
                            self.users[username] = password_hash
            except FileNotFoundError:
                print(f"User file {self.filename} not found. Creating new file.")
    
    def save_users(self):
        """Save users to the text file"""
        try:
            with open(self.filename, 'w') as file:
                for username, password_hash in self.users.items():
                    file.write(f"{username}:{password_hash}\n")
            return True
        except Exception as e:
            print(f"Error saving users: {e}")
            return False
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def validate_username(self, username):
        """Validate username format"""
        if len(username) < 3:
            return False, "Username must be at least 3 characters long"
        if len(username) > 20:
            return False, "Username must be less than 20 characters"
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return False, "Username can only contain letters, numbers, and underscores"
        return True, ""
    
    def validate_password(self, password):
        """Validate password strength"""
        if len(password) < 6:
            return False, "Password must be at least 6 characters long"
        if len(password) > 50:
            return False, "Password must be less than 50 characters"
        return True, ""
    
    def register(self, username, password):
        """Register a new user"""
        # Validate username
        is_valid, error_msg = self.validate_username(username)
        if not is_valid:
            return False, error_msg
        
        # Check if username already exists
        if username in self.users:
            return False, "Username already exists"
        
        # Validate password
        is_valid, error_msg = self.validate_password(password)
        if not is_valid:
            return False, error_msg
        
        # Hash password and save user
        password_hash = self.hash_password(password)
        self.users[username] = password_hash
        
        # Save to file
        if self.save_users():
            return True, "Registration successful!"
        else:
            # Remove from memory if save failed
            del self.users[username]
            return False, "Registration failed. Please try again."
    
    def login(self, username, password):
        """Login user"""
        if username not in self.users:
            return False, "Username not found"
        
        password_hash = self.hash_password(password)
        if self.users[username] == password_hash:
            return True, "Login successful!"
        else:
            return False, "Incorrect password"
    
    def list_users(self):
        """List all registered usernames (for admin purposes)"""
        return list(self.users.keys())

def main():
    auth_system = UserAuthSystem()
    
    while True:
        print("\n" + "="*50)
        print("USER AUTHENTICATION SYSTEM")
        print("="*50)
        print("1. Register")
        print("2. Login")
        print("3. List Users (Admin)")
        print("4. Exit")
        print("="*50)
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            print("\n--- REGISTRATION ---")
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            confirm_password = input("Confirm password: ").strip()
            
            if password != confirm_password:
                print("Error: Passwords do not match!")
                continue
            
            success, message = auth_system.register(username, password)
            print(f"{'SUCCESS' if success else 'ERROR'}: {message}")
        
        elif choice == "2":
            print("\n--- LOGIN ---")
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            
            success, message = auth_system.login(username, password)
            print(f"{'SUCCESS' if success else 'ERROR'}: {message}")
            
            if success:
                print(f"Welcome, {username}!")
        
        elif choice == "3":
            print("\n--- REGISTERED USERS ---")
            users = auth_system.list_users()
            if users:
                for i, user in enumerate(users, 1):
                    print(f"{i}. {user}")
            else:
                print("No users registered yet.")
        
        elif choice == "4":
            print("Thank you for using the authentication system!")
            break
        
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main() 