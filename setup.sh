#!/bin/bash

# N0-BODYKNOWS Network Setup Script
# Automated setup for secure communications system

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Python is installed
check_python() {
    print_status "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python $PYTHON_VERSION found"
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_VERSION=$(python --version | cut -d' ' -f2)
        print_success "Python $PYTHON_VERSION found"
        PYTHON_CMD="python"
    else
        print_error "Python is not installed. Please install Python 3.8+ first."
        exit 1
    fi
    
    # Check Python version
    if [[ $(echo "$PYTHON_VERSION 3.8" | tr " " "\n" | sort -V | head -n1) != "3.8" ]]; then
        print_error "Python 3.8+ is required. Found version: $PYTHON_VERSION"
        exit 1
    fi
}

# Create virtual environment
create_venv() {
    print_status "Creating virtual environment..."
    
    if [ -d "venv" ]; then
        print_warning "Virtual environment already exists. Removing old one..."
        rm -rf venv
    fi
    
    $PYTHON_CMD -m venv venv
    print_success "Virtual environment created"
}

# Activate virtual environment and install dependencies
install_dependencies() {
    print_status "Installing dependencies..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Dependencies installed from requirements.txt"
    else
        # Install core dependencies manually
        pip install rich cryptography
        print_success "Core dependencies installed"
    fi
    
    # Deactivate virtual environment
    deactivate
}

# Initialize system
initialize_system() {
    print_status "Initializing N0-BODYKNOWS Network..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Change to operational tools directory
    cd "Operational Tools"
    
    # Generate master key
    print_status "Generating master encryption key..."
    python key_generator.py --generate-master > /dev/null 2>&1
    print_success "Master key generated"
    
    # Create default agents
    print_status "Creating default agent accounts..."
    
    # Create admin agent
    python key_generator.py --create-agent admin --clearance admin > /dev/null 2>&1
    print_success "Admin agent created (ID: admin)"
    
    # Create field agent
    python key_generator.py --create-agent alpha --clearance field_agent > /dev/null 2>&1
    print_success "Field agent created (ID: alpha)"
    
    # Create operative agent
    python key_generator.py --create-agent bravo --clearance operative > /dev/null 2>&1
    print_success "Operative agent created (ID: bravo)"
    
    # Go back to root directory
    cd ../..
    
    # Deactivate virtual environment
    deactivate
}

# Create startup scripts
create_scripts() {
    print_status "Creating startup scripts..."
    
    # Create server startup script
    cat > start_server.sh << 'EOF'
#!/bin/bash
# N0-BODYKNOWS Command Center Startup Script

echo "🚀 Starting N0-BODYKNOWS Command Center..."
source venv/bin/activate
cd "Core Components"
python server.py
EOF
    
    # Create client startup script
    cat > start_client.sh << 'EOF'
#!/bin/bash
# N0-BODYKNOWS Operative Terminal Startup Script

if [ -z "$1" ]; then
    echo "Usage: $0 <agent_id>"
    echo "Available agents: admin, alpha, bravo"
    exit 1
fi

echo "🔐 Starting N0-BODYKNOWS Operative Terminal for agent: $1"
source venv/bin/activate
cd "Core Components"
python client.py --agent-id "$1"
EOF
    
    # Make scripts executable
    chmod +x start_server.sh
    chmod +x start_client.sh
    
    print_success "Startup scripts created"
}

# Display usage information
show_usage() {
    echo ""
    echo -e "${GREEN}🎯 N0-BODYKNOWS Network Setup Complete!${NC}"
    echo ""
    echo -e "${BLUE}Default Agent Credentials:${NC}"
    echo -e "  Admin:     ID=admin, Password=<shown during creation>"
    echo -e "  Field Agent: ID=alpha, Password=<shown during creation>"
    echo -e "  Operative:  ID=bravo, Password=<shown during creation>"
    echo ""
    echo -e "${BLUE}Quick Start Commands:${NC}"
    echo -e "  Start Command Center:  ${YELLOW}./start_server.sh${NC}"
    echo -e "  Connect as Agent:     ${YELLOW}./start_client.sh <agent_id>${NC}"
    echo ""
    echo -e "${BLUE}Manual Commands:${NC}"
    echo -e "  Activate environment: ${YELLOW}source venv/bin/activate${NC}"
    echo -e "  Start server:          ${YELLOW}cd \"Core Components\" && python server.py${NC}"
    echo -e "  Connect client:        ${YELLOW}cd \"Core Components\" && python client.py --agent-id <agent_id>${NC}"
    echo ""
    echo -e "${BLUE}Operational Tools:${NC}"
    echo -e "  Key Management:       ${YELLOW}cd \"Operational Tools\" && python key_generator.py${NC}"
    echo -e "  Log Cleaning:         ${YELLOW}cd \"Operational Tools\" && python log_cleaner.py${NC}"
    echo -e "  Network Testing:       ${YELLOW}cd \"Operational Tools\" && python network_test.py${NC}"
    echo ""
    echo -e "${BLUE}Documentation:${NC}"
    echo -e "  Operations Manual:    ${YELLOW}Documentation/op_manual.md${NC}"
    echo -e "  Communication Protocols: ${YELLOW}Documentation/protocols.md${NC}"
    echo -e "  Security Procedures:   ${YELLOW}Documentation/security.md${NC}"
    echo ""
    echo -e "${GREEN}🔐 System is ready for secure communications!${NC}"
    echo ""
}

# Main setup function
main() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              N0-BODYKNOWS NETWORK SETUP                  ║${NC}"
    echo -e "${BLUE}║            Secure Communications System                  ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    check_python
    create_venv
    install_dependencies
    initialize_system
    create_scripts
    show_usage
}

# Run main function
main "$@"
