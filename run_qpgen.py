from qpgen import generate_password, QuantumPassConfig

def main() -> None:
    password = generate_password()  # uses DEFAULT_CONFIG from config.py
    print("\n[Quantum Superposition Password Generator]")
    print(f"Generated password: {password}\n")

if __name__ == "__main__":
    main()