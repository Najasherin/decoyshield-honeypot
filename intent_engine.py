def analyze_intent(ip, command=None, attempts=1):

    if command:
        command = command.lower()

        if "password" in command or "login" in command:
            return "BRUTE_FORCE"

        if "ls" in command or "whoami" in command:
            return "RECON"

    if attempts > 10:
        return "AGGRESSIVE_SCAN"

    return "PORT_SCAN"