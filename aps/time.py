from datetime import datetime

# Get current date and time
current_time = datetime.now()

# Print current time
print("Current date and time:", current_time)

# If you want to format it (e.g., for specific output like "YYYY-MM-DD HH:MM:SS"):
formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
print("Formatted date and time:", formatted_time)
