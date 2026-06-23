import multiprocessing

# The socket to bind
bind = "0.0.0.0:5000"

# Number of concurrent worker processes
# Rule of thumb: (cpu_cores * 2) + 1
workers = multiprocessing.cpu_count() * 2 + 1

# Number of threads per worker
threads = 2

# Timeout limit for requests (in seconds)
timeout = 120

# Log files
accesslog = "-"  # Log access records to stdout/terminal stdout
errorlog = "-"   # Log error records to stderr
loglevel = "info"
