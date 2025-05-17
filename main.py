import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import psutil
import datetime
import pymem
import socket
import os

def display_processes():
    # Clear previous content
    for item in process_tree.get_children():
        process_tree.delete(item)

    # Display processes
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'create_time'])
            create_time = datetime.datetime.fromtimestamp(pinfo['create_time']).strftime("%Y-%m-%d %H:%M:%S")
            memory_usage = get_memory_usage(pinfo['pid'])
            cpu_usage = get_cpu_usage(pinfo['pid'])
            process_tree.insert('', tk.END, values=(pinfo['pid'], pinfo['name'], create_time, memory_usage, cpu_usage))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def get_memory_usage(pid):
    try:
        pm = pymem.Pymem()
        process_base = pm.open_process(pid)
        memory_info = process_base.get_memory_info()
        memory_usage_mb = memory_info['WorkingSetSize'] / (1024 * 1024)  # Memory usage in MB
        return f"{memory_usage_mb:.2f} MB"
    except Exception as e:
        print(f"Error fetching memory info for PID {pid}: {e}")
        return "N/A"

def get_cpu_usage(pid):
    try:
        process = psutil.Process(pid)
        cpu_usage = process.cpu_percent()
        return f"{cpu_usage:.2f} %"
    except psutil.NoSuchProcess:
        return "N/A"

def display_network_connections():
    # Clear previous content
    for item in network_tree.get_children():
        network_tree.delete(item)

    # Display network connections
    for conn in psutil.net_connections(kind='inet'):
        try:
            local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown"
            remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown"
            pid_name = get_process_name(conn.pid)
            network_tree.insert('', tk.END, values=(conn.pid, pid_name, conn.status, local_address, remote_address))
        except Exception as e:
            print(f"Error processing network connection: {e}")

def get_process_name(pid):
    try:
        process = psutil.Process(pid)
        return process.name() if process else "Unknown"
    except psutil.NoSuchProcess:
        return "N/A"

def display_loaded_drivers():
    try:
        output = os.popen("driverquery /FO CSV").read().splitlines()
        for line in output[1:]:
            values = line.split(',')
            if len(values) >= 2:
                driver_name, description = values[0], values[1]
                loaded_drivers_tree.insert('', tk.END, values=(driver_name.strip('"'), description.strip('"')))
    except Exception as e:
        print(f"Error displaying loaded drivers: {e}")

def save_to_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write("Processes:\n")
            for item in process_tree.get_children():
                values = process_tree.item(item, 'values')
                file.write(", ".join(map(str, values)) + "\n")
            file.write("\nNetwork Connections:\n")
            for item in network_tree.get_children():
                values = network_tree.item(item, 'values')
                file.write(", ".join(map(str, values)) + "\n")
            file.write("\nLoaded Drivers:\n")
            for item in loaded_drivers_tree.get_children():
                values = loaded_drivers_tree.item(item, 'values')
                file.write(", ".join(map(str, values)) + "\n")
        print(f"Data saved to {file_path}")

def refresh():
    display_processes()
    display_network_connections()
    display_loaded_drivers()

# Create main window
root = tk.Tk()
root.title("Memory Forensics Tool")

# Create notebook (tabbed interface)
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# Create Processes tab
process_tab = ttk.Frame(notebook)
notebook.add(process_tab, text='Processes')

# Create Treeview for displaying processes
process_tree = ttk.Treeview(process_tab, columns=("PID", "Name", "Start Time", "Memory Usage", "CPU Usage"), show="headings")
process_tree.pack(fill='both', expand=True)

process_tree_scroll = ttk.Scrollbar(process_tab, orient="vertical", command=process_tree.yview)
process_tree_scroll.pack(side="right", fill="y")

process_tree.configure(yscrollcommand=process_tree_scroll.set)

# Set column headings for processes
process_tree.heading("PID", text="PID")
process_tree.heading("Name", text="Name")
process_tree.heading("Start Time", text="Start Time")
process_tree.heading("Memory Usage", text="Memory Usage")
process_tree.heading("CPU Usage", text="CPU Usage")

# Create Network Connections tab
network_tab = ttk.Frame(notebook)
notebook.add(network_tab, text='Network Connections')

# Create Treeview for displaying network connections
network_tree = ttk.Treeview(network_tab, columns=("PID", "Name", "Status", "Local Address", "Remote Address"), show="headings")
network_tree.pack(fill='both', expand=True)

network_tree_scroll = ttk.Scrollbar(network_tab, orient="vertical", command=network_tree.yview)
network_tree_scroll.pack(side="right", fill="y")

network_tree.configure(yscrollcommand=network_tree_scroll.set)

# Set column headings for network connections
network_tree.heading("PID", text="PID")
network_tree.heading("Name", text="Name")
network_tree.heading("Status", text="Status")
network_tree.heading("Local Address", text="Local Address")
network_tree.heading("Remote Address", text="Remote Address")

# Create Loaded Drivers tab
drivers_tab = ttk.Frame(notebook)
notebook.add(drivers_tab, text='Loaded Drivers')

# Create Treeview for displaying loaded drivers
loaded_drivers_tree = ttk.Treeview(drivers_tab, columns=("Driver Name", "Description"), show="headings")
loaded_drivers_tree.pack(fill='both', expand=True)

loaded_drivers_tree_scroll = ttk.Scrollbar(drivers_tab, orient="vertical", command=loaded_drivers_tree.yview)
loaded_drivers_tree_scroll.pack(side="right", fill="y")

loaded_drivers_tree.configure(yscrollcommand=loaded_drivers_tree_scroll.set)

# Set column headings for loaded drivers
loaded_drivers_tree.heading("Driver Name", text="Driver Name")
loaded_drivers_tree.heading("Description", text="Description")

# Display processes, network connections, and loaded drivers initially
display_processes()
display_network_connections()
display_loaded_drivers()

# Save as File button
save_button = tk.Button(root, text="Save as File", command=save_to_file)
save_button.pack()

# Refresh button
refresh_button = tk.Button(root, text="Refresh", command=refresh)
refresh_button.pack()

root.mainloop()
