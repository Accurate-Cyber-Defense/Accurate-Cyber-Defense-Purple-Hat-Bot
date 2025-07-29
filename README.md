# Accurate-Cyber-Defense-Purple-Hat-Bot

<img width="1536" height="1024" alt="5577a319-552a-4b6f-8155-032b711f233c" src="https://github.com/user-attachments/assets/a54c6bdc-7d4b-4ed2-9725-b1a6cea7c5bb" />

Accurate-Cyber-Defense-Purple-Hat-Bot is a modern, intelligent cybersecurity tool built for real-time threat monitoring, detection, and alerting. It combines a powerful interactive command-line interface with automated threat detection and instant Telegram notifications.

Designed with a focus on modularity and performance, this bot empowers system administrators, DevOps teams, and security professionals with the tools to stay ahead of evolving cyber threats.

**Features**

**🔒 Real-Time Cyber Threat Detection**
Leverages `scapy` for deep packet inspection and a multi-threaded engine to analyze network traffic for threats like DoS attacks, port scans, and HTTP floods in real time.

**⚙️ Interactive Command-Line Interface**
A rich, color-coded CLI to manage monitoring, run network diagnostics, configure settings, and view threat reports.

**💡 Purple Team Tactics**
Combines offensive simulation tools with defensive monitoring capabilities, allowing you to test your defenses and respond effectively.

**📊 Comprehensive Threat Reporting**
Detected threats are logged, displayed in formatted tables, and can be exported to Telegram on-demand for a quick security overview.

**🔔 Instant Telegram Alerts**
Configure your Telegram bot token and chat ID to receive immediate, detailed alerts the moment a threat is detected.

**🛠️ Use Cases**

- **Monitoring:** Actively monitor one or more specific IPs on your network for malicious activity.
- **Diagnostics:** Quickly run network diagnostics like `ping`, `scan`, `tracert`, and `netstat` directly from the tool.
- **Threat Simulation:** Generate test traffic (`portscan`, `dos`, `httpflood`) to validate detection rules and response times.
- **Education:** A hands-on tool for learning about network defense and packet analysis.

**📦 Installation**

1.  Clone the repository:
    ```bash
    git clone https://github.com/Accurate-Cyber-Defense/Accurate-Cyber-Defense-Purple-Hat-Bot.git
    cd Accurate-Cyber-Defense-Purple-Hat-Bot
    ```

2.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

3.  (Optional but Recommended) Configure Telegram:
    Create `config/accuratecyberbot_config.json` or let the tool create a default one on first run. Then, use the in-app commands to set your credentials:
    ```
    AccurateBot> config telegram token YOUR_TOKEN
    AccurateBot> config telegram chat_id YOUR_CHAT_ID
    ```

4.  Run the bot:
    ```bash
    sudo python3 main.py
    ```
    *Note: `sudo` is often required for packet sniffing capabilities.*

**📸 CLI Preview**
The interface is clean, interactive, and powerful, providing clear feedback and formatted data tables for easy reading.

<img width="1000" alt="CLI Preview" src="https://i.imgur.com/example.png" />
*(Image is a representation of the CLI Though i cant really create one, perhaps another contributor can)*

**🤝 Contributing**

We welcome contributors from all backgrounds. Feel free to improve the detection rules, enhance the CLI, or add new features.

---
Stay safe. Stay informed. Stay accurate.

**modification log**
 -Successfully broke the project across files
 -Made the config fetched from the config file 
 -Made a propper requirements.txt because the installation called for one but there wasent one.
 -Optimized it for expandability and modularity
 -This Pullrequest IS SUPPOSED TO BE modified to fit the tool correctly
 -Spent way to long optimizing things im to lazy to list.. it tbh just felt like 99.99% ai with how many things didnt line up, no offense
 -i kinda stopped logging what i was doing because i had to change a bit...
