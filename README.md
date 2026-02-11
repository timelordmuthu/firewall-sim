# firewall-sim
# 🛡️ Simple Firewall Simulator

This is a lightweight **Stateless Firewall Simulator** written in Python. It mimics how network routers and security appliances filter traffic using Access Control Lists (ACLs).

---

## 🧠 The Logic (How it thinks)

The firewall operates on a **Sequential Evaluation** model. Think of it like a bouncer at a club with a checklist:

1.  **Top-Down Processing:** The firewall starts at the very first rule in your list and moves down one by one.
2.  **The "First Match" Rule:** As soon as a packet matches a rule's criteria (IP, Port, and Protocol), the firewall makes a decision (**ALLOW** or **BLOCK**) and **stops looking**. It doesn't matter if a later rule says something different.
3.  **Wildcards (`*`):** If a rule uses a `*`, it acts as a "catch-all" for that specific field.
4.  **The Safety Net (Default Policy):** If a packet doesn't match any of your custom rules, it hits the "Default Policy." In this simulator, the default is set to `ALLOW`.



---

## 🚀 Installation & Usage

### 1. Requirements
* Python 3.x installed on your machine.

### 2. Running the Simulator
Run the following command in your terminal or command prompt:
```bash
python firewall_sim.py
