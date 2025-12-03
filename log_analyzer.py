#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analyseur de Logs de Sécurité
Auteur : Valérie Ename
Description : Détecte les tentatives de brute force et patterns d'attaque dans les logs
"""

import re
from collections import Counter, defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
from colorama import Fore, Style, init
import sys

# Initialiser colorama pour Windows
init(autoreset=True)

class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.failed_attempts = []
        self.successful_logins = []
        self.ip_failures = defaultdict(list)
        self.user_failures = defaultdict(list)
        self.alerts = []
        
        # Seuils de détection
        self.BRUTE_FORCE_THRESHOLD = 5  # Nombre de tentatives échouées pour considérer brute force
        self.TIME_WINDOW = 300  # Fenêtre de temps en secondes (5 minutes)
    
    def banner(self):
        """Affiche le banner"""
        print(Fore.CYAN + "="*70)
        print(Fore.CYAN + "   📊 ANALYSEUR DE LOGS DE SÉCURITÉ")
        print(Fore.CYAN + "   Auteur : Valérie Ename")
        print(Fore.CYAN + "   Date : " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print(Fore.CYAN + "="*70)
        print()
    
    def info(self, message):
        """Message d'information"""
        print(Fore.BLUE + "[ℹ] " + message)
    
    def success(self, message):
        """Message de succès"""
        print(Fore.GREEN + "[✓] " + message)
    
    def warning(self, message):
        """Message d'avertissement"""
        print(Fore.YELLOW + "[!] " + message)
    
    def error(self, message):
        """Message d'erreur"""
        print(Fore.RED + "[✗] " + message)
    
    def alert(self, message, severity="MEDIUM"):
        """Génère une alerte"""
        self.alerts.append({
            'message': message,
            'severity': severity,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        color = Fore.RED if severity == "HIGH" else Fore.YELLOW if severity == "MEDIUM" else Fore.BLUE
        print(color + f"[🚨] ALERTE {severity}: {message}")
    
    def parse_log_line(self, line):
        """Parse une ligne de log SSH"""
        # Pattern pour les tentatives échouées
        failed_pattern = r'Failed password for (\w+) from ([\d.]+) port (\d+)'
        failed_match = re.search(failed_pattern, line)
        
        if failed_match:
            return {
                'type': 'failed',
                'user': failed_match.group(1),
                'ip': failed_match.group(2),
                'port': failed_match.group(3),
                'timestamp': self.extract_timestamp(line)
            }
        
        # Pattern pour les connexions réussies
        success_pattern = r'Accepted password for (\w+) from ([\d.]+) port (\d+)'
        success_match = re.search(success_pattern, line)
        
        if success_match:
            return {
                'type': 'success',
                'user': success_match.group(1),
                'ip': success_match.group(2),
                'port': success_match.group(3),
                'timestamp': self.extract_timestamp(line)
            }
        
        return None
    
    def extract_timestamp(self, line):
        """Extrait le timestamp d'une ligne de log"""
        # Format : Dec  1 10:23:45
        timestamp_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)'
        match = re.search(timestamp_pattern, line)
        
        if match:
            try:
                # Ajouter l'année courante
                timestamp_str = match.group(1) + f" {datetime.now().year}"
                return datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            except:
                return datetime.now()
        
        return datetime.now()
    
    def analyze_logs(self):
        """Analyse le fichier de logs"""
        self.info(f"Analyse du fichier : {self.log_file}")
        
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            self.success(f"{len(lines)} lignes de logs à analyser")
            
            for line in lines:
                parsed = self.parse_log_line(line)
                
                if parsed:
                    if parsed['type'] == 'failed':
                        self.failed_attempts.append(parsed)
                        self.ip_failures[parsed['ip']].append(parsed)
                        self.user_failures[parsed['user']].append(parsed)
                    elif parsed['type'] == 'success':
                        self.successful_logins.append(parsed)
            
            self.success(f"Tentatives échouées : {len(self.failed_attempts)}")
            self.success(f"Connexions réussies : {len(self.successful_logins)}")
            print()
        
        except FileNotFoundError:
            self.error(f"Fichier non trouvé : {self.log_file}")
            sys.exit(1)
        except Exception as e:
            self.error(f"Erreur lors de la lecture du fichier : {e}")
            sys.exit(1)
    
    def detect_brute_force(self):
        """Détecte les tentatives de brute force"""
        self.info("Détection des attaques par brute force...")
        
        brute_force_ips = []
        
        for ip, attempts in self.ip_failures.items():
            if len(attempts) >= self.BRUTE_FORCE_THRESHOLD:
                brute_force_ips.append((ip, len(attempts)))
                self.alert(
                    f"Brute force détecté depuis {ip} : {len(attempts)} tentatives échouées",
                    "HIGH"
                )
        
        if not brute_force_ips:
            self.success("Aucune attaque par brute force détectée")
        else:
            self.warning(f"{len(brute_force_ips)} IP(s) suspecte(s) détectée(s)")
        
        print()
        return brute_force_ips
    
    def identify_suspicious_ips(self):
        """Identifie les IPs suspectes"""
        self.info("Identification des IPs suspectes...")
        
        # IPs avec le plus de tentatives échouées
        ip_counts = Counter({ip: len(attempts) for ip, attempts in self.ip_failures.items()})
        top_ips = ip_counts.most_common(10)
        
        print(Fore.YELLOW + "\n  Top 10 des IPs avec le plus de tentatives échouées :")
        for ip, count in top_ips:
            color = Fore.RED if count >= self.BRUTE_FORCE_THRESHOLD else Fore.YELLOW
            print(color + f"    {ip:20} : {count} tentatives")
        
        print()
        return top_ips
    
    def analyze_targeted_users(self):
        """Analyse les comptes utilisateurs ciblés"""
        self.info("Analyse des comptes utilisateurs ciblés...")
        
        user_counts = Counter({user: len(attempts) for user, attempts in self.user_failures.items()})
        top_users = user_counts.most_common(10)
        
        print(Fore.YELLOW + "\n  Top 10 des comptes les plus ciblés :")
        for user, count in top_users:
            print(Fore.YELLOW + f"    {user:20} : {count} tentatives")
        
        # Alerte pour les comptes sensibles
        sensitive_accounts = ['root', 'admin', 'administrator']
        for user in sensitive_accounts:
            if user in user_counts and user_counts[user] > 0:
                self.alert(
                    f"Compte sensible ciblé : {user} ({user_counts[user]} tentatives)",
                    "HIGH"
                )
        
        print()
        return top_users
    
    def check_successful_after_failed(self):
        """Vérifie les connexions réussies après des échecs"""
        self.info("Vérification des connexions réussies suspectes...")
        
        suspicious_success = []
        
        for success in self.successful_logins:
            ip = success['ip']
            user = success['user']
            
            # Vérifier si cette IP a eu des échecs avant
            if ip in self.ip_failures and len(self.ip_failures[ip]) >= 3:
                suspicious_success.append(success)
                self.alert(
                    f"Connexion réussie suspecte : {user}@{ip} après {len(self.ip_failures[ip])} échecs",
                    "MEDIUM"
                )
        
        if not suspicious_success:
            self.success("Aucune connexion réussie suspecte détectée")
        
        print()
        return suspicious_success
    
    def generate_statistics(self):
        """Génère des statistiques globales"""
        self.info("Génération des statistiques...")
        
        print(Fore.CYAN + "\n" + "="*70)
        print(Fore.CYAN + "   📊 STATISTIQUES GLOBALES")
        print(Fore.CYAN + "="*70)
        
        print(Fore.WHITE + f"\n  Total de lignes analysées : {len(self.failed_attempts) + len(self.successful_logins)}")
        print(Fore.RED + f"  Tentatives échouées : {len(self.failed_attempts)}")
        print(Fore.GREEN + f"  Connexions réussies : {len(self.successful_logins)}")
        print(Fore.YELLOW + f"  IPs uniques (échecs) : {len(self.ip_failures)}")
        print(Fore.YELLOW + f"  Comptes ciblés : {len(self.user_failures)}")
        print(Fore.RED + f"  Alertes générées : {len(self.alerts)}")
        
        # Taux de réussite
        total = len(self.failed_attempts) + len(self.successful_logins)
        if total > 0:
            success_rate = (len(self.successful_logins) / total) * 100
            print(Fore.BLUE + f"  Taux de réussite : {success_rate:.2f}%")
        
        print(Fore.CYAN + "="*70 + "\n")
    
    def create_visualizations(self):
        """Crée des graphiques de visualisation"""
        self.info("Génération des graphiques...")
        
        try:
            # Graphique 1 : Top IPs
            ip_counts = Counter({ip: len(attempts) for ip, attempts in self.ip_failures.items()})
            top_ips = ip_counts.most_common(10)
            
            if top_ips:
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
                fig.suptitle('Analyse de Logs de Sécurité', fontsize=16, fontweight='bold')
                
                # Graphique des IPs
                ips = [ip for ip, _ in top_ips]
                counts = [count for _, count in top_ips]
                
                ax1.barh(ips, counts, color='#ff4757')
                ax1.set_xlabel('Nombre de tentatives échouées')
                ax1.set_title('Top 10 IPs Suspectes')
                ax1.grid(axis='x', alpha=0.3)
                
                # Graphique des utilisateurs
                user_counts = Counter({user: len(attempts) for user, attempts in self.user_failures.items()})
                top_users = user_counts.most_common(10)
                
                users = [user for user, _ in top_users]
                user_count_values = [count for _, count in top_users]
                
                ax2.bar(users, user_count_values, color='#ffa502')
                ax2.set_ylabel('Nombre de tentatives')
                ax2.set_title('Top 10 Comptes Ciblés')
                ax2.tick_params(axis='x', rotation=45)
                ax2.grid(axis='y', alpha=0.3)
                
                plt.tight_layout()
                
                filename = f"log_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                plt.savefig(filename, dpi=300, bbox_inches='tight')
                self.success(f"Graphiques sauvegardés : {filename}")
                
                plt.show()
        
        except Exception as e:
            self.warning(f"Impossible de générer les graphiques : {e}")
    
    def generate_report(self):
        """Génère un rapport HTML"""
        self.info("Génération du rapport HTML...")
        
        filename = f"log_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Top IPs et utilisateurs
        ip_counts = Counter({ip: len(attempts) for ip, attempts in self.ip_failures.items()})
        top_ips = ip_counts.most_common(10)
        
        user_counts = Counter({user: len(attempts) for user, attempts in self.user_failures.items()})
        top_users = user_counts.most_common(10)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Analyse de Logs - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .summary {{
            padding: 40px;
            background: #f8f9fa;
        }}
        .summary h2 {{
            color: #1e3c72;
            margin-bottom: 20px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .stat-box {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .stat-number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .stat-number.red {{ color: #e74c3c; }}
        .stat-number.green {{ color: #27ae60; }}
        .stat-number.yellow {{ color: #f39c12; }}
        .stat-label {{
            color: #666;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        .alerts {{
            padding: 40px;
        }}
        .alerts h2 {{
            color: #1e3c72;
            margin-bottom: 30px;
        }}
        .alert-item {{
            background: #fee;
            border-left: 5px solid #e74c3c;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 5px;
        }}
        .alert-item.medium {{
            background: #ffeaa7;
            border-left-color: #f39c12;
        }}
        .alert-header {{
            font-weight: bold;
            color: #e74c3c;
            margin-bottom: 5px;
        }}
        .alert-item.medium .alert-header {{
            color: #f39c12;
        }}
        .tables {{
            padding: 40px;
            background: #f8f9fa;
        }}
        .tables h2 {{
            color: #1e3c72;
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        th {{
            background: #1e3c72;
            color: white;
            padding: 15px;
            text-align: left;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        footer {{
            background: #2c3e50;
            color: white;
            padding: 30px;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>📊 Rapport d'Analyse de Logs</h1>
            <p>Fichier : {self.log_file}</p>
            <p>Date : {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
        </header>
        
        <div class="summary">
            <h2>Résumé</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-number red">{len(self.failed_attempts)}</div>
                    <div class="stat-label">Échecs</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number green">{len(self.successful_logins)}</div>
                    <div class="stat-label">Réussites</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number yellow">{len(self.ip_failures)}</div>
                    <div class="stat-label">IPs Uniques</div>
                </div>
                <div class="stat-box">
                    <div class="stat-number red">{len(self.alerts)}</div>
                    <div class="stat-label">Alertes</div>
                </div>
            </div>
        </div>
        
        <div class="alerts">
            <h2>🚨 Alertes de Sécurité</h2>
{self._generate_alerts_html()}
        </div>
        
        <div class="tables">
            <h2>📍 Top 10 IPs Suspectes</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Adresse IP</th>
                        <th>Tentatives Échouées</th>
                        <th>Statut</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for idx, (ip, count) in enumerate(top_ips, 1):
            status = "🔴 CRITIQUE" if count >= self.BRUTE_FORCE_THRESHOLD else "⚠️ SUSPECT"
            html_content += f"""
                    <tr>
                        <td>{idx}</td>
                        <td>{ip}</td>
                        <td>{count}</td>
                        <td>{status}</td>
                    </tr>
"""
        
        html_content += """
                </tbody>
            </table>
            
            <h2>👤 Top 10 Comptes Ciblés</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Nom d'utilisateur</th>
                        <th>Tentatives</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for idx, (user, count) in enumerate(top_users, 1):
            user_type = "🔑 Sensible" if user in ['root', 'admin', 'administrator'] else "👤 Standard"
            html_content += f"""
                    <tr>
                        <td>{idx}</td>
                        <td>{user}</td>
                        <td>{count}</td>
                        <td>{user_type}</td>
                    </tr>
"""
        
        html_content += """
                </tbody>
            </table>
        </div>
        
        <footer>
            <p><strong>Analyseur de Logs de Sécurité</strong></p>
            <p>Développé par Valérie Ename | Bachelor AIS - Cybersécurité</p>
        </footer>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.success(f"Rapport généré : {filename}")
        
        # Ouvrir le rapport
        import webbrowser
        webbrowser.open(filename)
        
        return filename
    
    def _generate_alerts_html(self):
        """Génère le HTML des alertes"""
        if not self.alerts:
            return "<p>Aucune alerte générée - Système sain ✅</p>"
        
        html = ""
        for alert in self.alerts:
            severity_class = "high" if alert['severity'] == "HIGH" else "medium"
            html += f"""
            <div class="alert-item {severity_class}">
                <div class="alert-header">[{alert['severity']}] Alerte de Sécurité</div>
                <div>{alert['message']}</div>
                <div style="margin-top: 10px; font-size: 0.9em; color: #666;">
                    Détecté le : {alert['timestamp']}
                </div>
            </div>
"""
        return html
    
    def run_analysis(self):
        """Exécute l'analyse complète"""
        self.banner()
        
        # Analyse des logs
        self.analyze_logs()
        
        # Détections
        self.detect_brute_force()
        self.identify_suspicious_ips()
        self.analyze_targeted_users()
        self.check_successful_after_failed()
        
        # Statistiques
        self.generate_statistics()
        
        # Visualisations
        self.create_visualizations()
        
        # Rapport
        self.generate_report()

def main():
    print(Fore.CYAN + Style.BRIGHT + """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        📊 ANALYSEUR DE LOGS DE SÉCURITÉ 📊               ║
    ║                                                           ║
    ║        Auteur : Valérie Ename                            ║
    ║        Formation : Bachelor AIS - Cybersécurité           ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Demander le fichier de logs
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = input(Fore.CYAN + "📁 Entrez le chemin du fichier de logs (ou appuyez sur Entrée pour 'auth.log') : ").strip()
        if not log_file:
            log_file = "auth.log"
    
    print()
    
    # Créer et lancer l'analyseur
    analyzer = LogAnalyzer(log_file)
    analyzer.run_analysis()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n\n[!] Analyse interrompue par l'utilisateur")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"\n[✗] Erreur fatale : {e}")
        sys.exit(1)