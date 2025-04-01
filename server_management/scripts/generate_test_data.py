import os
import sys
# Add the parent directory to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from models import db, Machine
from config import Config
import random
from faker import Faker

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
fake = Faker()

def generate_test_machines():
    os_types = ['Linux', 'Windows', 'Mac']
    linux_distros = ['Ubuntu 22.04', 'CentOS 7', 'Debian 11', 'RedHat 8', 'Fedora 38']
    windows_versions = ['Windows 10 Pro', 'Windows 11 Enterprise', 'Windows Server 2019', 'Windows Server 2022']
    mac_versions = ['macOS Ventura', 'macOS Monterey', 'macOS Big Sur']
    
    cpu_models = ['Intel Core i5', 'Intel Core i7', 'Intel Core i9', 'AMD Ryzen 5', 'AMD Ryzen 7', 'AMD Ryzen 9']
    ram_sizes = ['8GB', '16GB', '32GB', '64GB', '128GB']
    
    cloud_providers = [
        'aws.amazon.com',
        'cloud.google.com',
        'azure.microsoft.com',
        'digitalocean.com',
        'linode.com'
    ]

    with app.app_context():
        for i in range(100):
            os_type = random.choice(os_types)
            
            if os_type == 'Linux':
                installed_os = random.choice(linux_distros)
            elif os_type == 'Windows':
                installed_os = random.choice(windows_versions)
            else:
                installed_os = random.choice(mac_versions)
            
            hostname = f"{fake.word()}-{os_type.lower()}-{str(i+1).zfill(3)}"
            username = fake.user_name()
            cpu = f"{random.choice(cpu_models)} {random.randint(4, 16)} Cores"
            ram = random.choice(ram_sizes)
            
            private_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            public_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            provider = random.choice(cloud_providers)
            cloud_url = f"https://{provider}/instance/{fake.uuid4()}"
            
            vnc_port = random.randint(5900, 5999) if random.random() > 0.3 else None
            ssh_port = random.randint(22000, 22999) if random.random() > 0.3 else None
            outside_accessible = random.choice([True, False])
            
            remarks = fake.sentence() if random.random() > 0.5 else None
            
            machine = Machine(
                hostname=hostname,
                username=username,
                os_type=os_type,
                installed_os=installed_os,
                cpu_details=cpu,
                ram_details=ram,
                private_ip=private_ip,
                public_ip=public_ip,
                cloud_provider_url=cloud_url,
                vnc_port=vnc_port,
                ssh_port=ssh_port,
                outside_accessible=outside_accessible,
                remarks=remarks
            )
            
            db.session.add(machine)
            
        db.session.commit()
        print("Successfully generated 100 test machines!")

if __name__ == '__main__':
    generate_test_machines()
