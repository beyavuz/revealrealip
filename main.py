"""

scope'da domainler ve subdomainler var diyelim.
Önce verilen domainlerin gerçekten cloudflare'e ait olduğunu bulalım.
Cloudflare'e ait olmayanları önce ele.
Cloudflare'e ait olanları bulduktan sonra, başka bir dosyaya ilgili target'a ait olabilecek ip'leri veya ip bloğunu girelim.
ondan sonra kartezyen çarpım gibi bir bağlantı yaparız.

Peki bir domainin gerçekten verilen ip'den sunulduğunu nerden anlayacağız.
Bir şeyleri kaydedip onları daha sonra ip ile gittiğimizde check etmemiz lazım.

Önce verilen domainlere gidiyoruz ondan sonra response'u aynen alıyoruz, headerları aynen alıyoruz, sunulan sertifikayı aynen alıyoruz(özellikle sha'sını). 
Bunları kaydediyoruz ondan sonra ip ile gidip aynılarını alıyoruz ve bunları karşılaştıyoruz.

TODO ASN number verildiği zaman mesela ripe'e sorgu atıp, oradan ip listesini de çekebiliriz.
TODO https ve http olabilir yani illa tls olucak diye bir koşulumuz yok.
"""

import ipaddress
import argparse
import dns.resolver
import requests
import ssl
import socket
import json
from datetime import datetime
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


# /etc/hosts' a tek tek yazmak yerine burada nereye çözümleneceğini seçebiliriz.
class HostNameAdapter(HTTPAdapter):
    def __init__(self, host_ip_map, *args, **kwargs):
        super(HostNameAdapter, self).__init__(*args, **kwargs)
        self.host_ip_map = host_ip_map

    def send(self, request, **kwargs):
        request.url = self.host_ip_map.get(request.url, request.url)
        return super(HostNameAdapter, self).send(request, **kwargs)


def get_subject_info(cert_der):
    cert = x509.load_der_x509_certificate(cert_der, default_backend())

    # Subject DN
    subject_dn = cert.subject.rfc4514_string()

    # Subject CN
    try:
        subject_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except IndexError:
        subject_cn = None

    # Subject Alternative Names
    try:
        ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        subject_an = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        subject_an = []

    return {
        "subject_dn": subject_dn,
        "subject_cn": subject_cn,
        "subject_an": subject_an
    }

def get_certificate_hashes(certificate):
    sha256_result = hashlib.sha256(certificate).hexdigest()
    md5_result = hashlib.md5(certificate).hexdigest()
    return {"sha256":sha256_result, "md5": md5_result}


def format_name(rdn_sequence):
    # RDN (Relative Distinguished Name) dizisini düzgün bir sözlüğe dönüştür
    return dict(x[0] for x in rdn_sequence)

def format_certificate(certificate, cert_bin):
    # Sertifika bilgilerini anlaşılır bir formata çevir
    extra_subjects = get_subject_info(cert_bin)
    formatted = {
        "subject": format_name(certificate["subject"]),
        "issuer": format_name(certificate["issuer"]),
        "version": certificate["version"],
        "serialNumber": certificate["serialNumber"],
        "notBefore": certificate["notBefore"],
        "notAfter": certificate["notAfter"],
        "sha256": get_certificate_hashes(cert_bin),
        "subject_dn": extra_subjects['subject_dn'],
        "subject_cn": extra_subjects['subject_cn'],
        "subject_an": extra_subjects['subject_an']
    }
    return formatted

def get_ssl_certificate(host, port=443):
    context = ssl.create_default_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            certificate = ssock.getpeercert()
            cert_bin = ssock.getpeercert(binary_form=True)

    return format_certificate(certificate, cert_bin)


def check_there_is_any_scheme(domain:str):
    return domain.startswith('http://') or domain.startswith('https://')

def first_visit_of_a_domain(domains):
    original_data_dict = {} #domainlerin bilgileri burada tutulcak.
    for domain in domains:
        # önce get isteği atalım ve hem response'u hem header'ları hem de response'un string halini tutalım.
        # hakoriginfinder'a bir bak.
        if check_there_is_any_scheme(domain):
            print("The domain has schema..., next...")
            continue
        original_data_dict[domain] = {}
        
        # http git
        try:
            ress = requests.get('http://' + domain)
        except Exception as exc:
            ress = None
        finally:
            if not ress is None:
                original_data_dict[domain]['http'] = {
                    #'content':ress.content.decode(),
                    'size': len(ress.content.decode()),
                    'hash_str':''
                    }
            else:
                original_data_dict[domain]['http'] = None
                
        
        # https git
        try:
            ress_ssl = requests.get('https://' + domain, verify=False)
        except Exception as exc:
            ress_ssl = None
        finally:
            if not ress_ssl is None:
                original_data_dict[domain]['https'] = {
                    #'content': ress.content.decode(),
                    'size': len(ress.content.decode()),
                    'hash_str': ''
                }
            else:
                original_data_dict[domain]['https'] = None
        
        # ssl git, ssl sertifikasını da çek.
        try:
            ssl_data = get_ssl_certificate(domain)
        except Exception as exc:
            ssl_data = None
        finally:
            original_data_dict[domain]['ssl'] = ssl_data

    
    return original_data_dict
        
    

def visit_with_domain_get_size(domain):
    """
        Domain ve ip ile gidip dönen response size'lanı
    """
    requests.get(domain)

def get_cloudflare_ips():
    # https://api.cloudflare.com/client/v4/ips => return JSON
    # https://www.cloudflare.com/ips-v4/#  => return text
    url = "https://api.cloudflare.com/client/v4/ips"
    response = requests.get('url').json()
    if 'result' in response and 'ipv4_cidrs' in response['result']:
        return response['result']['ipv4_cidrs']
    else:
        return None
    

def get_a_record_of_a_domain(fqdn:str):
    """
    Verilen fqdn'nin DNS A kayıtlarını döndürür.
    """
    records_list = []
    try:
        records = dns.resolver.resolve(fqdn,'A')
        for item in records:
            records_list.append(item.to_text())
    except Exception as exc:
        pass
    return records_list


def read_domains_from_file(filename):
    domains = []
    with open(filename, 'r') as f:
        for line in f:
            domains.append(line.strip())


def read_ips_from_file(filename):
    ips = []
    error_line = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if '/' in line:
                # cidr notasyonu var.
                try:
                    network = ipaddress.ip_network(line)
                except ValueError as exc:
                    error_line.append(line)
                else:
                    for ip in network:
                        ips.append(ip)
    return ips


def is_ip_in_network(ip:str, network_list:list):
    """
        verilen ip adresinin belirtilen network içerisinde olup olmadığını söyler.
    """
    ip_addr = ipaddress.ip_address(ip)
    for network in network_list:
        network_obj = ipaddress.ip_network(network)
        if ip_addr in network_obj:
            return True
    return False



def check_domains_if_is_in_cloudflare(domains):
    """
        Domainlerin cloudflare arkasında olup olmadığını kontrol eden yapı.
    """
    domains_in_cloudflare = []
    cloudflare_ip_blocks = get_cloudflare_ips()
    if cloudflare_ip_blocks is None:
        return False
    for domain in domains:
        # get DSN A record of a domain
        record_of_given_item = get_a_record_of_a_domain(domain)
        if len(record_of_given_item) > 0:
            for record_item in record_of_given_item:
                # is this a record in cloudflare blocks
                if is_ip_in_network(record_item,cloudflare_ip_blocks):
                    domains_in_cloudflare.append(domain)
    return domains_in_cloudflare
            

# TODO
def check_fqdn_tls_using_tlsx(fqdn):
    """
        tlsx ile
    """
    """
    echo "blog.papara.com" | tlsx -cn -san -json | jq
    echo "swordsec.com" | tlsx -cn -san -json | jq
    echo "blog.papara.com" | tlsx -cn
    """

    parameters = ""

def domains_datas_save(domains):
    dict_domains = {'result':{}}
    for domain in domains:
        # Bu domain ile ilgili response'u, response size'ı, ssl sertifikası gibi dataları storelayalım.
        
        dict_domains


def main(ip_filename, domain_filename):

    #cloudflare arkasındaki domainleri aldık.
    check_domains_if_is_in_cloudflare()

    #şimdi bunları ssl sertifikalarından hash'leri ve common name'leri çekmeliyiz.

    domains_that_will_be_check = []


# debug için release olunca sil.
def dosyaya_yaz(data):
    with open('result.json','w') as ff:
        json.dump(data,ff)



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Argparse Kullanım Örneği")
    parser.add_argument("--ips", help="ip listesi", required=True)
    parser.add_argument("--domains", required=True)
    parser.add_argument("--cloudflare_list")
    args = parser.parse_args()
    """
    print("Args => ",args.ips)
    print("Args => ",args.domains)

    main(
        ip_filename = args.ips,
        domain_filename = args.domains
    )
    """

    # print(get_ssl_certificate('blog.papara.com'))

    dosyaya_yaz(
        first_visit_of_a_domain(['swordsec.com','papara.com'])
    )
    

