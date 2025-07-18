import dns.resolver

def resolve_dns(domain):
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    results = {}

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = []

            for record in answers:
                records.append(record.to_text())

            results[rtype] = records

        except Exception:
            results[rtype] = []

    print(results)

resolve_dns(domain="google.com")