from database import get_traffic_logs

logs = get_traffic_logs(limit=10000, offset=0)
print(f'\n📊 ESTADO ACTUAL DE TRAFFIC_LOGS.DB\n')
print(f'Total logs en BD: {len(logs)}')

if logs:
    localhost = sum(1 for log in logs if log.source_ip == '127.0.0.1')
    externos = len(logs) - localhost
    
    print(f'Localhost (127.0.0.1): {localhost} ({localhost/len(logs)*100:.1f}%)')
    print(f'Externos: {externos} ({externos/len(logs)*100:.1f}%)')
    
    if externos > 0:
        ips_ext = {}
        for log in logs:
            if log.source_ip != '127.0.0.1':
                ips_ext[log.source_ip] = ips_ext.get(log.source_ip, 0) + 1
        
        print(f'\n🌐 Top 5 IPs externas:')
        for ip, count in sorted(ips_ext.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f'  {ip}: {count} requests')
    else:
        print('\n⚠️  NO HAY LOGS EXTERNOS - Solo hay tráfico de localhost')
else:
    print('⚠️  LA BASE DE DATOS ESTÁ VACÍA')
