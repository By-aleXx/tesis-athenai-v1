    
    def _update_traffic_stats(self, ip):
        """Actualiza estadísticas de tráfico para una IP"""
        import time
        
        if ip not in self.traffic_stats:
            self.traffic_stats[ip] = {
                'request_count': 0,
                'error_count': 0,
                'response_times': [],
                'first_seen': time.time(),
                'last_seen': time.time()
            }
        
        stats = self.traffic_stats[ip]
        stats['request_count'] += 1
        stats['last_seen'] = time.time()
        
        # Limpiar stats viejos (más de 5 minutos)
        window = 300  # 5 minutos
        if time.time() - stats['first_seen'] > window:
            # Reset stats
            self.traffic_stats[ip] = {
                'request_count': 1,
                'error_count': 0,
                'response_times': [],
                'first_seen': time.time(),
                'last_seen': time.time()
            }
    
    def _get_traffic_features(self, ip):
        """
        Obtiene features de tráfico para ML.
        
        Returns:
            [request_count, error_rate, avg_response_time, unique_ips]
        """
        if ip not in self.traffic_stats:
            return None
        
        stats = self.traffic_stats[ip]
        
        request_count = stats['request_count']
        error_count = stats.get('error_count', 0)
        error_rate = error_count / request_count if request_count > 0 else 0.0
        
        response_times = stats.get('response_times', [])
        avg_response_time = sum(response_times) / len(response_times) if response_times else 100
        
        # unique_ips siempre es 1 para este contexto (estamos analizando una IP)
        unique_ips = 1
        
        return [request_count, error_rate, avg_response_time, unique_ips]
    
    def record_response(self, ip, status_code, response_time):
        """
        Registra la respuesta de una request para tracking.
        Debe ser llamado después de cada request.
        """
        if ip in self.traffic_stats:
            stats = self.traffic_stats[ip]
            
            # Registrar error si status >= 400
            if status_code >= 400:
                stats['error_count'] = stats.get('error_count', 0) + 1
            
            # Registrar response time
            if 'response_times' not in stats:
                stats['response_times'] = []
            stats['response_times'].append(response_time)
            
            # Mantener solo los últimos 100 response times
            if len(stats['response_times']) > 100:
                stats['response_times'] = stats['response_times'][-100:]
