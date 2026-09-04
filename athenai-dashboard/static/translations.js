/* AthenAI — i18n centralizado  */
(function () {
  var LANG_KEY = 'athenai_lang';

  window.TRANSLATIONS = {
    es: {
      /* ── común ── */
      'lang.toggle': 'EN',

      /* ── login ── */
      'login.subtitle':          'Panel de Inteligencia de Seguridad',
      'login.username':          'Usuario',
      'login.username.ph':       'Ingresa tu usuario',
      'login.password':          'Contraseña',
      'login.password.ph':       'Ingresa tu contraseña',
      'login.submit':            'Iniciar sesión',
      'login.submit.loading':    'Iniciando sesión',
      'login.submit.success':    '✓ ¡Éxito!',
      'login.error.credentials': 'Credenciales incorrectas. Inténtalo de nuevo.',
      'login.error.connection':  'Error de conexión. Verifica que el servidor esté activo.',

      /* ── landing ── */
      'landing.accuracy':        'Exactitud',
      'landing.f1score':         'Puntuación F1',
      'landing.precision':       'Precisión',
      'landing.recall':          'Recuperación',
      'landing.aucroc':          'AUC-ROC',
      'landing.accuracy.chip':   '99.96% Exactitud',
      'landing.access':          'Acceder al sistema',
      'landing.see.arch':        'Ver arquitectura',

      /* ── dashboard ── */
      'status.online':           'En línea',
      'status.offline':          'Fuera de línea',
      'status.loading':          'cargando',

      /* ── panel amenazas ── */
      'threats.title':           'Panel de Amenazas',

      /* ── system health ── */
      'health.title':            'Salud del Sistema',
      'health.subtitle':         'Métricas de infraestructura en tiempo real',
      'health.autorefresh':      'Auto-actualización: 5s',
      'health.cpu':              'Uso de CPU',
      'health.cpu.cores':        'núcleos',
      'health.memory':           'Memoria',
      'health.disk':             'Espacio en Disco',
      'health.disk.free':        'GB libres',
      'health.hitrate':          'Tasa de acierto:',
      'health.clients':          'Clientes:',
      'health.memory.lbl':       'Memoria:',
      'health.tables':           'Tablas:',
      'health.status':           'Estado:',
      'health.buckets':          'Buckets:',
      'health.uptime':           'Tiempo activo:',
      'health.reqmin':           'Req/min:',
      'health.latency':          'Latencia media:',

      /* ── gestión IPs ── */
      'ip.total_blocked':        'Total Bloqueadas',
      'ip.all_time':             'Total histórico',
      'ip.blocked_today':        'Bloqueadas hoy',
      'ip.auto_blocked_kpi':     'Auto-bloqueadas',
      'ip.by_detector':          'Por detector de amenazas',
      'ip.whitelisted':          'Lista blanca',
      'ip.trusted':              'IPs de confianza',
      'ip.section_blocked':      'IPs Bloqueadas',
      'ip.search':               'Buscar IP o motivo...',
      'ip.filter.all':           'Todos los bloqueos',
      'ip.filter.auto':          'Auto-bloqueadas',
      'ip.filter.manual':        'Manuales',
      'ip.filter.permanent':     'Permanentes',
      'ip.col.address':          'Dirección IP',
      'ip.col.threat':           'Tipo de Amenaza',
      'ip.filter.threat_type':   'Tipo de Amenaza',
      'ip.col.reason':           'Motivo',
      'ip.col.blocked_at':       'Bloqueada el',
      'ip.col.source':           'Origen',
      'ip.col.ttl':              'TTL',
      'ip.col.actions':          'Acciones',
      'ip.type.auto':            'Auto',
      'ip.type.manual':          'Manual',
      'ip.type.permanent':       'Permanente',
      'ip.type.expired':         'Expirada',
      'ip.unblock':              'Desbloquear',
      'ip.read_only':            'Solo lectura',
      'ip.no_match':             'Ninguna IP bloqueada coincide con el filtro.',
      'ip.whitelist_title':      'Lista Blanca',
      'ip.remove':               'Eliminar',
      'ip.last24h':              'Últimas 24 horas',
    },

    en: {
      /* ── common ── */
      'lang.toggle': 'ES',

      /* ── login ── */
      'login.subtitle':          'Security Intelligence Dashboard',
      'login.username':          'Username',
      'login.username.ph':       'Enter your username',
      'login.password':          'Password',
      'login.password.ph':       'Enter your password',
      'login.submit':            'Sign In',
      'login.submit.loading':    'Signing In',
      'login.submit.success':    '✓ Success!',
      'login.error.credentials': 'Invalid credentials. Please try again.',
      'login.error.connection':  'Connection error. Please check the server.',

      /* ── landing ── */
      'landing.accuracy':        'Accuracy',
      'landing.f1score':         'F1-Score',
      'landing.precision':       'Precision',
      'landing.recall':          'Recall',
      'landing.aucroc':          'AUC-ROC',
      'landing.accuracy.chip':   '99.96% Accuracy',
      'landing.access':          'Access the system',
      'landing.see.arch':        'See architecture',

      /* ── dashboard ── */
      'status.online':           'Online',
      'status.offline':          'Offline',
      'status.loading':          'loading',

      /* ── threats panel ── */
      'threats.title':           'Threat Dashboard',

      /* ── system health ── */
      'health.title':            'System Health',
      'health.subtitle':         'Real-time infrastructure metrics',
      'health.autorefresh':      'Auto-refresh: 5s',
      'health.cpu':              'CPU Usage',
      'health.cpu.cores':        'cores',
      'health.memory':           'Memory',
      'health.disk':             'Disk Space',
      'health.disk.free':        'GB free',
      'health.hitrate':          'Hit Rate:',
      'health.clients':          'Clients:',
      'health.memory.lbl':       'Memory:',
      'health.tables':           'Tables:',
      'health.status':           'Status:',
      'health.buckets':          'Buckets:',
      'health.uptime':           'Uptime:',
      'health.reqmin':           'Req/min:',
      'health.latency':          'Avg Latency:',

      /* ── IP management ── */
      'ip.total_blocked':        'Total Blocked',
      'ip.all_time':             'All time',
      'ip.blocked_today':        'Blocked Today',
      'ip.auto_blocked_kpi':     'Auto Blocked',
      'ip.by_detector':          'By threat detector',
      'ip.whitelisted':          'Whitelisted',
      'ip.trusted':              'Trusted IPs',
      'ip.section_blocked':      'Blocked IPs',
      'ip.search':               'Search IP or reason...',
      'ip.filter.all':           'All Blocks',
      'ip.filter.auto':          'Auto Blocked',
      'ip.filter.manual':        'Manual Blocks',
      'ip.filter.permanent':     'Permanent',
      'ip.col.address':          'IP Address',
      'ip.col.threat':           'Threat Type',
      'ip.filter.threat_type':   'Threat Type',
      'ip.col.reason':           'Reason',
      'ip.col.blocked_at':       'Blocked At',
      'ip.col.source':           'Source',
      'ip.col.ttl':              'TTL',
      'ip.col.actions':          'Actions',
      'ip.type.auto':            'Auto',
      'ip.type.manual':          'Manual',
      'ip.type.permanent':       'Permanent',
      'ip.type.expired':         'Expired',
      'ip.unblock':              'Unblock',
      'ip.read_only':            'Read only',
      'ip.no_match':             'No blocked IPs match the current filter.',
      'ip.whitelist_title':      'Whitelist',
      'ip.remove':               'Remove',
      'ip.last24h':              'Last 24 hours',
    }
  };

  window.i18n = {
    lang: localStorage.getItem(LANG_KEY) || 'es',

    t: function (key) {
      var dict = window.TRANSLATIONS[this.lang] || window.TRANSLATIONS['es'];
      var fallback = window.TRANSLATIONS['es'];
      var val = dict[key];
      if (val === undefined) val = fallback[key];
      return (typeof val === 'string') ? val : key;
    },

    setLang: function (newLang) {
      this.lang = newLang;
      localStorage.setItem(LANG_KEY, newLang);
      document.documentElement.setAttribute('lang', newLang);
      this._applyDOM();
      if (typeof window.__i18nReactUpdate === 'function') {
        window.__i18nReactUpdate(newLang);
      }
    },

    /* Actualiza elementos con data-i18n en páginas no-React */
    _applyDOM: function () {
      var self = this;
      document.querySelectorAll('[data-i18n]').forEach(function (el) {
        el.textContent = self.t(el.getAttribute('data-i18n'));
      });
      document.querySelectorAll('[data-i18n-ph]').forEach(function (el) {
        el.placeholder = self.t(el.getAttribute('data-i18n-ph'));
      });
      document.querySelectorAll('[data-i18n-title]').forEach(function (el) {
        el.title = self.t(el.getAttribute('data-i18n-title'));
      });
    }
  };

  document.documentElement.setAttribute('lang', window.i18n.lang);
})();
