"""
Test de caché del AI Engine
"""
import time
import sys
sys.path.insert(0, 'c:\\Users\\jcond\\OneDrive\\Escritorio\\prubas AthenAI\\athenai-dashboard')

from ai_engine import AIEngine

print("\n" + "="*60)
print("🧪 TEST DE CACHÉ DEL AI ENGINE")
print("="*60 + "\n")

# Inicializar AI Engine
print("🧠 Inicializando AI Engine...")
brain = AIEngine()
print("✅ AI Engine inicializado\n")

# Payloads de prueba
payloads = [
    "' OR 1=1--",  # SQL Injection
    "<script>alert('XSS')</script>",  # XSS
    "../../etc/passwd",  # Path Traversal
    "normal request to /api/users",  # Normal
    "' OR 1=1--",  # Repetir primer payload (debería estar en caché)
]

print("="*60)
print(f"📊 FASE 1: Primera predicción de cada payload (caché MISS)")
print("="*60 + "\n")

times_first = []
results_first = []

for i, payload in enumerate(payloads[:4], 1):
    print(f"Request {i}: {payload[:50]}...")
    start = time.time()
    label, confidence = brain.predict(payload)
    elapsed = (time.time() - start) * 1000
    times_first.append(elapsed)
    results_first.append((label, confidence))
    
    color = '\033[92m' if elapsed < 100 else '\033[93m' if elapsed < 300 else '\033[91m'
    reset = '\033[0m'
    print(f"  └─ Resultado: {label} ({confidence:.2%}) - {color}{elapsed:.0f}ms{reset}\n")

print("="*60)
print(f"📊 FASE 2: Predicciones repetidas (caché HIT esperado)")
print("="*60 + "\n")

times_cache = []
results_cache = []

# Repetir los primeros 4 payloads
for i, payload in enumerate(payloads[:4], 1):
    print(f"Request {i}: {payload[:50]}...")
    start = time.time()
    label, confidence = brain.predict(payload)
    elapsed = (time.time() - start) * 1000
    times_cache.append(elapsed)
    results_cache.append((label, confidence))
    
    color = '\033[92m' if elapsed < 100 else '\033[93m' if elapsed < 300 else '\033[91m'
    reset = '\033[0m'
    print(f"  └─ Resultado: {label} ({confidence:.2%}) - {color}{elapsed:.0f}ms{reset}\n")

# Estadísticas del caché
print("="*60)
print("📈 ESTADÍSTICAS DEL CACHÉ")
print("="*60 + "\n")

cache_stats = brain.cache_stats
cache_size = len(brain.prediction_cache)

print(f"Cache Hits:   {cache_stats['hits']}")
print(f"Cache Misses: {cache_stats['misses']}")
hit_rate = (cache_stats['hits'] / max(1, cache_stats['hits'] + cache_stats['misses'])) * 100
print(f"Hit Rate:     {hit_rate:.1f}%")
print(f"Cache Size:   {cache_size} entradas\n")

# Comparación de tiempos
avg_first = sum(times_first) / len(times_first)
avg_cache = sum(times_cache) / len(times_cache)
speedup = avg_first / avg_cache

print("="*60)
print("⚡ COMPARACIÓN DE RENDIMIENTO")
print("="*60 + "\n")

print(f"Promedio sin caché: {avg_first:.0f}ms")
print(f"Promedio con caché: {avg_cache:.0f}ms")
print(f"Aceleración:        {speedup:.1f}x más rápido\n")

# Verificar consistencia de resultados
print("="*60)
print("✓ VERIFICACIÓN DE CONSISTENCIA")
print("="*60 + "\n")

all_consistent = True
for i in range(len(results_first)):
    consistent = results_first[i] == results_cache[i]
    status = "✅" if consistent else "❌"
    print(f"{status} Payload {i+1}: {consistent}")
    if not consistent:
        all_consistent = False
        print(f"   Primera: {results_first[i]}")
        print(f"   Caché:   {results_cache[i]}")

print()

# Resultado final
print("="*60)
if avg_cache < 100 and hit_rate >= 50 and all_consistent:
    print("✅ CACHÉ FUNCIONANDO PERFECTAMENTE!")
elif avg_cache < 300 and hit_rate >= 25:
    print("⚠️  CACHÉ PARCIALMENTE FUNCIONAL")
else:
    print("❌ CACHÉ NO FUNCIONANDO CORRECTAMENTE")
print("="*60 + "\n")
