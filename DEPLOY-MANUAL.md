# Déploiement Manuel Requis — lumen-push Worker

**Date:** 2026-05-16  
**Raison:** Token API manque de permissions pour déploiement

---

## ✅ Code Prêt

- TypeScript compile : ✓ (`npx tsc --noEmit`)
- Dry-run passe : ✓ (`wrangler deploy --dry-run`)
- Classification intégrée : ✓ (classifier.ts + index.ts)
- Taille bundle : 31.74 KiB / gzip: 9.15 KiB

---

## ❌ Déploiement Bloqué

**Erreur:** `Authentication error [code: 10000]`

**Cause:** Token API `CLOUDFLARE_API_TOKEN` dans environnement manque de permissions Workers Scripts:Write

---

## 🔧 Solution (2 options)

### Option A: Login interactif (recommandé)
```bash
cd ~/GitHub/lumen-push

# Login interactif (ouvre navigateur)
wrangler login

# Deploy
wrangler deploy

# Expected:
# ✨ Deployed lumen-push to production
#   https://lumen-push.mail5491.workers.dev
```

### Option B: Nouveau token API
1. Aller sur https://dash.cloudflare.com/profile/api-tokens
2. Create Token → Custom Token
3. Permissions:
   - Account → Workers Scripts → Edit
   - Account → Workers KV Storage → Edit
   - Account → Account Analytics → Read
4. Account Resources: Include → Specific account → (votre compte)
5. Continue → Create Token
6. Copier le token
7. ```bash
   export CLOUDFLARE_API_TOKEN="nouveau-token"
   cd ~/GitHub/lumen-push
   wrangler deploy
   ```

---

## 📝 Après Déploiement

### 1. Vérifier le déploiement
```bash
# Test endpoint
curl -X POST https://lumen-push.mail5491.workers.dev/v1/notify/{secret}/{token} \
  -H "Content-Type: application/json" \
  -d '{
    "type":"new",
    "after":{
      "id":"test.123",
      "camera":"front_door",
      "label":"person",
      "top_score":0.9,
      "zones":["porch"],
      "has_snapshot":true,
      "has_clip":true,
      "start_time":1715875200,
      "end_time":null,
      "stationary":true
    }
  }'

# Expected: 200 OK
```

### 2. Vérifier les logs
```bash
wrangler tail

# Attendre un événement Frigate réel
# Chercher: [LOG] Classification: {"class":"...","severity":...}
```

### 3. Test avec événement réel
1. Déclencher détection Frigate (marcher devant caméra)
2. Vérifier logs Worker : classification visible ?
3. Vérifier notification iOS : rendu bilingue ?

---

## 🎯 Classification Attendue

**Exemples de sortie :**

```json
// Personne qui s'approche (<20s, moving)
{
  "class": "personApproaching",
  "severity": 4,
  "confidence": 0.92,
  "context_flags": ["high_confidence"],
  "suggested_actions": ["view_live"]
}

// Personne immobile (>60s, stationary)
{
  "class": "personLoitering",
  "severity": 5,
  "confidence": 0.87,
  "context_flags": ["stationary_long", "high_confidence"],
  "suggested_actions": ["notify_immediately", "view_live", "two_way_audio"]
}

// Colis livré (stationary package)
{
  "class": "packageDelivered",
  "severity": 4,
  "confidence": 0.95,
  "context_flags": ["object_left", "high_confidence"],
  "suggested_actions": ["view_snapshot"]
}

// Véhicule de passage (<15s)
{
  "class": "vehiclePassing",
  "severity": 1,
  "confidence": 0.81,
  "context_flags": [],
  "suggested_actions": []
}
```

---

## 📲 Rendu iOS Attendu

### Français (locale FR)
- `personApproaching` → "👤 Personne s'approche de porte d'entrée"
- `personLoitering` → "⚠️ Personne immobile à porte d'entrée depuis 45 secondes" (critical)
- `packageDelivered` → "📦 Colis livré à porte d'entrée"
- `vehiclePassing` → "🚗 Véhicule de passage à porte d'entrée"

### English (locale EN)
- `personApproaching` → "👤 Person approaching front door"
- `personLoitering` → "⚠️ Person loitering at front door for 45 seconds" (critical)
- `packageDelivered` → "📦 Package delivered at front door"
- `vehiclePassing` → "🚗 Vehicle passing front door"

**Niveaux sonores:**
- Severity 5 → Critical alert (bypass DND)
- Severity 4 → Time-sensitive (high priority)
- Severity 3 → Active (default)
- Severity 1-2 → Passive (low priority)

---

## ✅ Une Fois Déployé

Cocher dans `DEPLOYMENT-CHECKLIST.md` :
- [x] Worker deployed to production
- [ ] TestFlight build uploaded
- [ ] Real Frigate event tested
- [ ] Bilingual rendering verified

---

**Le code est prêt. Juste besoin de `wrangler login` pour déployer.**
