import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from backend.app.database import IPState, SecurityAlert

logger = logging.getLogger("SOC-Correlation")

# Severity Weight configuration
SEVERITY_WEIGHTS = {
    "CRITICAL": 5.0,
    "HIGH": 4.0,
    "MEDIUM": 2.0,
    "LOW": 1.0,
    "INFO": 0.0
}

class CorrelationEngine:
    def correlate_event(self, db: Session, ip: str, source: str, label: str, severity: str, base_score: int) -> tuple[float, bool]:
        """
        Correlates a security event for an IP address.
        Updates IP dynamic state in database.
        
        Returns:
            (dynamic_risk_score: float, should_escalate: bool)
        """
        try:
            # 1. Fetch or create IPState
            ip_state = db.query(IPState).filter(IPState.ip == ip).first()
            if not ip_state:
                ip_state = IPState(
                    ip=ip,
                    risk_score=0.0,
                    attack_history=[],
                    event_count=0,
                    last_seen=datetime.utcnow()
                )
                db.add(ip_state)

            # 2. Append event to history
            history = list(ip_state.attack_history)
            new_event = {
                "timestamp": datetime.utcnow().isoformat(),
                "source": source,
                "label": label,
                "severity": severity,
                "score": base_score
            }
            history.append(new_event)
            
            # Prune history to last 50 events to avoid unbounded DB growth
            if len(history) > 50:
                history = history[-50:]
                
            ip_state.attack_history = history
            ip_state.event_count += 1
            ip_state.last_seen = datetime.utcnow()

            # 3. Dynamic Risk Score Calculation
            # Base accumulation = sum of weights of events in the history window
            # Limit the window to the last 1 hour of active history
            one_hour_ago = datetime.utcnow() - timedelta(hours=1)
            active_events = []
            for ev in history:
                try:
                    ev_time = datetime.fromisoformat(ev["timestamp"])
                    if ev_time >= one_hour_ago:
                        active_events.append(ev)
                except Exception:
                    active_events.append(ev) # Keep if parsing fails

            # Accumulate severity weights of recent events
            accumulated_severity = sum(SEVERITY_WEIGHTS.get(ev["severity"], 1.0) for ev in active_events)
            
            # Multi-Source Trigger Correlation
            unique_sources = {ev["source"] for ev in active_events}
            num_sources = len(unique_sources)
            
            # Dynamic Score formula:
            # Risk = Base Score of the latest alert + Accumulated weights + Multi-Source Correlation Factor
            dynamic_score = float(base_score) + accumulated_severity
            
            if num_sources >= 2:
                # Attack chains spanning multiple sources get boosted
                correlation_multiplier = num_sources * 3.0
                dynamic_score += correlation_multiplier
                logger.info(f"[CORRELATION BOOST] Attacker IP {ip} triggers {num_sources} sources! Added +{correlation_multiplier} reputation penalty.")

            # Limit dynamic score between 0.0 and 100.0
            ip_state.risk_score = float(max(0.0, min(100.0, dynamic_score)))
            
            # 4. Determine L2 Escalation
            # Escalation thresholds:
            # - Dynamic risk score >= 15
            # - More than 3 unique attack events in last hour
            should_escalate = (ip_state.risk_score >= 15.0) or (len(active_events) >= 5)
            
            db.commit()
            db.refresh(ip_state)
            
            return ip_state.risk_score, should_escalate

        except Exception as e:
            logger.error(f"Error correlating event for IP {ip}: {e}")
            db.rollback()
            return float(base_score), False

# Export a single global instance
correlation_engine = CorrelationEngine()
