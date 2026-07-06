from loguru import logger

class ConfidenceEstimator:
    """
    Tracks the viability of a given execution sequence.
    Reduces confidence based on tool outputs automatically.
    """
    def __init__(self, initial_confidence: int = 100, threshold: int = 30):
        self.confidence_score = initial_confidence
        self.threshold = threshold
        self.history = []

    def evaluate_outcome(self, tool_name: str, output: str, is_error: bool) -> int:
        """
        Evaluate tool output and apply a confidence penalty or reward.
        Returns the new confidence score.
        """
        penalty = 0
        reward = 0
        output_lower = output.lower()
        
        if is_error:
            penalty += 5
        
        # Severe blockers
        if any(term in output_lower for term in ["waf", "blocked", "403 forbidden", "access denied", "environment_blocked"]):
            penalty += 50
            
        # Dead ends
        elif any(term in output_lower for term in ["0 vulnerabilities found", "not vulnerable", "no open ports", "no results"]):
            penalty += 40
            
        if penalty > 0:
            self.confidence_score -= penalty
            self.history.append({"tool": tool_name, "penalty": penalty, "new_score": self.confidence_score})
            logger.debug(f"Confidence Estimator penalty applied: -{penalty} (new score: {self.confidence_score})")
        else:
            # Positive indicators (rewards)
            if any(term in output_lower for term in ["vulnera", "exploit", "password", "hash", "flag", "uid=0", "administrator"]):
                reward += 20
            elif not is_error:
                # Normal successful command progress
                reward += 5
                
            if reward > 0:
                old_score = self.confidence_score
                self.confidence_score = min(100, self.confidence_score + reward)
                self.history.append({"tool": tool_name, "reward": reward, "new_score": self.confidence_score})
                logger.debug(f"Confidence Estimator reward applied: +{reward} (old score: {old_score}, new score: {self.confidence_score})")
            
        return self.confidence_score

    def is_viable(self) -> bool:
        """
        Returns True if the current vector is still considered viable.
        """
        return self.confidence_score > self.threshold

