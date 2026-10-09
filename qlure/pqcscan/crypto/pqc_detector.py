import json
import os

REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "..", "crypto_registry", "algorithms.json")


class PQCDetector:
    def __init__(self):
        with open(REGISTRY_PATH) as f:
            data = json.load(f)
            self.registry_version = data.get("registry_version", "unknown")
            self.algorithms = data.get("algorithms", {})
            self.groups = data.get("groups", {})
            self.signature_oids = data.get("signature_oids", {})

    def _determine_class(self, name_str: str) -> str:
        """Helper to match string against registry."""
        if not name_str or name_str == "UNKNOWN":
            return "UNKNOWN"
        name_upper = name_str.upper()

        # Check explicit registry matches (prioritize PQC in string)
        for alg, meta in self.algorithms.items():
            if meta["class"] == "PQC" and alg in name_upper:
                return "PQC"

        for alg, meta in self.algorithms.items():
            if meta["class"] != "PQC" and alg in name_upper:
                return meta["class"]

        # Heuristics for typical classical algorithms
        if any(x in name_upper for x in ["RSA", "ECDSA", "ECDHE", "ED25519", "SECP", "X25519"]):
            return "CLASSICAL"

        return "UNKNOWN"

    def classify_key_establishment(
        self, cipher_suite: str, key_exchange_group: str = "UNKNOWN"
    ) -> dict:
        classification = "UNKNOWN"
        basis = []
        confidence = 0.5

        # If cipher string explicitly has hybrid elements (e.g. X25519_KYBER768)
        c_class = self._determine_class(cipher_suite)
        k_class = self._determine_class(key_exchange_group)

        if c_class == "PQC" or k_class == "PQC":
            # Very basic hybrid check: if there's classical and PQC it's hybrid
            combined_upper = cipher_suite.upper() + "_" + key_exchange_group.upper()
            if any(x in combined_upper for x in ["X25519", "ECDHE", "SECP", "RSA", "ECDSA"]):
                classification = "HYBRID"
            else:
                classification = "PQC"
            basis.append(f"Cipher/Group indicates {classification}")
            confidence = 0.8
        elif c_class == "CLASSICAL" or k_class == "CLASSICAL":
            classification = "CLASSICAL"
            basis.append("Classical algorithms detected in key exchange")
            confidence = 0.9

        return {
            "classification": classification,
            "basis": basis,
            "confidence": confidence,
            "registry_version": self.registry_version,
        }

    def classify_authentication(self, sig_algorithm: str) -> dict:
        classification = self._determine_class(sig_algorithm)
        return {
            "classification": classification,
            "basis": [f"Signature algorithm '{sig_algorithm}' matches class {classification}"],
            "confidence": 0.95 if classification != "UNKNOWN" else 0.5,
            "registry_version": self.registry_version,
        }

    # ---- v2: classification by observed codepoint / OID rather than by substring ----

    def classify_group(self, group_id):
        """Classify a TLS supported_groups codepoint (int). Returns name, class and a stable key."""
        if group_id is None:
            return {"name": None, "class": "UNKNOWN"}
        meta = self.groups.get("0x%04x" % group_id)
        if not meta:
            return {"name": "0x%04x" % group_id, "class": "UNKNOWN"}
        return {"name": meta["name"], "class": meta["class"], "note": meta.get("note")}

    def classify_signature_oid(self, dotted_oid: str):
        meta = self.signature_oids.get(dotted_oid)
        return (
            {"name": meta["name"], "class": "PQC"} if meta else {"name": None, "class": "CLASSICAL"}
        )
