"""
MITRE ATT&CK Validation Service
Validates LLM responses against the actual MITRE ATT&CK framework to prevent hallucination
"""

import json
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from difflib import SequenceMatcher
from core import logger, Config

@dataclass
class ValidationResult:
    """Result of MITRE technique validation"""
    is_valid: bool
    technique_id: str
    confidence_score: float
    validation_details: Dict[str, Any]
    corrected_data: Optional[Dict[str, Any]] = None

def similarity_ratio(a: str, b: str) -> float:
    """Calculate similarity ratio between two strings using SequenceMatcher"""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100

def partial_ratio(a: str, b: str) -> float:
    """Calculate partial similarity ratio between two strings"""
    # Find the best matching substring
    shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
    best_ratio = 0
    
    for i in range(len(longer) - len(shorter) + 1):
        substring = longer[i:i + len(shorter)]
        ratio = similarity_ratio(shorter, substring)
        best_ratio = max(best_ratio, ratio)
    
    return best_ratio

class MitreValidationService:
    """Service to validate MITRE ATT&CK technique data against the official framework"""
    
    def __init__(self):
        self.mitre_data = {}
        self.technique_mapping = {}
        self.valid_platforms = set()
        self.valid_tactics = set()
        self._load_mitre_data()
        logger.info("MITRE validation service initialized")
    
    def _load_mitre_data(self):
        """Load and index MITRE ATT&CK data for validation"""
        try:
            with open(Config.ATTACK_DATA_PATH, 'r', encoding='utf-8') as f:
                stix_data = json.load(f)
            
            attack_patterns = 0
            techniques_loaded = 0
            
            # Index techniques by ID and name
            for obj in stix_data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    attack_patterns += 1
                    # Get technique ID from external references
                    tech_id = None
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            tech_id = ref.get('external_id')
                            break
                    
                    if tech_id:
                        techniques_loaded += 1
                        technique_data = {
                            'id': tech_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'kill_chain_phases': [phase.get('phase_name', '') for phase in obj.get('kill_chain_phases', [])],
                            'platforms': obj.get('x_mitre_platforms', []),
                            'data_sources': obj.get('x_mitre_data_sources', []),
                            'created': obj.get('created', ''),
                            'modified': obj.get('modified', ''),
                            'aliases': obj.get('aliases', [])
                        }
                        
                        # Index by technique ID
                        self.mitre_data[tech_id] = technique_data
                        
                        # Index by name for fuzzy matching
                        self.technique_mapping[obj.get('name', '').lower()] = tech_id
                        
                        # Collect valid platforms and tactics
                        self.valid_platforms.update(technique_data['platforms'])
                        self.valid_tactics.update(technique_data['kill_chain_phases'])
            
            logger.info(f"Found {attack_patterns} attack patterns, loaded {techniques_loaded} techniques for validation")
            logger.info(f"Valid platforms: {len(self.valid_platforms)}")
            logger.info(f"Valid tactics: {len(self.valid_tactics)}")
            
            # Debug: Show first few technique IDs
            sample_ids = list(self.mitre_data.keys())[:5]
            logger.info(f"Sample technique IDs: {sample_ids}")
            
        except Exception as e:
            logger.error(f"Error loading MITRE data for validation: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
    
    def _normalize_technique_id(self, technique_id: str) -> str:
        """Normalize technique ID format"""
        if not technique_id:
            return ""
        
        # Remove any prefix variations
        technique_id = re.sub(r'^(MITRE-)?ATT&CK-?', '', technique_id, flags=re.IGNORECASE)
        technique_id = re.sub(r'^T-?', 'T', technique_id)
        
        # Ensure proper T prefix
        if not technique_id.startswith('T'):
            technique_id = 'T' + technique_id
        
        return technique_id.upper()
    
    def _validate_technique_id(self, technique_id: str) -> Tuple[bool, float, Dict[str, Any]]:
        """Validate if technique ID exists in MITRE framework"""
        normalized_id = self._normalize_technique_id(technique_id)
        
        details = {
            'original_id': technique_id,
            'normalized_id': normalized_id,
            'exists_in_framework': False,
            'similar_ids': []
        }
        
        # Exact match
        if normalized_id in self.mitre_data:
            details['exists_in_framework'] = True
            return True, 1.0, details
        
        # Find similar technique IDs
        similar_ids = []
        for valid_id in self.mitre_data.keys():
            similarity = similarity_ratio(normalized_id, valid_id)
            if similarity > 70:  # 70% similarity threshold
                similar_ids.append((valid_id, similarity))
        
        details['similar_ids'] = sorted(similar_ids, key=lambda x: x[1], reverse=True)[:3]
        
        # If we have high similarity matches, consider it partially valid
        if similar_ids and similar_ids[0][1] > 85:
            return True, similar_ids[0][1] / 100, details
        
        return False, 0.0, details
    
    def _validate_technique_name(self, technique_id: str, name: str) -> Tuple[bool, float, Dict[str, Any]]:
        """Validate if technique name matches the ID"""
        if not technique_id or not name:
            return False, 0.0, {'error': 'Missing technique ID or name'}
        
        normalized_id = self._normalize_technique_id(technique_id)
        
        details = {
            'provided_name': name,
            'official_name': '',
            'name_similarity': 0.0
        }
        
        if normalized_id in self.mitre_data:
            official_name = self.mitre_data[normalized_id]['name']
            details['official_name'] = official_name
            
            # Calculate name similarity
            similarity = similarity_ratio(name.lower(), official_name.lower())
            details['name_similarity'] = similarity
            
            # Consider valid if 80% similar or higher
            if similarity >= 80:
                return True, similarity / 100, details
            else:
                return False, similarity / 100, details
        
        return False, 0.0, details
    
    def _validate_platforms(self, technique_id: str, platforms: List[str]) -> Tuple[bool, float, Dict[str, Any]]:
        """Validate if platforms are correct for the technique"""
        if not platforms:
            return True, 1.0, {'note': 'No platforms to validate'}
        
        normalized_id = self._normalize_technique_id(technique_id)
        
        details = {
            'provided_platforms': platforms,
            'official_platforms': [],
            'valid_platforms': [],
            'invalid_platforms': []
        }
        
        if normalized_id in self.mitre_data:
            official_platforms = self.mitre_data[normalized_id]['platforms']
            details['official_platforms'] = official_platforms
            
            for platform in platforms:
                if platform in official_platforms:
                    details['valid_platforms'].append(platform)
                else:
                    details['invalid_platforms'].append(platform)
            
            if not details['invalid_platforms']:
                return True, 1.0, details
            elif details['valid_platforms']:
                # Partial match
                accuracy = len(details['valid_platforms']) / len(platforms)
                return True, accuracy, details
            else:
                return False, 0.0, details
        
        return False, 0.0, details
    
    def _validate_tactics(self, technique_id: str, tactics: List[str]) -> Tuple[bool, float, Dict[str, Any]]:
        """Validate if tactics (kill chain phases) are correct"""
        if not tactics:
            return True, 1.0, {'note': 'No tactics to validate'}
        
        normalized_id = self._normalize_technique_id(technique_id)
        
        details = {
            'provided_tactics': tactics,
            'official_tactics': [],
            'valid_tactics': [],
            'invalid_tactics': []
        }
        
        if normalized_id in self.mitre_data:
            official_tactics = self.mitre_data[normalized_id]['kill_chain_phases']
            details['official_tactics'] = official_tactics
            
            for tactic in tactics:
                if tactic in official_tactics:
                    details['valid_tactics'].append(tactic)
                else:
                    details['invalid_tactics'].append(tactic)
            
            if not details['invalid_tactics']:
                return True, 1.0, details
            elif details['valid_tactics']:
                accuracy = len(details['valid_tactics']) / len(tactics)
                return True, accuracy, details
            else:
                return False, 0.0, details
        
        return False, 0.0, details
    
    def validate_technique(self, technique_data: Dict[str, Any]) -> ValidationResult:
        """
        Comprehensive validation of a single MITRE technique
        
        Args:
            technique_data: Dictionary containing technique information
            
        Returns:
            ValidationResult with validation details and corrections
        """
        technique_id = technique_data.get('technique_id', '')
        name = technique_data.get('name', '')
        platforms = technique_data.get('platforms', [])
        tactics = technique_data.get('kill_chain_phases', [])
        
        validation_details = {
            'id_validation': {},
            'name_validation': {},
            'platforms_validation': {},
            'tactics_validation': {},
            'overall_issues': []
        }
        
        # Validate technique ID
        id_valid, id_confidence, id_details = self._validate_technique_id(technique_id)
        validation_details['id_validation'] = {
            'valid': id_valid,
            'confidence': id_confidence,
            'details': id_details
        }
        
        if not id_valid:
            validation_details['overall_issues'].append(f"Invalid technique ID: {technique_id}")
        
        # Validate technique name
        name_valid, name_confidence, name_details = self._validate_technique_name(technique_id, name)
        validation_details['name_validation'] = {
            'valid': name_valid,
            'confidence': name_confidence,
            'details': name_details
        }
        
        if not name_valid and name_confidence < 0.8:
            validation_details['overall_issues'].append(f"Technique name mismatch: '{name}'")
        
        # Validate platforms
        platforms_valid, platforms_confidence, platforms_details = self._validate_platforms(technique_id, platforms)
        validation_details['platforms_validation'] = {
            'valid': platforms_valid,
            'confidence': platforms_confidence,
            'details': platforms_details
        }
        
        if not platforms_valid:
            validation_details['overall_issues'].append(f"Invalid platforms: {platforms_details.get('invalid_platforms', [])}")
        
        # Validate tactics
        tactics_valid, tactics_confidence, tactics_details = self._validate_tactics(technique_id, tactics)
        validation_details['tactics_validation'] = {
            'valid': tactics_valid,
            'confidence': tactics_confidence,
            'details': tactics_details
        }
        
        if not tactics_valid:
            validation_details['overall_issues'].append(f"Invalid tactics: {tactics_details.get('invalid_tactics', [])}")
        
        # Calculate overall confidence
        confidences = [id_confidence, name_confidence, platforms_confidence, tactics_confidence]
        overall_confidence = sum(confidences) / len(confidences)
        
        # Debug logging
        logger.debug(f"Validation for {technique_id}: ID={id_confidence:.2f}, Name={name_confidence:.2f}, Platforms={platforms_confidence:.2f}, Tactics={tactics_confidence:.2f}, Overall={overall_confidence:.2f}")
        
        # Determine if technique is valid overall
        # A technique is valid if the ID exists and either:
        # 1. Everything matches well (high confidence)
        # 2. ID is correct and name is reasonably accurate (partial validation)
        is_valid = (id_valid and name_confidence > 0.7 and 
                   (platforms_confidence > 0.6 or len(platforms) == 0) and 
                   (tactics_confidence > 0.6 or len(tactics) == 0))
        
        # Generate corrected data if needed
        corrected_data = None
        normalized_id = self._normalize_technique_id(technique_id)
        if normalized_id in self.mitre_data and not is_valid:
            official_data = self.mitre_data[normalized_id]
            corrected_data = {
                'technique_id': normalized_id,
                'name': official_data['name'],
                'description': official_data['description'],
                'platforms': official_data['platforms'],
                'kill_chain_phases': official_data['kill_chain_phases'],
                'relevance_score': technique_data.get('relevance_score', 0.0)
            }
        
        return ValidationResult(
            is_valid=is_valid,
            technique_id=technique_id,
            confidence_score=overall_confidence,
            validation_details=validation_details,
            corrected_data=corrected_data
        )
    
    def validate_techniques_list(self, techniques: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate a list of techniques and provide detailed report
        
        Args:
            techniques: List of technique dictionaries
            
        Returns:
            Validation report with statistics and corrections
        """
        results = []
        for technique in techniques:
            result = self.validate_technique(technique)
            results.append(result)
        
        # Generate summary statistics
        total_count = len(results)
        valid_count = sum(1 for r in results if r.is_valid)
        avg_confidence = sum(r.confidence_score for r in results) / total_count if total_count > 0 else 0
        
        # Categorize issues
        hallucinated = [r for r in results if not r.is_valid and r.confidence_score < 0.5]
        questionable = [r for r in results if not r.is_valid and r.confidence_score >= 0.5]
        
        return {
            'validation_summary': {
                'total_techniques': total_count,
                'valid_techniques': valid_count,
                'invalid_techniques': total_count - valid_count,
                'average_confidence': avg_confidence,
                'validation_rate': valid_count / total_count if total_count > 0 else 0
            },
            'issues': {
                'likely_hallucinated': len(hallucinated),
                'questionable_accuracy': len(questionable)
            },
            'detailed_results': results,
            'corrected_techniques': [r.corrected_data for r in results if r.corrected_data]
        }
    
    def get_technique_suggestions(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Get technique suggestions based on query for LLM guidance"""
        suggestions = []
        
        query_lower = query.lower()
        for tech_id, data in self.mitre_data.items():
            # Calculate relevance based on name and description
            name_similarity = partial_ratio(query_lower, data['name'].lower())
            desc_similarity = partial_ratio(query_lower, data['description'].lower())
            
            relevance = max(name_similarity, desc_similarity * 0.8)
            
            if relevance > 60:  # 60% relevance threshold
                suggestions.append({
                    'technique_id': tech_id,
                    'name': data['name'],
                    'description': data['description'][:200] + '...' if len(data['description']) > 200 else data['description'],
                    'relevance': relevance,
                    'platforms': data['platforms'],
                    'tactics': data['kill_chain_phases']
                })
        
        # Sort by relevance and return top results
        suggestions.sort(key=lambda x: x['relevance'], reverse=True)
        return suggestions[:limit]

# Global service instance
mitre_validation_service = MitreValidationService()