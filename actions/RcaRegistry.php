<?php
/**
 * RcaRegistry — Registry CRUD endpoint.
 * Restricted to Super Admin users only.
 * Handles: read, add_pattern, update_pattern, delete_pattern,
 *          add_relationship, delete_relationship, add_gap_rule,
 *          train (append training log from incident data).
 *
 * Namespace: Modules\RCA
 */

namespace Modules\RCA\Actions;

use CController;
use CControllerResponseData;
use CWebUser;

class RcaRegistry extends CController {

	private const REGISTRY_FILE = __DIR__ . '/../config/rca_registry.json';

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		$fields = [
			'action_type' => 'required|string',
			'payload'     => 'array',
		];
		return $this->validateInput($fields);
	}

	protected function checkPermissions(): bool {
		// Registry editing is STRICTLY Super Admin only
		if (CWebUser::getType() != \USER_TYPE_SUPER_ADMIN) {
			$this->setResponse(new CControllerResponseData([
				'error' => 'Access denied. Registry management requires Super Admin privileges.',
				'code'  => 403,
			]));
			return false;
		}
		return true;
	}

	protected function doAction(): void {
		$actionType = $this->getInput('action_type');
		$payload    = $this->getInput('payload', []);

		$registry = $this->loadRegistry();
		if ($registry === null) {
			$this->setResponse(new CControllerResponseData(['error' => 'Failed to load registry file.']));
			return;
		}

		$result = match($actionType) {
			'read'               => ['data' => $registry],
			'add_pattern'        => $this->addPattern($registry, $payload),
			'update_pattern'     => $this->updatePattern($registry, $payload),
			'delete_pattern'     => $this->deletePattern($registry, $payload),
			'add_relationship'   => $this->addRelationship($registry, $payload),
			'delete_relationship'=> $this->deleteRelationship($registry, $payload),
			'add_gap_rule'       => $this->addGapRule($registry, $payload),
			'delete_gap_rule'    => $this->deleteGapRule($registry, $payload),
			'train'              => $this->trainFromIncident($registry, $payload),
			default              => ['error' => 'Unknown action_type: ' . $actionType],
		};

		$this->setResponse(new CControllerResponseData($result));
	}

	// ── PATTERN CRUD ──────────────────────────────────────────────────────

	private function addPattern(array &$registry, array $payload): array {
		$required = ['cause_pattern', 'effect_pattern', 'window_seconds'];
		foreach ($required as $f) {
			if (empty($payload[$f])) {
				return ['error' => "Missing required field: {$f}"];
			}
		}

		$newId = $this->generateId('pat', $registry['alert_patterns']['patterns'] ?? []);
		$pattern = [
			'id'              => $newId,
			'cause_pattern'   => $payload['cause_pattern'],
			'effect_pattern'  => $payload['effect_pattern'],
			'cause_type'      => $payload['cause_type'] ?? '',
			'effect_type'     => $payload['effect_type'] ?? '',
			'window_seconds'  => (int) $payload['window_seconds'],
			'confidence'      => (float) ($payload['confidence'] ?? 0.5),
			'seen_count'      => 0,
			'note'            => $payload['note'] ?? '',
			'created_by'      => CWebUser::$data['alias'] ?? 'admin',
			'created_at'      => time(),
		];

		$registry['alert_patterns']['patterns'][] = $pattern;
		return $this->saveRegistry($registry) ? ['success' => true, 'pattern' => $pattern] : ['error' => 'Save failed'];
	}

	private function updatePattern(array &$registry, array $payload): array {
		if (empty($payload['id'])) return ['error' => 'Missing id'];

		foreach ($registry['alert_patterns']['patterns'] as &$p) {
			if ($p['id'] === $payload['id']) {
				foreach (['cause_pattern','effect_pattern','cause_type','effect_type','window_seconds','confidence','note'] as $f) {
					if (isset($payload[$f])) $p[$f] = $payload[$f];
				}
				$p['updated_by'] = CWebUser::$data['alias'] ?? 'admin';
				$p['updated_at'] = time();
				return $this->saveRegistry($registry) ? ['success' => true, 'pattern' => $p] : ['error' => 'Save failed'];
			}
		}
		return ['error' => 'Pattern not found: ' . $payload['id']];
	}

	private function deletePattern(array &$registry, array $payload): array {
		if (empty($payload['id'])) return ['error' => 'Missing id'];
		$before = count($registry['alert_patterns']['patterns']);
		$registry['alert_patterns']['patterns'] = array_values(
			array_filter($registry['alert_patterns']['patterns'], fn($p) => $p['id'] !== $payload['id'])
		);
		if (count($registry['alert_patterns']['patterns']) === $before) {
			return ['error' => 'Pattern not found'];
		}
		return $this->saveRegistry($registry) ? ['success' => true] : ['error' => 'Save failed'];
	}

	// ── RELATIONSHIP CRUD ──────────────────────────────────────────────────

	private function addRelationship(array &$registry, array $payload): array {
		$required = ['from_type', 'to_type', 'relationship', 'expected_cascade_seconds'];
		foreach ($required as $f) {
			if (empty($payload[$f])) return ['error' => "Missing: {$f}"];
		}

		$newId = $this->generateId('rel', $registry['ci_relationships']['relationships'] ?? []);
		$rel = [
			'id'                       => $newId,
			'from_type'                => $payload['from_type'],
			'from_name'                => $payload['from_name'] ?? '',
			'to_type'                  => $payload['to_type'],
			'to_name'                  => $payload['to_name'] ?? '',
			'relationship'             => $payload['relationship'],
			'direction'                => 'upstream_to_downstream',
			'expected_cascade_seconds' => (int) $payload['expected_cascade_seconds'],
			'note'                     => $payload['note'] ?? '',
			'created_by'               => CWebUser::$data['alias'] ?? 'admin',
			'created_at'               => time(),
		];

		$registry['ci_relationships']['relationships'][] = $rel;
		return $this->saveRegistry($registry) ? ['success' => true, 'relationship' => $rel] : ['error' => 'Save failed'];
	}

	private function deleteRelationship(array &$registry, array $payload): array {
		if (empty($payload['id'])) return ['error' => 'Missing id'];
		$registry['ci_relationships']['relationships'] = array_values(
			array_filter($registry['ci_relationships']['relationships'], fn($r) => $r['id'] !== $payload['id'])
		);
		return $this->saveRegistry($registry) ? ['success' => true] : ['error' => 'Save failed'];
	}

	// ── GAP RULE CRUD ────────────────────────────────────────────────────

	private function addGapRule(array &$registry, array $payload): array {
		$required = ['trigger_pattern', 'expected_pattern', 'window_seconds'];
		foreach ($required as $f) {
			if (empty($payload[$f])) return ['error' => "Missing: {$f}"];
		}
		$newId = $this->generateId('gap', $registry['gap_rules']['rules'] ?? []);
		$rule = [
			'id'              => $newId,
			'trigger_pattern' => $payload['trigger_pattern'],
			'trigger_type'    => $payload['trigger_type'] ?? '',
			'expected_pattern'=> $payload['expected_pattern'],
			'expected_type'   => $payload['expected_type'] ?? '',
			'window_seconds'  => (int) $payload['window_seconds'],
			'gap_severity'    => $payload['gap_severity'] ?? 'warning',
			'message'         => $payload['message'] ?? '',
			'seen_count'      => 0,
			'created_by'      => CWebUser::$data['alias'] ?? 'admin',
			'created_at'      => time(),
		];
		$registry['gap_rules']['rules'][] = $rule;
		return $this->saveRegistry($registry) ? ['success' => true, 'rule' => $rule] : ['error' => 'Save failed'];
	}

	private function deleteGapRule(array &$registry, array $payload): array {
		if (empty($payload['id'])) return ['error' => 'Missing id'];
		$registry['gap_rules']['rules'] = array_values(
			array_filter($registry['gap_rules']['rules'], fn($r) => $r['id'] !== $payload['id'])
		);
		return $this->saveRegistry($registry) ? ['success' => true] : ['error' => 'Save failed'];
	}

	// ── TRAINING ────────────────────────────────────────────────────────

	private function trainFromIncident(array &$registry, array $payload): array {
		if (empty($payload['events']) || empty($payload['confirmed_root'])) {
			return ['error' => 'Training requires events[] and confirmed_root fields'];
		}

		$entry = [
			'trained_at'      => time(),
			'trained_by'      => CWebUser::$data['alias'] ?? 'admin',
			'incident_id'     => $payload['incident_id'] ?? ('INC_' . time()),
			'confirmed_root'  => $payload['confirmed_root'],
			'event_count'     => count($payload['events']),
			'new_patterns'    => $payload['new_patterns'] ?? [],
		];

		// Bump seen_count + confidence for matched patterns
		foreach ($payload['pattern_matches'] ?? [] as $patId) {
			foreach ($registry['alert_patterns']['patterns'] as &$pat) {
				if ($pat['id'] === $patId) {
					$pat['seen_count']++;
					// Nudge confidence upward (max 0.99)
					$pat['confidence'] = min(0.99, $pat['confidence'] + 0.01);
				}
			}
		}

		// Add any confirmed new patterns from this incident
		foreach ($payload['new_patterns'] ?? [] as $np) {
			$this->addPattern($registry, $np);
		}

		$registry['training_log']['entries'][] = $entry;
		$registry['_last_trained']             = date('c');
		$registry['_trained_incident_count']   = ($registry['_trained_incident_count'] ?? 0) + 1;

		return $this->saveRegistry($registry)
			? ['success' => true, 'entry' => $entry, 'trained_count' => $registry['_trained_incident_count']]
			: ['error' => 'Save failed'];
	}

	// ── FILE I/O ─────────────────────────────────────────────────────────

	private function loadRegistry(): ?array {
		if (!file_exists(self::REGISTRY_FILE)) return null;
		$data = json_decode(file_get_contents(self::REGISTRY_FILE), true);
		return is_array($data) ? $data : null;
	}

	private function saveRegistry(array $registry): bool {
		// Write atomically via temp file
		$tmp = self::REGISTRY_FILE . '.tmp';
		$ok  = file_put_contents($tmp, json_encode($registry, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
		if ($ok === false) return false;
		return rename($tmp, self::REGISTRY_FILE);
	}

	private function generateId(string $prefix, array $existing): string {
		$max = 0;
		foreach ($existing as $item) {
			if (preg_match('/_(\d+)$/', $item['id'] ?? '', $m)) {
				$max = max($max, (int) $m[1]);
			}
		}
		return sprintf('%s_%03d', $prefix, $max + 1);
	}
}
