<?php
/**
 * HostnameParser — Parses Zabbix hostnames into structured metadata.
 *
 * Strategy (in order):
 *   1. Check hostname_exceptions.json for manual override
 *   2. Attempt positional 13-char parse against hostname_map.json
 *   3. Fallback: extract from Zabbix hostgroup names (CUSTOMER/, PRODUCT/, TYPE/)
 *   4. If all fail: return raw hostname flagged as UNRESOLVED
 *
 * Namespace: Modules\RCA\Actions
 */

namespace Modules\RCA\Actions;

class HostnameParser {

	/** @var array Loaded hostname_map config */
	private array $map = [];

	/** @var array Loaded exceptions list, keyed by hostname */
	private array $exceptions = [];

	/** @var bool Whether configs are loaded */
	private bool $loaded = false;

	/** Expected fixed hostname length (covers ~95% of cases) */
	private const FIXED_LENGTH = 13;

	/** Segment definitions: [offset, length] */
	private const SEGMENTS = [
		'env'      => [0, 2],
		'customer' => [2, 4],
		'product'  => [6, 2],
		'type'     => [8, 2],
		'instance' => [10, 3],
	];

	public function __construct() {
		$this->loadConfigs();
	}

	/**
	 * Main parse entry point.
	 *
	 * @param string $hostname   Raw Zabbix hostname
	 * @param array  $hostgroups Array of hostgroup name strings for this host
	 * @return array Parsed metadata with keys:
	 *   hostname, env, env_name, customer, customer_name, product, product_name,
	 *   type, type_name, type_icon, type_layer, instance, display_name,
	 *   parse_source (exception|positional|hostgroup|unresolved),
	 *   parse_confidence (0.0–1.0), unresolved (bool), unresolved_segments (array)
	 */
	public function parse(string $hostname, array $hostgroups = []): array {
		$result = $this->baseResult($hostname);

		// ── Step 1: Exception override ──────────────────────────────────────
		if (isset($this->exceptions[$hostname])) {
			return $this->applyException($result, $this->exceptions[$hostname]);
		}

		// ── Step 2: Positional 13-char parse ────────────────────────────────
		$len = strlen($hostname);
		if ($len === self::FIXED_LENGTH) {
			$parsed = $this->positionalParse($hostname);
			if ($parsed['parse_confidence'] >= 0.5) {
				// Partial or full positional match — fill remaining from hostgroups
				if ($parsed['parse_confidence'] < 1.0 && !empty($hostgroups)) {
					$parsed = $this->mergeHostgroupFallback($parsed, $hostgroups);
				}
				$parsed['display_name'] = $this->buildDisplayName($parsed);
				return $parsed;
			}
		}

		// ── Step 3: Non-standard length — try partial positional then hostgroup
		if ($len !== self::FIXED_LENGTH) {
			$result['parse_source'] = 'exception_needed';
			$result['unresolved'] = true;
			$result['unresolved_note'] = "Hostname length {$len} ≠ expected " . self::FIXED_LENGTH . ". Add to hostname_exceptions.json.";
		}

		// ── Step 4: Hostgroup fallback ────────────────────────────────────
		if (!empty($hostgroups)) {
			$hgParsed = $this->parseHostgroups($hostgroups);
			if (!empty($hgParsed)) {
				$result = array_merge($result, $hgParsed);
				$result['parse_source'] = 'hostgroup';
				$result['parse_confidence'] = 0.6;
				$result['unresolved'] = $this->hasUnresolvedSegments($result);
				$result['display_name'] = $this->buildDisplayName($result);
				return $result;
			}
		}

		// ── Step 5: Fully unresolved — show raw, flag it ─────────────────
		$result['unresolved'] = true;
		$result['parse_source'] = 'unresolved';
		$result['parse_confidence'] = 0.0;
		$result['display_name'] = $hostname . ' ⚠';
		return $result;
	}

	// ── PRIVATE: Positional parse ─────────────────────────────────────────

	private function positionalParse(string $hostname): array {
		$result = $this->baseResult($hostname);
		$result['parse_source'] = 'positional';
		$unresolved = [];
		$resolved = 0;
		$total = 5;

		foreach (self::SEGMENTS as $key => [$offset, $length]) {
			$code = substr($hostname, $offset, $length);
			$lookup = $this->lookupCode($key, $code);
			if ($lookup !== null) {
				$result[$key] = $code;
				$this->applyLookup($result, $key, $lookup);
				$resolved++;
			} else {
				$result[$key] = $code;
				$unresolved[] = $key;
			}
		}

		$result['parse_confidence'] = $resolved / $total;
		$result['unresolved_segments'] = $unresolved;
		$result['unresolved'] = !empty($unresolved);
		return $result;
	}

	// ── PRIVATE: Hostgroup parser ────────────────────────────────────────

	private function parseHostgroups(array $hostgroups): array {
		$out = [];
		$patterns = $this->map['hostgroup_patterns'] ?? [
			'customer' => '^CUSTOMER\/(.+)$',
			'product'  => '^PRODUCT\/(.+)$',
			'type'     => '^TYPE\/(.+)$',
		];

		foreach ($hostgroups as $hg) {
			// CUSTOMER/xxx
			if (!empty($patterns['customer']) && preg_match('/' . $patterns['customer'] . '/i', $hg, $m)) {
				$label = trim($m[1]);
				$code  = $this->reverseCustomerLookup($label);
				if ($code === '') {
					// Not in map — generate slug consistent with RcaView dropdown key
					$code = strtolower(preg_replace('/[^a-z0-9]+/i', '_', $label));
				}
				$out['customer']      = $code;
				$out['customer_name'] = $label;
				// Preserve mapped short name if available
				if (!empty($this->map['customers'][$code]['short'])) {
					$out['customer_short'] = $this->map['customers'][$code]['short'];
				} else {
					$out['customer_short'] = ucwords(strtolower($label));
				}
			}
			// PRODUCT/xxx
			if (!empty($patterns['product']) && preg_match('/' . $patterns['product'] . '/i', $hg, $m)) {
				$label = trim($m[1]);
				$code  = $this->reverseProductLookup($label);
				if ($code === '') {
					$code = strtolower(preg_replace('/[^a-z0-9]+/i', '_', $label));
				}
				$out['product']       = $code;
				$out['product_name']  = $label;
				$out['product_short'] = ucwords(strtolower($label));
			}
			// TYPE/xxx
			if (!empty($patterns['type']) && preg_match('/' . $patterns['type'] . '/i', $hg, $m)) {
				$typeName = trim($m[1]);
				$typeData = $this->reverseTypeLookup($typeName);
				if ($typeData) {
					$out['type']       = $typeData['code'];
					$out['type_name']  = $typeData['name'];
					$out['type_icon']  = $typeData['icon'] ?? '🖥';
					$out['type_layer'] = $typeData['layer'] ?? 3;
				} else {
					// Type not in map — use slug
					$out['type']       = strtolower(preg_replace('/[^a-z0-9]+/i', '_', $typeName));
					$out['type_name']  = $typeName;
					$out['type_icon']  = '🖥';
					$out['type_layer'] = 3;
				}
			}
		}
		return $out;
	}

	// ── PRIVATE: Merge hostgroup data into partially-resolved positional result

	private function mergeHostgroupFallback(array $parsed, array $hostgroups): array {
		$hgData = $this->parseHostgroups($hostgroups);
		foreach ($hgData as $key => $value) {
			// Only fill in if the segment was unresolved
			$baseKey = str_replace(['_name', '_icon', '_layer'], '', $key);
			if (in_array($baseKey, $parsed['unresolved_segments'] ?? [], true) || !isset($parsed[$key])) {
				$parsed[$key] = $value;
			}
		}
		// Recalculate confidence
		$remaining = $parsed['unresolved_segments'] ?? [];
		$stillUnresolved = array_filter($remaining, fn($s) => empty($parsed[$s . '_name']) && empty($parsed[$s]));
		$parsed['unresolved_segments'] = array_values($stillUnresolved);
		$parsed['unresolved'] = !empty($stillUnresolved);
		$parsed['parse_confidence'] = min(1.0, $parsed['parse_confidence'] + (count($remaining) - count($stillUnresolved)) / 5);
		$parsed['parse_source'] = 'positional+hostgroup';
		return $parsed;
	}

	// ── PRIVATE: Exception apply ──────────────────────────────────────────

	private function applyException(array $result, array $exc): array {
		foreach (['env', 'customer', 'product', 'type', 'instance'] as $seg) {
			if (!empty($exc[$seg])) {
				$result[$seg] = $exc[$seg];
				$lookup = $this->lookupCode($seg, $exc[$seg]);
				if ($lookup) {
					$this->applyLookup($result, $seg, $lookup);
				}
			}
		}
		$result['parse_source'] = 'exception';
		$result['parse_confidence'] = 1.0;
		$result['unresolved'] = false;
		$result['display_name'] = $exc['resolved_name'] ?? $this->buildDisplayName($result);
		$result['exception_note'] = $exc['note'] ?? '';
		return $result;
	}

	// ── PRIVATE: Lookup helpers ───────────────────────────────────────────

	private function lookupCode(string $segment, string $code): ?array {
		return match($segment) {
			'env'      => $this->map['environments'][$code] ?? null,
			'customer' => $this->map['customers'][$code] ?? null,
			'product'  => $this->map['products'][$code] ?? null,
			'type'     => $this->map['server_types'][$code] ?? null,
			'instance' => ['value' => $code], // instance always resolves
			default    => null,
		};
	}

	private function applyLookup(array &$result, string $segment, array $lookup): void {
		switch ($segment) {
			case 'env':
				$result['env_name']  = $lookup['name'] ?? '';
				$result['env_short'] = $lookup['short'] ?? '';
				$result['env_color'] = $lookup['color'] ?? '';
				break;
			case 'customer':
				$result['customer_name']  = $lookup['name'] ?? '';
				$result['customer_short'] = $lookup['short'] ?? '';
				break;
			case 'product':
				$result['product_name']  = $lookup['name'] ?? '';
				$result['product_short'] = $lookup['short'] ?? '';
				break;
			case 'type':
				$result['type_name']  = $lookup['name'] ?? '';
				$result['type_short'] = $lookup['short'] ?? '';
				$result['type_icon']  = $lookup['icon'] ?? '🖥';
				$result['type_layer'] = (int)($lookup['layer'] ?? 3);
				break;
			case 'instance':
				$result['instance'] = $lookup['value'];
				break;
		}
	}

	private function reverseCustomerLookup(string $name): string {
		foreach ($this->map['customers'] ?? [] as $code => $data) {
			if (strcasecmp($data['name'], $name) === 0 || strcasecmp($data['short'], $name) === 0) {
				return $code;
			}
		}
		return '';
	}

	private function reverseProductLookup(string $name): string {
		foreach ($this->map['products'] ?? [] as $code => $data) {
			if (strcasecmp($data['name'], $name) === 0) {
				return $code;
			}
		}
		return '';
	}

	private function reverseTypeLookup(string $name): ?array {
		foreach ($this->map['server_types'] ?? [] as $code => $data) {
			if (strcasecmp($data['name'], $name) === 0 || strcasecmp($data['short'], $name) === 0) {
				return array_merge($data, ['code' => $code]);
			}
		}
		return null;
	}

	private function hasUnresolvedSegments(array $result): bool {
		foreach (['env_name', 'customer_name', 'product_name', 'type_name'] as $f) {
			if (empty($result[$f])) return true;
		}
		return false;
	}

	private function buildDisplayName(array $r): string {
		$parts = array_filter([
			$r['env_short']      ?? null,
			$r['customer_short'] ?? $r['customer_name'] ?? null,
			$r['product_name']   ?? null,
			$r['type_name']      ?? null,
		]);
		return implode(' · ', $parts) ?: $r['hostname'];
	}

	private function baseResult(string $hostname): array {
		return [
			'hostname'           => $hostname,
			'env'                => '',
			'env_name'           => '',
			'env_short'          => '',
			'env_color'          => '',
			'customer'           => '',
			'customer_name'      => '',
			'customer_short'     => '',
			'product'            => '',
			'product_name'       => '',
			'product_short'      => '',
			'type'               => '',
			'type_name'          => '',
			'type_short'         => '',
			'type_icon'          => '🖥',
			'type_layer'         => 3,
			'instance'           => '',
			'display_name'       => $hostname,
			'parse_source'       => 'none',
			'parse_confidence'   => 0.0,
			'unresolved'         => true,
			'unresolved_segments'=> [],
			'exception_note'     => '',
		];
	}

	// ── PRIVATE: Config loader ────────────────────────────────────────────

	private function loadConfigs(): void {
		if ($this->loaded) return;

		$mapFile = __DIR__ . '/../config/hostname_map.json';
		$excFile = __DIR__ . '/../config/hostname_exceptions.json';

		if (file_exists($mapFile)) {
			$this->map = json_decode(file_get_contents($mapFile), true) ?? [];
		}

		if (file_exists($excFile)) {
			$data = json_decode(file_get_contents($excFile), true) ?? [];
			foreach ($data['exceptions'] ?? [] as $exc) {
				if (!empty($exc['hostname'])) {
					$this->exceptions[$exc['hostname']] = $exc;
				}
			}
		}

		$this->loaded = true;
	}
}
