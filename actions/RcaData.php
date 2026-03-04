<?php
/**
 * RcaData — AJAX data endpoint for the RCA module.
 * Called by the frontend JS to fetch and correlate alert data.
 *
 * Returns JSON with:
 *   - hosts[]         Parsed host metadata
 *   - events[]        All events in window
 *   - chains[]        Detected cascade chains
 *   - root_cause      Best root cause candidate
 *   - gap_alerts[]    Detected gaps vs registry
 *   - summary{}       Counts and time span
 *
 * Namespace: Modules\RCA
 */

namespace Modules\RCA\Actions;

use CController;
use CControllerResponseData;
use API;
use CWebUser;

require_once __DIR__ . '/HostnameParser.php';

class RcaData extends CController {

	/** Max events to fetch (prevent overload) */
	private const MAX_EVENTS = 500;

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		$fields = [
			'time_from'    => 'required|int32',
			'time_till'    => 'required|int32',
			'env'          => 'string',
			'customer'     => 'string',
			'search'       => 'string',
			'correlate_by' => 'array',
			'groupids'     => 'array',
			'hostids'      => 'array',
		];
		$ret = $this->validateInput($fields);
		if (!$ret) {
			$this->setResponse(new CControllerResponseData(['error' => 'Invalid input']));
		}
		return $ret;
	}

	protected function checkPermissions(): bool {
		return CWebUser::isLoggedIn();
	}

	protected function doAction(): void {
		$timeFrom  = (int) $this->getInput('time_from');
		$timeTill  = (int) $this->getInput('time_till');
		$env       = $this->getInput('env', '');
		$customer  = $this->getInput('customer', '');
		$search    = $this->getInput('search', '');
		$correlateBy = $this->getInput('correlate_by', ['alert_name', 'time', 'hostgroup']);

		try {
			// ── 1. Fetch problems from Zabbix API ─────────────────────────
			$problems = $this->fetchProblems($timeFrom, $timeTill);

			if (empty($problems)) {
				$this->setResponse(new CControllerResponseData([
					'hosts'      => [],
					'events'     => [],
					'chains'     => [],
					'root_cause' => null,
					'gap_alerts' => [],
					'summary'    => ['total' => 0, 'critical' => 0, 'warning' => 0],
					'time_from'  => $timeFrom,
					'time_till'  => $timeTill,
				]));
				return;
			}

			// ── 2. Enrich with host data ───────────────────────────────────
			$hostIds   = array_unique(array_column($problems, 'objectid'));
			$hostsRaw  = $this->fetchHosts($hostIds);
			$hostMeta  = $this->parseHostMeta($hostsRaw);

			// ── 3. Apply filters ──────────────────────────────────────────
			$problems  = $this->applyFilters($problems, $hostMeta, $env, $customer, $search);

			// ── 4. Load registry ──────────────────────────────────────────
			$registry  = $this->loadRegistry();

			// ── 5. Build enriched event list ──────────────────────────────
			$events    = $this->buildEventList($problems, $hostMeta);

			// ── 6. Correlate and detect cascade chains ────────────────────
			$chains    = $this->detectCascadeChains($events, $registry, $correlateBy);

			// ── 7. Score root cause ───────────────────────────────────────
			$rootCause = $this->scoreRootCause($events, $chains, $registry);

			// ── 8. Gap detection ──────────────────────────────────────────
			$gapAlerts = $this->detectGaps($events, $registry);

			// ── 9. Summary ────────────────────────────────────────────────
			$summary   = $this->buildSummary($events, $chains, $gapAlerts, $rootCause);

			$this->setResponse(new CControllerResponseData([
				'hosts'      => array_values($hostMeta),
				'events'     => $events,
				'chains'     => $chains,
				'root_cause' => $rootCause,
				'gap_alerts' => $gapAlerts,
				'summary'    => $summary,
				'time_from'  => $timeFrom,
				'time_till'  => $timeTill,
			]));

		} catch (\Exception $e) {
			$this->setResponse(new CControllerResponseData([
				'error' => $e->getMessage(),
			]));
		}
	}

	// ── ZABBIX API CALLS ──────────────────────────────────────────────────

	private function fetchProblems(int $timeFrom, int $timeTill): array {
		return API::Problem()->get([
			'output'             => ['eventid', 'objectid', 'clock', 'name', 'severity', 'acknowledged', 'r_eventid', 'cause_eventid'],
			'selectTags'         => ['tag', 'value'],
			'time_from'          => $timeFrom,
			'time_till'          => $timeTill,
			'recent'             => false,
			'sortfield'          => 'clock',
			'sortorder'          => 'ASC',
			'limit'              => self::MAX_EVENTS,
		]) ?: [];
	}

	private function fetchHosts(array $hostIds): array {
		if (empty($hostIds)) return [];

		return API::Host()->get([
			'output'      => ['hostid', 'host', 'name', 'status'],
			'hostids'     => $hostIds,
			'selectGroups'=> ['groupid', 'name'],
			'selectTags'  => ['tag', 'value'],
		]) ?: [];
	}

	// ── HOST METADATA ──────────────────────────────────────────────────────

	private function parseHostMeta(array $hostsRaw): array {
		$parser = new HostnameParser();
		$meta   = [];

		foreach ($hostsRaw as $host) {
			$hostgroups = array_column($host['groups'] ?? [], 'name');
			$parsed     = $parser->parse($host['host'], $hostgroups);

			$meta[$host['hostid']] = array_merge($parsed, [
				'hostid'     => $host['hostid'],
				'host'       => $host['host'],
				'name'       => $host['name'],
				'hostgroups' => $hostgroups,
				'tags'       => $host['tags'] ?? [],
			]);
		}

		return $meta;
	}

	// ── FILTERS ───────────────────────────────────────────────────────────

	private function applyFilters(array $problems, array $hostMeta, string $env, string $customer, string $search): array {
		return array_values(array_filter($problems, function ($p) use ($hostMeta, $env, $customer, $search) {
			$hid  = $p['objectid'];
			$meta = $hostMeta[$hid] ?? null;

			if ($env && $meta && $meta['env'] !== $env) return false;
			if ($customer && $meta && $meta['customer'] !== $customer) return false;

			if ($search) {
				$haystack = strtolower(($meta['host'] ?? '') . ' ' . ($p['name'] ?? '') . ' ' . implode(' ', $meta['hostgroups'] ?? []));
				if (strpos($haystack, strtolower($search)) === false) return false;
			}

			return true;
		}));
	}

	// ── EVENT LIST ────────────────────────────────────────────────────────

	private function buildEventList(array $problems, array $hostMeta): array {
		$events = [];
		foreach ($problems as $p) {
			$hid   = $p['objectid'];
			$meta  = $hostMeta[$hid] ?? [];
			$clock = (int) $p['clock'];

			$events[] = [
				'eventid'      => $p['eventid'],
				'hostid'       => $hid,
				'host'         => $meta['host'] ?? $hid,
				'trigger_name' => $p['name'],
				'severity'     => (int) $p['severity'],
				'severity_name'=> $this->severityName((int) $p['severity']),
				'clock'        => $clock,
				'clock_fmt'    => date('H:i:s', $clock),
				'clock_date'   => date('Y-m-d', $clock),
				'acknowledged' => (bool) $p['acknowledged'],
				'tags'         => $p['tags'] ?? [],
				'r_eventid'    => $p['r_eventid'],
				'cause_eventid'=> $p['cause_eventid'] ?? null,
				// Parsed host metadata
				'env'          => $meta['env'] ?? '',
				'env_short'    => $meta['env_short'] ?? '',
				'env_color'    => $meta['env_color'] ?? '',
				'customer_name'=> $meta['customer_name'] ?? '',
				'customer_short'=> $meta['customer_short'] ?? '',
				'product_name' => $meta['product_name'] ?? '',
				'type'         => $meta['type'] ?? '',
				'type_name'    => $meta['type_name'] ?? '',
				'type_icon'    => $meta['type_icon'] ?? '🖥',
				'type_layer'   => $meta['type_layer'] ?? 3,
				'display_name' => $meta['display_name'] ?? ($meta['host'] ?? ''),
				'parse_source' => $meta['parse_source'] ?? 'unresolved',
				'parse_confidence' => $meta['parse_confidence'] ?? 0.0,
				'unresolved'   => $meta['unresolved'] ?? true,
				// Will be filled by correlation
				'rca_role'     => 'unknown',
				'chain_id'     => null,
				'delta_seconds'=> null,
			];
		}
		return $events;
	}

	// ── CASCADE CHAIN DETECTION ───────────────────────────────────────────

	private function detectCascadeChains(array &$events, array $registry, array $correlateBy): array {
		$patterns  = $registry['alert_patterns']['patterns'] ?? [];
		$ciRels    = $registry['ci_relationships']['relationships'] ?? [];
		$chains    = [];
		$chainIdx  = 0;

		// Index events by hostid for fast lookup
		$byHost = [];
		foreach ($events as $i => $evt) {
			$byHost[$evt['hostid']][] = $i;
		}

		$matched = [];

		foreach ($events as $i => $cause) {
			foreach ($events as $j => $effect) {
				if ($i === $j || isset($matched[$j])) continue;

				$deltaSeconds = $effect['clock'] - $cause['clock'];
				if ($deltaSeconds <= 0 || $deltaSeconds > 3600) continue;

				$score = $this->correlationScore($cause, $effect, $patterns, $ciRels, $correlateBy, $deltaSeconds);
				if ($score < 0.4) continue;

				// Found a cascade link
				$chainKey = $cause['eventid'];
				if (!isset($chains[$chainKey])) {
					$chains[$chainKey] = [
						'chain_id'     => 'chain_' . (++$chainIdx),
						'root_event'   => $cause,
						'root_index'   => $i,
						'links'        => [],
						'total_span_s' => 0,
					];
					$events[$i]['rca_role']  = 'root_candidate';
					$events[$i]['chain_id']  = $chains[$chainKey]['chain_id'];
					$events[$i]['delta_seconds'] = 0;
				}

				$events[$j]['rca_role']     = 'cascade';
				$events[$j]['chain_id']     = $chains[$chainKey]['chain_id'];
				$events[$j]['delta_seconds']= $deltaSeconds;
				$events[$j]['corr_score']   = round($score, 2);
				$matched[$j]                = true;

				$chains[$chainKey]['links'][] = [
					'event_index'    => $j,
					'eventid'        => $effect['eventid'],
					'delta_seconds'  => $deltaSeconds,
					'corr_score'     => round($score, 2),
				];
				$chains[$chainKey]['total_span_s'] = max(
					$chains[$chainKey]['total_span_s'],
					$deltaSeconds
				);
			}
		}

		return array_values($chains);
	}

	private function correlationScore(array $cause, array $effect, array $patterns, array $ciRels, array $correlateBy, int $delta): float {
		$score = 0.0;
		$weights = ['alert_name' => 0.40, 'time' => 0.25, 'hostgroup' => 0.20, 'trigger_deps' => 0.10, 'tags' => 0.05];

		// Alert name pattern match
		if (in_array('alert_name', $correlateBy)) {
			foreach ($patterns as $pat) {
				$causeMatch  = fnmatch($pat['cause_pattern'],  $cause['trigger_name'],  FNM_CASEFOLD);
				$effectMatch = fnmatch($pat['effect_pattern'], $effect['trigger_name'], FNM_CASEFOLD);
				if ($causeMatch && $effectMatch && $delta <= $pat['window_seconds']) {
					$score += $weights['alert_name'] * (float)($pat['confidence'] ?? 0.8);
					break;
				}
			}
		}

		// Time proximity score (closer = higher)
		if (in_array('time', $correlateBy)) {
			$maxWindow = 3600;
			$timeScore = max(0, 1.0 - ($delta / $maxWindow));
			$score += $weights['time'] * $timeScore;
		}

		// Same hostgroup / customer
		if (in_array('hostgroup', $correlateBy)) {
			if (!empty($cause['customer_name']) && $cause['customer_name'] === $effect['customer_name']) {
				$score += $weights['hostgroup'] * 0.8;
			}
		}

		// Layer-based CI relationship (lower layer causes higher layer)
		if ($cause['type_layer'] < $effect['type_layer']) {
			$score += 0.1;
		}

		// Tags overlap
		if (in_array('tags', $correlateBy)) {
			$causeTags  = array_column($cause['tags'],  'value');
			$effectTags = array_column($effect['tags'], 'value');
			$overlap    = count(array_intersect($causeTags, $effectTags));
			if ($overlap > 0) {
				$score += $weights['tags'] * min(1.0, $overlap / 3);
			}
		}

		return min(1.0, $score);
	}

	// ── ROOT CAUSE SCORING ────────────────────────────────────────────────

	private function scoreRootCause(array &$events, array $chains, array $registry): ?array {
		if (empty($chains)) return null;

		$best      = null;
		$bestScore = -1;

		foreach ($chains as $chain) {
			$root  = $chain['root_event'];
			$score = 0.0;

			// More cascade links = more likely root
			$score += count($chain['links']) * 0.2;

			// Lower infrastructure layer = more likely root
			$score += (6 - ($root['type_layer'] ?? 3)) * 0.15;

			// Higher severity = more likely root
			$score += ((int)($root['severity']) / 5) * 0.2;

			// Earliest in window
			if ($root['delta_seconds'] === 0) $score += 0.3;

			// Registry pattern match bonus
			foreach ($registry['alert_patterns']['patterns'] ?? [] as $pat) {
				if (fnmatch($pat['cause_pattern'], $root['trigger_name'], FNM_CASEFOLD)) {
					$score += 0.1 * ($pat['confidence'] ?? 0.5);
				}
			}

			if ($score > $bestScore) {
				$bestScore = $score;
				$best      = [
					'eventid'     => $root['eventid'],
					'hostid'      => $root['hostid'],
					'host'        => $root['host'],
					'trigger'     => $root['trigger_name'],
					'clock'       => $root['clock'],
					'clock_fmt'   => $root['clock_fmt'],
					'severity'    => $root['severity'],
					'type_name'   => $root['type_name'],
					'customer'    => $root['customer_name'],
					'chain_id'    => $chain['chain_id'],
					'rca_score'   => round($score, 2),
					'cascade_count'=> count($chain['links']),
				];
			}
		}

		// Mark root cause event in list
		if ($best) {
			foreach ($events as &$evt) {
				if ($evt['eventid'] === $best['eventid']) {
					$evt['rca_role'] = 'root_cause';
					break;
				}
			}
		}

		return $best;
	}

	// ── GAP DETECTION ────────────────────────────────────────────────────

	private function detectGaps(array $events, array $registry): array {
		$gaps     = [];
		$rules    = $registry['gap_rules']['rules'] ?? [];
		$eventNames = array_column($events, 'trigger_name');

		foreach ($events as $evt) {
			foreach ($rules as $rule) {
				// Check if this event matches the trigger pattern
				if (!fnmatch($rule['trigger_pattern'], $evt['trigger_name'], FNM_CASEFOLD)) continue;
				if (!empty($rule['trigger_type']) && $evt['type'] !== $rule['trigger_type']) continue;

				// Check if expected effect fired within window
				$windowEnd = $evt['clock'] + (int)($rule['window_seconds']);
				$effectFound = false;
				foreach ($events as $eff) {
					if ($eff['clock'] < $evt['clock']) continue;
					if ($eff['clock'] > $windowEnd) continue;
					if (fnmatch($rule['expected_pattern'], $eff['trigger_name'], FNM_CASEFOLD)) {
						$effectFound = true;
						break;
					}
				}

				if (!$effectFound) {
					$gaps[] = [
						'rule_id'       => $rule['id'],
						'trigger_event' => $evt['eventid'],
						'trigger_host'  => $evt['host'],
						'trigger_name'  => $evt['trigger_name'],
						'expected'      => $rule['expected_pattern'],
						'window_s'      => $rule['window_seconds'],
						'severity'      => $rule['gap_severity'],
						'message'       => $rule['message'],
						'clock'         => $evt['clock'],
					];
				}
			}
		}
		return $gaps;
	}

	// ── SUMMARY ───────────────────────────────────────────────────────────

	private function buildSummary(array $events, array $chains, array $gaps, ?array $rootCause): array {
		$severities = array_column($events, 'severity');
		$clocks     = array_column($events, 'clock');

		return [
			'total'          => count($events),
			'critical'       => count(array_filter($severities, fn($s) => $s >= 4)),
			'warning'        => count(array_filter($severities, fn($s) => $s >= 2 && $s < 4)),
			'affected_hosts' => count(array_unique(array_column($events, 'hostid'))),
			'chain_count'    => count($chains),
			'gap_count'      => count($gaps),
			'root_identified'=> $rootCause !== null,
			'span_seconds'   => !empty($clocks) ? (max($clocks) - min($clocks)) : 0,
			'span_fmt'       => !empty($clocks) ? $this->formatSpan(max($clocks) - min($clocks)) : '0s',
			'first_clock'    => !empty($clocks) ? min($clocks) : null,
			'last_clock'     => !empty($clocks) ? max($clocks) : null,
		];
	}

	// ── HELPERS ───────────────────────────────────────────────────────────

	private function loadRegistry(): array {
		$file = __DIR__ . '/../config/rca_registry.json';
		if (!file_exists($file)) return [];
		return json_decode(file_get_contents($file), true) ?? [];
	}

	private function severityName(int $sev): string {
		return match($sev) {
			0 => 'Not classified',
			1 => 'Information',
			2 => 'Warning',
			3 => 'Average',
			4 => 'High',
			5 => 'Disaster',
			default => 'Unknown',
		};
	}

	private function formatSpan(int $seconds): string {
		if ($seconds < 60)   return $seconds . 's';
		if ($seconds < 3600) return round($seconds / 60) . 'm ' . ($seconds % 60) . 's';
		return floor($seconds / 3600) . 'h ' . round(($seconds % 3600) / 60) . 'm';
	}
}
