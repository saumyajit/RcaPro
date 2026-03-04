<?php
/**
 * RcaData — AJAX data endpoint for the RCA module.
 * Returns JSON via rca.data.php view.
 *
 * Namespace: Modules\RCA\Actions
 * Zabbix 7.0+ compatible
 */

namespace Modules\RCA\Actions;

use CController;
use CControllerResponseData;
use API;
use CWebUser;

require_once __DIR__ . '/HostnameParser.php';

class RcaData extends CController {

	private const MAX_EVENTS = 500;

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		$fields = [
			'time_from'    => 'required|string',
			'time_till'    => 'required|string',
			'env'          => 'string',
			'customer'     => 'string',
			'search'       => 'string',
			'correlate_by' => 'array',
		];

		$ret = $this->validateInput($fields);

		if (!$ret) {
			$this->setResponse(new CControllerResponseData([
				'error' => 'Invalid input parameters',
				'hosts' => [], 'events' => [], 'chains' => [],
				'root_cause' => null, 'gap_alerts' => [],
				'summary' => ['total' => 0, 'critical' => 0, 'warning' => 0,
					'affected_hosts' => 0, 'chain_count' => 0, 'gap_count' => 0,
					'root_identified' => false, 'span_fmt' => '0s',
					'first_clock' => null, 'last_clock' => null, 'span_seconds' => 0],
				'time_from' => 0, 'time_till' => 0,
			]));
		}

		return $ret;
	}

	protected function checkPermissions(): bool {
		return CWebUser::isLoggedIn();
	}

	protected function doAction(): void {
		$timeFrom    = (int) $this->getInput('time_from', 0);
		$timeTill    = (int) $this->getInput('time_till', 0);
		$env         = $this->getInput('env', '');
		$customer    = $this->getInput('customer', '');
		$search      = $this->getInput('search', '');
		$correlateBy = $this->getInput('correlate_by', ['alert_name', 'time', 'hostgroup']);

		// Fallback: if times are 0 default to last 1 hour
		if ($timeTill === 0) $timeTill = time();
		if ($timeFrom === 0) $timeFrom = $timeTill - 3600;

		try {
			$problems = $this->fetchProblems($timeFrom, $timeTill);

			$emptyResponse = [
				'hosts'      => [],
				'events'     => [],
				'chains'     => [],
				'root_cause' => null,
				'gap_alerts' => [],
				'summary'    => [
					'total' => 0, 'critical' => 0, 'warning' => 0,
					'affected_hosts' => 0, 'chain_count' => 0, 'gap_count' => 0,
					'root_identified' => false, 'span_fmt' => '0s',
					'first_clock' => null, 'last_clock' => null, 'span_seconds' => 0,
				],
				'time_from'  => $timeFrom,
				'time_till'  => $timeTill,
			];

			if (empty($problems)) {
				$this->setResponse(new CControllerResponseData($emptyResponse));
				return;
			}

			// Collect all unique trigger IDs (objectid = triggerid for problems)
			$triggerIds = array_unique(array_column($problems, 'objectid'));

			// Fetch triggers to get hostids
			$triggers = API::Trigger()->get([
				'output'      => ['triggerid', 'description', 'priority'],
				'triggerids'  => $triggerIds,
				'selectHosts' => ['hostid', 'host', 'name', 'status'],
				'expandDescription' => true,
			]) ?: [];

			// Build triggerid → host map
			$triggerHostMap = [];
			$allHosts       = [];
			foreach ($triggers as $trigger) {
				foreach ($trigger['hosts'] as $host) {
					$triggerHostMap[$trigger['triggerid']] = $host;
					$allHosts[$host['hostid']]             = $host;
				}
			}

			// Fetch full host data with groups and tags
			$hostIds  = array_keys($allHosts);
			$hostsRaw = $this->fetchHosts($hostIds);
			$hostMeta = $this->parseHostMeta($hostsRaw);

			// Apply filters
			$problems = $this->applyFilters($problems, $triggerHostMap, $hostMeta, $env, $customer, $search);

			if (empty($problems)) {
				$this->setResponse(new CControllerResponseData($emptyResponse));
				return;
			}

			$registry  = $this->loadRegistry();
			$events    = $this->buildEventList($problems, $triggerHostMap, $hostMeta);
			$chains    = $this->detectCascadeChains($events, $registry, $correlateBy);
			$rootCause = $this->scoreRootCause($events, $chains, $registry);
			$gapAlerts = $this->detectGaps($events, $registry);
			$summary   = $this->buildSummary($events, $chains, $gapAlerts, $rootCause, $timeFrom, $timeTill);

			$this->setResponse(new CControllerResponseData([
				'hosts'      => array_values($hostMeta),
				'events'     => array_values($events),
				'chains'     => $chains,
				'root_cause' => $rootCause,
				'gap_alerts' => $gapAlerts,
				'summary'    => $summary,
				'time_from'  => $timeFrom,
				'time_till'  => $timeTill,
			]));

		} catch (\Exception $e) {
			$this->setResponse(new CControllerResponseData([
				'error'      => $e->getMessage(),
				'hosts'      => [], 'events'     => [], 'chains' => [],
				'root_cause' => null, 'gap_alerts' => [],
				'summary'    => ['total' => 0, 'critical' => 0, 'warning' => 0,
					'affected_hosts' => 0, 'chain_count' => 0, 'gap_count' => 0,
					'root_identified' => false, 'span_fmt' => '0s',
					'first_clock' => null, 'last_clock' => null, 'span_seconds' => 0],
				'time_from'  => $timeFrom,
				'time_till'  => $timeTill,
			]));
		}
	}

	// ── ZABBIX API ────────────────────────────────────────────────────────

	private function fetchProblems(int $timeFrom, int $timeTill): array {
		return API::Problem()->get([
			'output'     => ['eventid', 'objectid', 'clock', 'name', 'severity',
			                 'acknowledged', 'r_eventid', 'cause_eventid'],
			'selectTags' => ['tag', 'value'],
			'time_from'  => $timeFrom,
			'time_till'  => $timeTill,
			'recent'     => false,
			'sortfield'  => 'clock',
			'sortorder'  => 'ASC',
			'limit'      => self::MAX_EVENTS,
		]) ?: [];
	}

	private function fetchHosts(array $hostIds): array {
		if (empty($hostIds)) return [];
		return API::Host()->get([
			'output'       => ['hostid', 'host', 'name', 'status'],
			'hostids'      => $hostIds,
			'selectGroups' => ['groupid', 'name'],
			'selectTags'   => ['tag', 'value'],
		]) ?: [];
	}

	// ── HOST METADATA ─────────────────────────────────────────────────────

	private function parseHostMeta(array $hostsRaw): array {
		$parser = new HostnameParser();
		$meta   = [];
		foreach ($hostsRaw as $host) {
			$hostgroups       = array_column($host['groups'] ?? [], 'name');
			$parsed           = $parser->parse($host['host'], $hostgroups);
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

	private function applyFilters(array $problems, array $triggerHostMap, array $hostMeta,
	                               string $env, string $customer, string $search): array {
		return array_values(array_filter($problems, function ($p) use ($triggerHostMap, $hostMeta, $env, $customer, $search) {
			$host = $triggerHostMap[$p['objectid']] ?? null;
			if (!$host) return false;
			$meta = $hostMeta[$host['hostid']] ?? null;

			if ($env      && $meta && ($meta['env']      ?? '') !== $env)      return false;
			if ($customer && $meta && ($meta['customer'] ?? '') !== $customer) return false;

			if ($search) {
				$haystack = strtolower(
					($host['host'] ?? '') . ' ' .
					($p['name']    ?? '') . ' ' .
					implode(' ', $meta['hostgroups'] ?? [])
				);
				if (strpos($haystack, strtolower($search)) === false) return false;
			}
			return true;
		}));
	}

	// ── EVENT LIST ────────────────────────────────────────────────────────

	private function buildEventList(array $problems, array $triggerHostMap, array $hostMeta): array {
		$events = [];
		foreach ($problems as $p) {
			$host  = $triggerHostMap[$p['objectid']] ?? null;
			if (!$host) continue;
			$meta  = $hostMeta[$host['hostid']] ?? [];
			$clock = (int) $p['clock'];

			$events[] = [
				'eventid'          => $p['eventid'],
				'hostid'           => $host['hostid'],
				'host'             => $host['host'],
				'trigger_name'     => $p['name'],
				'severity'         => (int) $p['severity'],
				'severity_name'    => $this->severityName((int) $p['severity']),
				'clock'            => $clock,
				'clock_fmt'        => date('H:i:s', $clock),
				'clock_date'       => date('Y-m-d', $clock),
				'acknowledged'     => (bool) $p['acknowledged'],
				'tags'             => $p['tags'] ?? [],
				'r_eventid'        => $p['r_eventid'] ?? null,
				'cause_eventid'    => $p['cause_eventid'] ?? null,
				// Parsed host metadata
				'env'              => $meta['env']              ?? '',
				'env_name'         => $meta['env_name']         ?? '',
				'env_short'        => $meta['env_short']        ?? '',
				'env_color'        => $meta['env_color']        ?? '',
				'customer'         => $meta['customer']         ?? '',
				'customer_name'    => $meta['customer_name']    ?? '',
				'customer_short'   => $meta['customer_short']   ?? '',
				'product_name'     => $meta['product_name']     ?? '',
				'type'             => $meta['type']             ?? '',
				'type_name'        => $meta['type_name']        ?? '',
				'type_icon'        => $meta['type_icon']        ?? '🖥',
				'type_layer'       => (int) ($meta['type_layer'] ?? 3),
				'display_name'     => $meta['display_name']     ?? $host['host'],
				'parse_source'     => $meta['parse_source']     ?? 'unresolved',
				'parse_confidence' => (float) ($meta['parse_confidence'] ?? 0.0),
				'unresolved'       => (bool) ($meta['unresolved'] ?? true),
				// Correlation fields (filled later)
				'rca_role'         => 'unknown',
				'chain_id'         => null,
				'delta_seconds'    => null,
				'corr_score'       => null,
			];
		}
		return $events;
	}

	// ── CASCADE CHAIN DETECTION ───────────────────────────────────────────

	private function detectCascadeChains(array &$events, array $registry, array $correlateBy): array {
		$patterns = $registry['alert_patterns']['patterns'] ?? [];
		$chains   = [];
		$chainIdx = 0;
		$matched  = [];

		foreach ($events as $i => $cause) {
			foreach ($events as $j => $effect) {
				if ($i === $j || isset($matched[$j])) continue;
				$delta = $effect['clock'] - $cause['clock'];
				if ($delta <= 0 || $delta > 3600) continue;

				$score = $this->correlationScore($cause, $effect, $patterns, $correlateBy, $delta);
				if ($score < 0.35) continue;

				$key = $cause['eventid'];
				if (!isset($chains[$key])) {
					$chains[$key] = [
						'chain_id'    => 'chain_' . (++$chainIdx),
						'root_event'  => $cause,
						'root_index'  => $i,
						'links'       => [],
						'total_span_s'=> 0,
					];
					$events[$i]['rca_role']      = 'root_candidate';
					$events[$i]['chain_id']      = $chains[$key]['chain_id'];
					$events[$i]['delta_seconds'] = 0;
				}

				$events[$j]['rca_role']      = 'cascade';
				$events[$j]['chain_id']      = $chains[$key]['chain_id'];
				$events[$j]['delta_seconds'] = $delta;
				$events[$j]['corr_score']    = round($score, 2);
				$matched[$j]                 = true;

				$chains[$key]['links'][]     = [
					'eventid'       => $effect['eventid'],
					'delta_seconds' => $delta,
					'corr_score'    => round($score, 2),
				];
				$chains[$key]['total_span_s'] = max($chains[$key]['total_span_s'], $delta);
			}
		}

		return array_values($chains);
	}

	private function correlationScore(array $cause, array $effect, array $patterns,
	                                   array $correlateBy, int $delta): float {
		$score = 0.0;

		if (in_array('alert_name', $correlateBy)) {
			foreach ($patterns as $pat) {
				if (fnmatch($pat['cause_pattern'],  $cause['trigger_name'],  FNM_CASEFOLD) &&
				    fnmatch($pat['effect_pattern'], $effect['trigger_name'], FNM_CASEFOLD) &&
				    $delta <= (int)($pat['window_seconds'])) {
					$score += 0.40 * (float)($pat['confidence'] ?? 0.8);
					break;
				}
			}
		}

		if (in_array('time', $correlateBy)) {
			$score += 0.25 * max(0, 1.0 - ($delta / 3600));
		}

		if (in_array('hostgroup', $correlateBy)) {
			if (!empty($cause['customer_name']) && $cause['customer_name'] === $effect['customer_name']) {
				$score += 0.20;
			}
		}

		// Layer direction bonus — lower layer causing higher = valid cascade direction
		if ($cause['type_layer'] < $effect['type_layer']) {
			$score += 0.10;
		}

		if (in_array('tags', $correlateBy)) {
			$ct = array_column($cause['tags'],  'value');
			$et = array_column($effect['tags'], 'value');
			$overlap = count(array_intersect($ct, $et));
			if ($overlap > 0) $score += 0.05 * min(1.0, $overlap / 3);
		}

		return min(1.0, $score);
	}

	// ── ROOT CAUSE SCORING ────────────────────────────────────────────────

	private function scoreRootCause(array &$events, array $chains, array $registry): ?array {
		if (empty($chains)) return null;

		$best = null; $bestScore = -1;

		foreach ($chains as $chain) {
			$root  = $chain['root_event'];
			$score = 0.0;
			$score += count($chain['links']) * 0.20;
			$score += (6 - ($root['type_layer'] ?? 3)) * 0.15;
			$score += ((int)($root['severity']) / 5) * 0.20;
			if ($root['delta_seconds'] === 0) $score += 0.30;

			foreach ($registry['alert_patterns']['patterns'] ?? [] as $pat) {
				if (fnmatch($pat['cause_pattern'], $root['trigger_name'], FNM_CASEFOLD)) {
					$score += 0.10 * (float)($pat['confidence'] ?? 0.5);
				}
			}

			if ($score > $bestScore) {
				$bestScore = $score;
				$best = [
					'eventid'       => $root['eventid'],
					'hostid'        => $root['hostid'],
					'host'          => $root['host'],
					'trigger'       => $root['trigger_name'],
					'clock'         => $root['clock'],
					'clock_fmt'     => $root['clock_fmt'],
					'severity'      => $root['severity'],
					'type_name'     => $root['type_name'],
					'customer'      => $root['customer_name'],
					'chain_id'      => $chain['chain_id'],
					'rca_score'     => round($score, 2),
					'cascade_count' => count($chain['links']),
				];
			}
		}

		if ($best) {
			foreach ($events as &$evt) {
				if ($evt['eventid'] === $best['eventid']) {
					$evt['rca_role'] = 'root_cause';
					break;
				}
			}
			unset($evt);
		}

		return $best;
	}

	// ── GAP DETECTION ─────────────────────────────────────────────────────

	private function detectGaps(array $events, array $registry): array {
		$gaps  = [];
		$rules = $registry['gap_rules']['rules'] ?? [];

		foreach ($events as $evt) {
			foreach ($rules as $rule) {
				if (!fnmatch($rule['trigger_pattern'], $evt['trigger_name'], FNM_CASEFOLD)) continue;
				if (!empty($rule['trigger_type']) && $evt['type'] !== $rule['trigger_type']) continue;

				$windowEnd   = $evt['clock'] + (int)($rule['window_seconds']);
				$effectFound = false;

				foreach ($events as $eff) {
					if ($eff['clock'] < $evt['clock'] || $eff['clock'] > $windowEnd) continue;
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

	private function buildSummary(array $events, array $chains, array $gaps,
	                               ?array $rootCause, int $timeFrom, int $timeTill): array {
		$severities = array_column($events, 'severity');
		$clocks     = array_column($events, 'clock');

		return [
			'total'           => count($events),
			'critical'        => count(array_filter($severities, fn($s) => $s >= 4)),
			'warning'         => count(array_filter($severities, fn($s) => $s >= 2 && $s < 4)),
			'affected_hosts'  => count(array_unique(array_column($events, 'hostid'))),
			'chain_count'     => count($chains),
			'gap_count'       => count($gaps),
			'root_identified' => $rootCause !== null,
			'span_seconds'    => !empty($clocks) ? (max($clocks) - min($clocks)) : 0,
			'span_fmt'        => !empty($clocks) ? $this->formatSpan(max($clocks) - min($clocks)) : '0s',
			'first_clock'     => !empty($clocks) ? min($clocks) : $timeFrom,
			'last_clock'      => !empty($clocks) ? max($clocks) : $timeTill,
		];
	}

	// ── HELPERS ───────────────────────────────────────────────────────────

	private function loadRegistry(): array {
		$file = __DIR__ . '/../config/rca_registry.json';
		if (!file_exists($file)) return [];
		$data = json_decode(file_get_contents($file), true);
		return is_array($data) ? $data : [];
	}

	private function severityName(int $sev): string {
		return match($sev) {
			0 => 'Not classified', 1 => 'Information', 2 => 'Warning',
			3 => 'Average', 4 => 'High', 5 => 'Disaster', default => 'Unknown',
		};
	}

	private function formatSpan(int $seconds): string {
		if ($seconds < 60)   return $seconds . 's';
		if ($seconds < 3600) return round($seconds / 60) . 'm ' . ($seconds % 60) . 's';
		return floor($seconds / 3600) . 'h ' . round(($seconds % 3600) / 60) . 'm';
	}
}
