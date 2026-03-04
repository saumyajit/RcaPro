<?php
/**
 * RcaData — AJAX data endpoint for the RCA module.
 * Namespace: Modules\RCA\Actions
 * Zabbix 7.0+
 */

namespace Modules\RCA\Actions;

use CController;
use CControllerResponseData;
use API;
use CWebUser;

require_once __DIR__ . '/HostnameParser.php';

class RcaData extends CController {

	private const MAX_EVENTS = 500;
	private const DEBUG      = true;

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
			$this->setResponse(new CControllerResponseData($this->emptyResponse(0, 0)));
		}
		return $ret;
	}

	protected function checkPermissions(): bool {
		return CWebUser::isLoggedIn();
	}

	protected function doAction(): void {
		$timeTill    = (int) $this->getInput('time_till', time());
		$timeFrom    = (int) $this->getInput('time_from', $timeTill - 3600);
		$env         = $this->getInput('env', '');
		$customer    = $this->getInput('customer', '');
		$search      = $this->getInput('search', '');
		$correlateBy = $this->getInput('correlate_by', ['alert_name', 'time', 'hostgroup']);

		if ($timeTill === 0) $timeTill = time();
		if ($timeFrom === 0) $timeFrom = $timeTill - 3600;

		$debug = [
			'time_from_fmt' => date('Y-m-d H:i:s', $timeFrom),
			'time_till_fmt' => date('Y-m-d H:i:s', $timeTill),
			'server_time'   => date('Y-m-d H:i:s', time()),
		];

		try {
			$problems = $this->fetchProblems($timeFrom, $timeTill, $debug);

			$debug['problems_total'] = count($problems);

			if (empty($problems)) {
				$resp = $this->emptyResponse($timeFrom, $timeTill);
				$resp['debug'] = $debug;
				$this->setResponse(new CControllerResponseData($resp));
				return;
			}

			$triggerIds     = array_unique(array_column($problems, 'objectid'));
			$triggerHostMap = $this->fetchTriggerHostMap($triggerIds, $debug);
			$hostIds        = array_unique(array_map(fn($h) => $h['hostid'], array_values($triggerHostMap)));
			$hostsRaw       = $this->fetchHosts($hostIds);
			$hostMeta       = $this->parseHostMeta($hostsRaw);

			$debug['host_count'] = count($hostMeta);

			$problems = $this->applyFilters($problems, $triggerHostMap, $hostMeta, $env, $customer, $search);
			$debug['after_filter'] = count($problems);

			if (empty($problems)) {
				$resp = $this->emptyResponse($timeFrom, $timeTill);
				$resp['debug'] = $debug;
				$this->setResponse(new CControllerResponseData($resp));
				return;
			}

			$registry  = $this->loadRegistry();
			$events    = $this->buildEventList($problems, $triggerHostMap, $hostMeta);
			$chains    = $this->detectCascadeChains($events, $registry, $correlateBy);
			$rootCause = $this->scoreRootCause($events, $chains, $registry);
			$gapAlerts = $this->detectGaps($events, $registry);
			$summary   = $this->buildSummary($events, $chains, $gapAlerts, $rootCause, $timeFrom, $timeTill);

			$response = [
				'hosts'      => array_values($hostMeta),
				'events'     => array_values($events),
				'chains'     => $chains,
				'root_cause' => $rootCause,
				'gap_alerts' => $gapAlerts,
				'summary'    => $summary,
				'time_from'  => $timeFrom,
				'time_till'  => $timeTill,
			];

			if (self::DEBUG) $response['debug'] = $debug;

			$this->setResponse(new CControllerResponseData($response));

		} catch (\Exception $e) {
			$resp          = $this->emptyResponse($timeFrom, $timeTill);
			$resp['error'] = $e->getMessage();
			$resp['trace'] = $e->getTraceAsString();
			$resp['debug'] = $debug;
			$this->setResponse(new CControllerResponseData($resp));
		}
	}

	// ─────────────────────────────────────────────────────────────────────
	// FETCH PROBLEMS — tries 4 different API approaches to find what works
	// in this specific Zabbix 7.0 install. Debug captures each attempt.
	// ─────────────────────────────────────────────────────────────────────

	private function fetchProblems(int $timeFrom, int $timeTill, array &$debug): array {
		$attempts = [];

		// ── Attempt 1: Event API, value=1 (problem state), with time ─────
		try {
			$r = API::Event()->get([
				'output'     => ['eventid', 'objectid', 'clock', 'name', 'severity',
				                 'acknowledged', 'r_eventid', 'cause_eventid', 'value'],
				'selectTags' => ['tag', 'value'],
				'source'     => 0,
				'object'     => 0,
				'value'      => 1,
				'time_from'  => $timeFrom,
				'time_till'  => $timeTill,
				'sortfield'  => 'clock',
				'sortorder'  => 'ASC',
				'limit'      => self::MAX_EVENTS,
			]);
			$cnt = is_array($r) ? count($r) : null;
			$attempts['1_event_value1_timed'] = $cnt ?? ('not_array:' . gettype($r));
			if (is_array($r) && $cnt > 0) {
				$debug['fetch_method'] = 'event_api_value1_timed';
				$debug['fetch_attempts'] = $attempts;
				return $this->normaliseEventRows($r);
			}
		} catch (\Exception $e) { $attempts['1_event_value1_timed_ex'] = $e->getMessage(); }

		// ── Attempt 2: Event API, all values, with time ───────────────────
		try {
			$r = API::Event()->get([
				'output'     => ['eventid', 'objectid', 'clock', 'name', 'severity',
				                 'acknowledged', 'r_eventid', 'cause_eventid', 'value'],
				'selectTags' => ['tag', 'value'],
				'source'     => 0,
				'object'     => 0,
				'time_from'  => $timeFrom,
				'time_till'  => $timeTill,
				'sortfield'  => 'clock',
				'sortorder'  => 'ASC',
				'limit'      => self::MAX_EVENTS,
			]);
			$cnt = is_array($r) ? count($r) : null;
			$attempts['2_event_all_values_timed'] = $cnt ?? ('not_array:' . gettype($r));
			if (is_array($r) && $cnt > 0) {
				// Filter to only problem-state rows (value=1)
				$r = array_values(array_filter($r, fn($e) => (int)($e['value'] ?? 1) === 1));
				$debug['fetch_method'] = 'event_api_all_values_timed';
				$debug['fetch_attempts'] = $attempts;
				return $this->normaliseEventRows($r);
			}
		} catch (\Exception $e) { $attempts['2_event_all_values_timed_ex'] = $e->getMessage(); }

		// ── Attempt 3: Problem API, minimal params ────────────────────────
		try {
			$r = API::Problem()->get([
				'output'     => ['eventid', 'objectid', 'clock', 'name', 'severity',
				                 'acknowledged', 'r_eventid', 'r_clock', 'cause_eventid'],
				'selectTags' => ['tag', 'value'],
				'time_from'  => $timeFrom,
				'time_till'  => $timeTill,
				'sortfield'  => 'clock',
				'sortorder'  => 'ASC',
				'limit'      => self::MAX_EVENTS,
			]);
			$cnt = is_array($r) ? count($r) : null;
			$attempts['3_problem_timed'] = $cnt ?? ('not_array:' . gettype($r));
			if (is_array($r) && $cnt > 0) {
				$debug['fetch_method'] = 'problem_api_timed';
				$debug['fetch_attempts'] = $attempts;
				return $r;
			}
		} catch (\Exception $e) { $attempts['3_problem_timed_ex'] = $e->getMessage(); }

		// ── Attempt 4: Problem API, recent=true only (active problems) ────
		try {
			$r = API::Problem()->get([
				'output'     => ['eventid', 'objectid', 'clock', 'name', 'severity',
				                 'acknowledged', 'r_eventid', 'r_clock', 'cause_eventid'],
				'selectTags' => ['tag', 'value'],
				'recent'     => true,
				'sortfield'  => 'clock',
				'sortorder'  => 'DESC',
				'limit'      => 50,
			]);
			$cnt = is_array($r) ? count($r) : null;
			$attempts['4_problem_recent_only'] = $cnt ?? ('not_array:' . gettype($r));
			if (is_array($r) && $cnt > 0) {
				$debug['fetch_method'] = 'problem_api_recent';
				// Show sample timestamps so we can see what window they fall in
				$debug['recent_sample'] = array_map(fn($p) => [
					'name'  => substr($p['name'] ?? '', 0, 60),
					'clock' => date('Y-m-d H:i:s', (int)$p['clock']),
					'sev'   => $p['severity'],
				], array_slice($r, 0, 5));
				$debug['fetch_attempts'] = $attempts;
				// Filter to time window
				$r = array_values(array_filter($r, fn($p) =>
					(int)$p['clock'] >= $timeFrom && (int)$p['clock'] <= $timeTill
				));
				$debug['after_time_filter'] = count($r);
				return $r;
			}
		} catch (\Exception $e) { $attempts['4_problem_recent_ex'] = $e->getMessage(); }

		// ── Attempt 5: Trigger API — fetch triggers in PROBLEM state ──────
		// Completely bypasses Event/Problem APIs — uses Trigger API directly
		try {
			$r = API::Trigger()->get([
				'output'          => ['triggerid', 'description', 'priority',
				                      'lastchange', 'value', 'error'],
				'selectHosts'     => ['hostid', 'host', 'name'],
				'selectLastEvent' => ['eventid', 'clock', 'name', 'severity',
				                      'acknowledged', 'value'],
				'filter'          => ['value' => 1],  // TRIGGER_VALUE_TRUE = problem
				'lastChangeSince' => $timeFrom,
				'lastChangeTill'  => $timeTill,
				'skipDependent'   => false,
				'sortfield'       => 'lastchange',
				'sortorder'       => 'ASC',
				'limit'           => self::MAX_EVENTS,
			]);
			$cnt = is_array($r) ? count($r) : null;
			$attempts['5_trigger_in_problem'] = $cnt ?? ('not_array:' . gettype($r));
			if (is_array($r) && $cnt > 0) {
				$debug['fetch_method'] = 'trigger_api';
				$debug['fetch_attempts'] = $attempts;
				// Convert trigger rows to problem-shaped rows
				return $this->normaliseTriggerRows($r);
			}
		} catch (\Exception $e) { $attempts['5_trigger_ex'] = $e->getMessage(); }

		// ── Attempt 6: Trigger API, all recent (no time), sample ─────────
		try {
			$r = API::Trigger()->get([
				'output'      => ['triggerid', 'description', 'priority', 'lastchange', 'value'],
				'selectHosts' => ['hostid', 'host'],
				'filter'      => ['value' => 1],
				'limit'       => 20,
			]);
			$cnt = is_array($r) ? count($r) : null;
			$attempts['6_trigger_all_recent'] = $cnt ?? ('not_array:' . gettype($r));
			if (is_array($r)) {
				$debug['trigger_sample'] = array_map(fn($t) => [
					'desc'  => substr($t['description'] ?? '', 0, 60),
					'host'  => $t['hosts'][0]['host'] ?? '?',
					'clock' => date('Y-m-d H:i:s', (int)$t['lastchange']),
					'prio'  => $t['priority'],
				], array_slice($r, 0, 5));
			}
		} catch (\Exception $e) { $attempts['6_trigger_all_recent_ex'] = $e->getMessage(); }

		$debug['fetch_attempts'] = $attempts;
		return [];
	}

	private function normaliseEventRows(array $events): array {
		foreach ($events as &$e) {
			$e['r_clock']       = null;
			$e['r_eventid']     = $e['r_eventid']     ?? null;
			$e['cause_eventid'] = $e['cause_eventid'] ?? null;
		}
		unset($e);
		return $events;
	}

	private function normaliseTriggerRows(array $triggers): array {
		$rows = [];
		foreach ($triggers as $t) {
			$lastEvent = $t['lastEvent'] ?? $t['selectLastEvent'] ?? null;
			$eventId   = $lastEvent['eventid'] ?? ('t_' . $t['triggerid']);
			$rows[] = [
				'eventid'       => $eventId,
				'objectid'      => $t['triggerid'],
				'clock'         => $t['lastchange'],
				'name'          => $t['description'],
				'severity'      => $t['priority'],
				'acknowledged'  => '0',
				'r_eventid'     => null,
				'r_clock'       => null,
				'cause_eventid' => null,
				'tags'          => [],
			];
		}
		return $rows;
	}

	// ── TRIGGER → HOST MAP ────────────────────────────────────────────────

	private function fetchTriggerHostMap(array $triggerIds, array &$debug): array {
		if (empty($triggerIds)) return [];
		// Strip synthetic t_ prefixes from trigger API fallback
		$realIds = array_filter($triggerIds, fn($id) => !str_starts_with((string)$id, 't_'));
		$syntheticIds = array_filter($triggerIds, fn($id) => str_starts_with((string)$id, 't_'));

		$map = [];

		if (!empty($realIds)) {
			try {
				$triggers = API::Trigger()->get([
					'output'            => ['triggerid'],
					'triggerids'        => array_values($realIds),
					'selectHosts'       => ['hostid', 'host', 'name', 'status'],
					'expandDescription' => false,
				]);
				if (is_array($triggers)) {
					foreach ($triggers as $t) {
						if (!empty($t['hosts'])) $map[$t['triggerid']] = $t['hosts'][0];
					}
				}
			} catch (\Exception $e) {
				$debug['trigger_map_error'] = $e->getMessage();
			}
		}

		// For synthetic IDs from trigger fallback, extract triggerid from prefix
		foreach ($syntheticIds as $sid) {
			$tid = substr($sid, 2); // strip "t_"
			if (!isset($map[$sid]) && isset($map[$tid])) {
				$map[$sid] = $map[$tid];
			}
		}

		return $map;
	}

	private function fetchHosts(array $hostIds): array {
		if (empty($hostIds)) return [];
		try {
			$result = API::Host()->get([
				'output'       => ['hostid', 'host', 'name', 'status'],
				'hostids'      => $hostIds,
				'selectHostGroups' => ['groupid', 'name'],
				'selectTags'   => ['tag', 'value'],
			]);
			return is_array($result) ? $result : [];
		} catch (\Exception $e) { return []; }
	}

	private function parseHostMeta(array $hostsRaw): array {
		$parser = new HostnameParser();
		$meta   = [];
		foreach ($hostsRaw as $host) {
			$hostgroups            = array_column($host['groups'] ?? [], 'name');
			$parsed                = $parser->parse($host['host'], $hostgroups);
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

	private function applyFilters(array $problems, array $triggerHostMap, array $hostMeta,
	                               string $env, string $customer, string $search): array {
		return array_values(array_filter($problems, function($p)
		       use ($triggerHostMap, $hostMeta, $env, $customer, $search) {
			if ((int)$p['severity'] < 2) return false;
			$host = $triggerHostMap[$p['objectid']] ?? null;
			if (!$host) return false;
			$meta = $hostMeta[$host['hostid']] ?? [];
			if ($env      && ($meta['env']      ?? '') !== $env)      return false;
			if ($customer && ($meta['customer'] ?? '') !== $customer) return false;
			if ($search) {
				$hay = strtolower(($host['host']??'').' '.($p['name']??'').' '.implode(' ',$meta['hostgroups']??[]));
				if (strpos($hay, strtolower($search)) === false) return false;
			}
			return true;
		}));
	}

	private function buildEventList(array $problems, array $triggerHostMap, array $hostMeta): array {
		$events = [];
		foreach ($problems as $p) {
			$host = $triggerHostMap[$p['objectid']] ?? null;
			if (!$host) continue;
			$meta  = $hostMeta[$host['hostid']] ?? [];
			$clock = (int)$p['clock'];
			$sev   = (int)$p['severity'];
			$events[] = [
				'eventid'          => $p['eventid'],
				'hostid'           => $host['hostid'],
				'host'             => $host['host'],
				'trigger_name'     => $p['name'],
				'severity'         => $sev,
				'severity_name'    => $this->severityName($sev),
				'severity_class'   => $this->severityClass($sev),
				'clock'            => $clock,
				'clock_fmt'        => date('H:i:s', $clock),
				'clock_date'       => date('Y-m-d', $clock),
				'r_clock'          => !empty($p['r_clock']) ? (int)$p['r_clock'] : null,
				'acknowledged'     => (bool)$p['acknowledged'],
				'tags'             => $p['tags'] ?? [],
				'r_eventid'        => $p['r_eventid']     ?? null,
				'cause_eventid'    => $p['cause_eventid'] ?? null,
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
				'type_layer'       => (int)($meta['type_layer'] ?? 3),
				'display_name'     => $meta['display_name']     ?? $host['host'],
				'parse_source'     => $meta['parse_source']     ?? 'unresolved',
				'parse_confidence' => (float)($meta['parse_confidence'] ?? 0.0),
				'unresolved'       => (bool)($meta['unresolved'] ?? false),
				'rca_role'         => 'unknown',
				'chain_id'         => null,
				'delta_seconds'    => null,
				'corr_score'       => null,
			];
		}
		return $events;
	}

	private function detectCascadeChains(array &$events, array $registry, array $correlateBy): array {
		$patterns = $registry['alert_patterns']['patterns'] ?? [];
		$chains = []; $chainIdx = 0; $matched = [];
		foreach ($events as $i => $cause) {
			foreach ($events as $j => $effect) {
				if ($i === $j || isset($matched[$j])) continue;
				$delta = $effect['clock'] - $cause['clock'];
				if ($delta <= 0 || $delta > 3600) continue;
				$score = $this->correlationScore($cause, $effect, $patterns, $correlateBy, $delta);
				if ($score < 0.35) continue;
				$key = $cause['eventid'];
				if (!isset($chains[$key])) {
					$chains[$key] = ['chain_id' => 'chain_'.(++$chainIdx), 'root_event' => $cause,
					                 'root_index' => $i, 'links' => [], 'total_span_s' => 0];
					$events[$i]['rca_role'] = 'root_candidate';
					$events[$i]['chain_id'] = $chains[$key]['chain_id'];
					$events[$i]['delta_seconds'] = 0;
				}
				$events[$j] = array_merge($events[$j], ['rca_role' => 'cascade', 'chain_id' => $chains[$key]['chain_id'],
				    'delta_seconds' => $delta, 'corr_score' => round($score, 2)]);
				$matched[$j] = true;
				$chains[$key]['links'][] = ['eventid' => $effect['eventid'], 'delta_seconds' => $delta, 'corr_score' => round($score, 2)];
				$chains[$key]['total_span_s'] = max($chains[$key]['total_span_s'], $delta);
			}
		}
		return array_values($chains);
	}

	private function correlationScore(array $c, array $e, array $patterns, array $by, int $delta): float {
		$s = 0.0;
		if (in_array('alert_name', $by)) {
			foreach ($patterns as $p) {
				if (fnmatch($p['cause_pattern'], $c['trigger_name'], FNM_CASEFOLD) &&
				    fnmatch($p['effect_pattern'], $e['trigger_name'], FNM_CASEFOLD) &&
				    $delta <= (int)$p['window_seconds']) { $s += 0.40 * (float)($p['confidence']??0.8); break; }
			}
		}
		if (in_array('time', $by)) $s += 0.25 * max(0, 1.0 - ($delta / 3600));
		if (in_array('hostgroup', $by) && !empty($c['customer_name']) && $c['customer_name'] === $e['customer_name']) $s += 0.20;
		if ($c['type_layer'] < $e['type_layer']) $s += 0.10;
		if (in_array('tags', $by)) {
			$ol = count(array_intersect(array_column($c['tags'],'value'), array_column($e['tags'],'value')));
			if ($ol > 0) $s += 0.05 * min(1.0, $ol / 3);
		}
		return min(1.0, $s);
	}

	private function scoreRootCause(array &$events, array $chains, array $registry): ?array {
		if (empty($chains)) return null;
		$best = null; $bestScore = -1;
		foreach ($chains as $chain) {
			$root = $chain['root_event'];
			$score = count($chain['links'])*0.20 + (6-($root['type_layer']??3))*0.15 + ((int)$root['severity']/5)*0.20;
			if ($root['delta_seconds']===0) $score += 0.30;
			foreach ($registry['alert_patterns']['patterns']??[] as $p) {
				if (fnmatch($p['cause_pattern'], $root['trigger_name'], FNM_CASEFOLD)) $score += 0.10*(float)($p['confidence']??0.5);
			}
			if ($score > $bestScore) {
				$bestScore = $score;
				$best = ['eventid'=>$root['eventid'],'hostid'=>$root['hostid'],'host'=>$root['host'],
				         'trigger'=>$root['trigger_name'],'clock'=>$root['clock'],'clock_fmt'=>$root['clock_fmt'],
				         'severity'=>$root['severity'],'type_name'=>$root['type_name'],'customer'=>$root['customer_name'],
				         'chain_id'=>$chain['chain_id'],'rca_score'=>round($score,2),'cascade_count'=>count($chain['links'])];
			}
		}
		if ($best) { foreach ($events as &$evt) { if ($evt['eventid']===$best['eventid']) { $evt['rca_role']='root_cause'; break; } } unset($evt); }
		return $best;
	}

	private function detectGaps(array $events, array $registry): array {
		$gaps = [];
		foreach ($events as $evt) {
			foreach ($registry['gap_rules']['rules']??[] as $rule) {
				if (!fnmatch($rule['trigger_pattern'], $evt['trigger_name'], FNM_CASEFOLD)) continue;
				if (!empty($rule['trigger_type']) && $evt['type']!==$rule['trigger_type']) continue;
				$we = $evt['clock']+(int)$rule['window_seconds']; $ef = false;
				foreach ($events as $eff) {
					if ($eff['clock']<$evt['clock']||$eff['clock']>$we) continue;
					if (fnmatch($rule['expected_pattern'],$eff['trigger_name'],FNM_CASEFOLD)){$ef=true;break;}
				}
				if (!$ef) $gaps[] = ['rule_id'=>$rule['id'],'trigger_event'=>$evt['eventid'],
				    'trigger_host'=>$evt['host'],'trigger_name'=>$evt['trigger_name'],
				    'expected'=>$rule['expected_pattern'],'window_s'=>$rule['window_seconds'],
				    'severity'=>$rule['gap_severity'],'message'=>$rule['message'],'clock'=>$evt['clock']];
			}
		}
		return $gaps;
	}

	private function buildSummary(array $events, array $chains, array $gaps, ?array $rootCause, int $tf, int $tt): array {
		$sev = array_column($events,'severity'); $clocks = array_column($events,'clock');
		return ['total'=>count($events),
			'disaster'=>count(array_filter($sev,fn($s)=>$s==5)),
			'high'=>count(array_filter($sev,fn($s)=>$s==4)),
			'average'=>count(array_filter($sev,fn($s)=>$s==3)),
			'warning'=>count(array_filter($sev,fn($s)=>$s==2)),
			'critical'=>count(array_filter($sev,fn($s)=>$s>=4)),
			'affected_hosts'=>count(array_unique(array_column($events,'hostid'))),
			'chain_count'=>count($chains),'gap_count'=>count($gaps),'root_identified'=>$rootCause!==null,
			'span_seconds'=>!empty($clocks)?max($clocks)-min($clocks):0,
			'span_fmt'=>!empty($clocks)?$this->formatSpan(max($clocks)-min($clocks)):'0s',
			'first_clock'=>!empty($clocks)?min($clocks):$tf,'last_clock'=>!empty($clocks)?max($clocks):$tt];
	}

	private function loadRegistry(): array {
		$file = __DIR__.'/../config/rca_registry.json';
		if (!file_exists($file)) return [];
		$d = json_decode(file_get_contents($file), true);
		return is_array($d) ? $d : [];
	}

	private function severityName(int $s): string {
		return match($s){5=>'Disaster',4=>'High',3=>'Average',2=>'Warning',1=>'Information',0=>'Not classified',default=>'Unknown'};
	}
	private function severityClass(int $s): string {
		return match($s){5=>'disaster',4=>'high',3=>'average',2=>'warning',1=>'info',0=>'nc',default=>'nc'};
	}
	private function formatSpan(int $s): string {
		if($s<60) return $s.'s'; if($s<3600) return round($s/60).'m '.($s%60).'s';
		return floor($s/3600).'h '.round(($s%3600)/60).'m';
	}
	private function emptyResponse(int $tf, int $tt): array {
		return ['hosts'=>[],'events'=>[],'chains'=>[],'root_cause'=>null,'gap_alerts'=>[],
		        'summary'=>['total'=>0,'disaster'=>0,'high'=>0,'average'=>0,'warning'=>0,'critical'=>0,
		                    'affected_hosts'=>0,'chain_count'=>0,'gap_count'=>0,'root_identified'=>false,
		                    'span_fmt'=>'0s','span_seconds'=>0,'first_clock'=>null,'last_clock'=>null],
		        'time_from'=>$tf,'time_till'=>$tt];
	}
}
