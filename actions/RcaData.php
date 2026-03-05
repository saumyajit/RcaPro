<?php
/**
 * RcaData — AJAX JSON endpoint.
 * Namespace: Modules\RCA\Actions
 * Zabbix 7.0+
 *
 * Pattern: output JSON directly in doAction(), tell Zabbix to respond
 * with an empty CControllerResponseData so it doesn't try to render
 * a view on top of our output.
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
			'correlate_by'      => 'array',
			'customer_groupid'  => 'string',
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
		$customerGroupId = $this->getInput('customer_groupid', '');
		$search      = $this->getInput('search', '');
		$correlateBy = $this->getInput('correlate_by', ['alert_name', 'time', 'hostgroup']);

		if ($timeTill === 0) $timeTill = time();
		if ($timeFrom === 0) $timeFrom = $timeTill - 3600;

		$debug = [
			'time_from_fmt' => date('Y-m-d H:i:s', $timeFrom),
			'time_till_fmt' => date('Y-m-d H:i:s', $timeTill),
			'server_time'   => date('Y-m-d H:i:s', time()),
			'env'           => $env,
			'customer'      => $customer,
			'correlate_by'  => $correlateBy,
		];

		try {
			$problems = $this->fetchProblems($timeFrom, $timeTill, $debug);
			$debug['problems_fetched'] = count($problems);

			// Fetch recovery events to set r_clock on resolved problems
			if (!empty($problems)) {
				$problems = $this->attachRecoveryTimes($problems, $timeFrom, $timeTill, $debug);
			}

			if (empty($problems)) {
				$resp = $this->emptyResponse($timeFrom, $timeTill);
				if (self::DEBUG) $resp['debug'] = $debug;
				$this->setResponse(new CControllerResponseData($resp));
				return;
			}

			$triggerIds     = array_unique(array_column($problems, 'objectid'));
			$triggerHostMap = $this->fetchTriggerHostMap($triggerIds);
			$debug['triggers_mapped'] = count($triggerHostMap);

			$hostIds       = array_unique(array_map(fn($h) => $h['hostid'], array_values($triggerHostMap)));
			$hostsRaw      = $this->fetchHosts($hostIds);
			$hostGroupsMap = $this->fetchHostGroupsMap($hostIds);
			$debug['hostgroups_fetched'] = array_sum(array_map('count', $hostGroupsMap));
			$hostMeta      = $this->parseHostMeta($hostsRaw, $hostGroupsMap);
			$debug['hosts_found'] = count($hostMeta);

			// Resolve customer_groupid → allowed hostid set for group-based filtering
			$allowedHostIds = $this->resolveGroupHostIds($customerGroupId, $debug);
			$problems = $this->applyFilters($problems, $triggerHostMap, $hostMeta, $env, $allowedHostIds, $search);
			$debug['after_filter'] = count($problems);

			if (empty($problems)) {
				$resp = $this->emptyResponse($timeFrom, $timeTill);
				if (self::DEBUG) $resp['debug'] = $debug;
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

		} catch (\Throwable $e) {
			$resp = $this->emptyResponse($timeFrom, $timeTill);
			$resp['error'] = $e->getMessage();
			$resp['error_file'] = basename($e->getFile()) . ':' . $e->getLine();
			$resp['debug'] = $debug;
			$this->setResponse(new CControllerResponseData($resp));
		}
	}


	// ── FETCH: tries Event API first, falls back to Problem API ──────────

	private function fetchProblems(int $timeFrom, int $timeTill, array &$debug): array {
		// Attempt 1: Event API (most reliable in Zabbix 7.0 module context)
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
			if (is_array($r) && count($r) > 0) {
				$debug['fetch_method'] = 'event_api';
				$debug['fetch_count']  = count($r);
				return array_map(fn($e) => array_merge($e, ['r_clock' => null]), $r);
			}
			$debug['event_api_count'] = is_array($r) ? 0 : 'failed';
		} catch (\Throwable $e) {
			$debug['event_api_error'] = $e->getMessage();
		}

		// Attempt 2: Problem API
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
			if (is_array($r) && count($r) > 0) {
				$debug['fetch_method'] = 'problem_api';
				$debug['fetch_count']  = count($r);
				return $r;
			}
			$debug['problem_api_count'] = is_array($r) ? 0 : 'failed';
		} catch (\Throwable $e) {
			$debug['problem_api_error'] = $e->getMessage();
		}

		// Attempt 3: Trigger API — fetch triggers currently in problem state
		try {
			$r = API::Trigger()->get([
				'output'          => ['triggerid', 'description', 'priority', 'lastchange'],
				'selectHosts'     => ['hostid', 'host', 'name'],
				'filter'          => ['value' => 1],
				'lastChangeSince' => $timeFrom,
				'lastChangeTill'  => $timeTill,
				'sortfield'       => 'lastchange',
				'sortorder'       => 'ASC',
				'limit'           => self::MAX_EVENTS,
			]);
			if (is_array($r) && count($r) > 0) {
				$debug['fetch_method'] = 'trigger_api';
				$debug['fetch_count']  = count($r);
				return array_map(fn($t) => [
					'eventid'       => 't_' . $t['triggerid'],
					'objectid'      => $t['triggerid'],
					'clock'         => $t['lastchange'],
					'name'          => $t['description'],
					'severity'      => $t['priority'],
					'acknowledged'  => '0',
					'r_eventid'     => null,
					'r_clock'       => null,
					'cause_eventid' => null,
					'tags'          => [],
				], $r);
			}
			$debug['trigger_api_count'] = is_array($r) ? 0 : 'failed';
		} catch (\Throwable $e) {
			$debug['trigger_api_error'] = $e->getMessage();
		}

		return [];
	}

	/**
	 * Fetch value=0 (recovery) events for the same triggers in the window.
	 * Match them to problem events by objectid (triggerid) to set r_clock.
	 * For problems still active (no recovery), r_clock stays null.
	 */
	private function attachRecoveryTimes(array $problems, int $timeFrom, int $timeTill, array &$debug): array {
		$triggerIds = array_unique(array_column($problems, 'objectid'));
		if (empty($triggerIds)) return $problems;

		// Strip synthetic t_ prefixes — recovery lookup only works for real trigger IDs
		$realTriggerIds = array_values(array_filter($triggerIds, fn($id) => !str_starts_with((string)$id, 't_')));
		if (empty($realTriggerIds)) return $problems;

		try {
			$recoveries = API::Event()->get([
				'output'    => ['eventid', 'objectid', 'clock'],
				'source'    => 0,
				'object'    => 0,
				'value'     => 0,   // recovery events
				'objectids' => $realTriggerIds,
				'time_from' => $timeFrom,
				'time_till' => $timeTill + 3600, // extend window to catch resolutions after till
				'sortfield' => 'clock',
				'sortorder' => 'ASC',
			]);
			$debug['recovery_events'] = is_array($recoveries) ? count($recoveries) : 'failed';
		} catch (\Throwable $e) {
			$debug['recovery_error'] = $e->getMessage();
			return $problems;
		}

		if (!is_array($recoveries) || empty($recoveries)) return $problems;

		// Build lookup: triggerid → [array of recovery clocks sorted ASC]
		$recoveryMap = [];
		foreach ($recoveries as $r) {
			$recoveryMap[$r['objectid']][] = (int)$r['clock'];
		}

		// Match each problem to its nearest recovery event AFTER the problem clock
		foreach ($problems as &$p) {
			if (!empty($p['r_clock'])) continue;  // already has one (Problem API)
			$tid = $p['objectid'];
			if (!isset($recoveryMap[$tid])) continue;

			foreach ($recoveryMap[$tid] as $rClock) {
				if ($rClock > (int)$p['clock']) {
					$p['r_clock'] = $rClock;
					break;
				}
			}
		}
		unset($p);

		return $problems;
	}

	private function fetchTriggerHostMap(array $triggerIds): array {
		if (empty($triggerIds)) return [];
		// Strip synthetic t_ prefix
		$realIds = array_values(array_filter($triggerIds, fn($id) => !str_starts_with((string)$id, 't_')));
		$synIds  = array_values(array_filter($triggerIds, fn($id) =>  str_starts_with((string)$id, 't_')));

		$map = [];

		if (!empty($realIds)) {
			try {
				$triggers = API::Trigger()->get([
					'output'      => ['triggerid'],
					'triggerids'  => $realIds,
					'selectHosts' => ['hostid', 'host', 'name', 'status'],
				]);
				if (is_array($triggers)) {
					foreach ($triggers as $t) {
						if (!empty($t['hosts'])) $map[$t['triggerid']] = $t['hosts'][0];
					}
				}
			} catch (\Throwable $e) {}
		}

		// Re-map synthetic IDs: t_123 → look up triggerid 123
		foreach ($synIds as $sid) {
			$tid = substr($sid, 2);
			if (isset($map[$tid])) $map[$sid] = $map[$tid];
		}

		return $map;
	}

	private function fetchHosts(array $hostIds): array {
		if (empty($hostIds)) return [];
		try {
			$r = API::Host()->get([
				'output'   => ['hostid', 'host', 'name', 'status'],
				'hostids'  => $hostIds,
				'selectTags' => ['tag', 'value'],
			]);
			return is_array($r) ? $r : [];
		} catch (\Throwable $e) { return []; }
	}

	/**
	 * Fetch hostgroups for a set of hosts using API::HostGroup()->get().
	 * Returns map: hostid → [groupname, groupname, ...]
	 * This avoids the selectHostGroups/selectGroups key ambiguity in Zabbix 7.0.
	 */
	private function fetchHostGroupsMap(array $hostIds): array {
		if (empty($hostIds)) return [];
		try {
			$groups = API::HostGroup()->get([
				'output'  => ['groupid', 'name'],
				'hostids' => $hostIds,
				'selectHosts' => ['hostid'],
			]);
			if (!is_array($groups)) return [];

			$map = [];
			foreach ($groups as $group) {
				// Zabbix may return "0" (string) instead of [] for empty relations — skip
				$hosts = $group['hosts'] ?? [];
				if (!is_array($hosts)) continue;
				foreach ($hosts as $host) {
					if (!is_array($host)) continue; // extra guard
					$map[$host['hostid']][] = $group['name'];
				}
			}
			return $map;
		} catch (\Throwable $e) { return []; }
	}

	private function parseHostMeta(array $hostsRaw, array $hostGroupsMap = []): array {
		$parser = new HostnameParser();
		$meta   = [];
		foreach ($hostsRaw as $host) {
			$groups                = $hostGroupsMap[$host['hostid']] ?? [];
			$parsed                = $parser->parse($host['host'], $groups);
			$meta[$host['hostid']] = array_merge($parsed, [
				'hostid'     => $host['hostid'],
				'host'       => $host['host'],
				'name'       => $host['name'],
				'hostgroups' => $groups,
				'tags'       => $host['tags'] ?? [],
			]);
		}
		return $meta;
	}


	/**
	 * Given a groupid string, return the set of hostids in that group.
	 * Returns null if no groupid specified (meaning: no filter, all hosts allowed).
	 */
	private function resolveGroupHostIds(string $groupId, array &$debug): ?array {
		if ($groupId === '') return null; // no filter

		try {
			$hosts = API::Host()->get([
				'output'   => ['hostid'],
				'groupids' => [$groupId],
			]);
			$ids = is_array($hosts) ? array_column($hosts, 'hostid') : [];
			$debug['customer_group_hostids'] = count($ids);
			return $ids;
		} catch (\Throwable $e) {
			$debug['customer_group_error'] = $e->getMessage();
			return null;
		}
	}

	private function applyFilters(array $problems, array $triggerHostMap, array $hostMeta,
	                               string $env, ?array $allowedHostIds, string $search): array {
		return array_values(array_filter($problems, function($p)
		       use ($triggerHostMap, $hostMeta, $env, $allowedHostIds, $search) {
			if ((int)$p['severity'] < 2) return false;
			$host = $triggerHostMap[$p['objectid']] ?? null;
			if (!$host) return false;
			$meta = $hostMeta[$host['hostid']] ?? [];

			if ($env && ($meta['env'] ?? '') !== $env) return false;

			// Group-based filter: check hostid is in the resolved group set
			if ($allowedHostIds !== null && !in_array($host['hostid'], $allowedHostIds, true)) {
				return false;
			}

			if ($search) {
				$hay = strtolower(
					($host['host'] ?? '') . ' ' .
					($p['name']    ?? '') . ' ' .
					implode(' ', $meta['hostgroups'] ?? [])
				);
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
				$events[$j]['rca_role'] = 'cascade';
				$events[$j]['chain_id'] = $chains[$key]['chain_id'];
				$events[$j]['delta_seconds'] = $delta;
				$events[$j]['corr_score'] = round($score, 2);
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
				if (fnmatch($p['cause_pattern'],$c['trigger_name'],FNM_CASEFOLD) &&
				    fnmatch($p['effect_pattern'],$e['trigger_name'],FNM_CASEFOLD) &&
				    $delta<=(int)$p['window_seconds']) { $s+=0.40*(float)($p['confidence']??0.8); break; }
			}
		}
		if (in_array('time',$by))      $s += 0.25*max(0,1.0-($delta/3600));
		if (in_array('hostgroup',$by) && !empty($c['customer_name']) && $c['customer_name']===$e['customer_name']) $s += 0.20;
		if ($c['type_layer'] < $e['type_layer']) $s += 0.10;
		if (in_array('tags',$by)) {
			$ol = count(array_intersect(array_column($c['tags'],'value'),array_column($e['tags'],'value')));
			if ($ol>0) $s += 0.05*min(1.0,$ol/3);
		}
		return min(1.0,$s);
	}

	private function scoreRootCause(array &$events, array $chains, array $registry): ?array {
		if (empty($chains)) return null;
		$best = null; $bestScore = -1;
		foreach ($chains as $chain) {
			$root = $chain['root_event'];
			$score = count($chain['links'])*0.20+(6-($root['type_layer']??3))*0.15+((int)$root['severity']/5)*0.20;
			if ($root['delta_seconds']===0) $score+=0.30;
			foreach ($registry['alert_patterns']['patterns']??[] as $p) {
				if (fnmatch($p['cause_pattern'],$root['trigger_name'],FNM_CASEFOLD)) $score+=0.10*(float)($p['confidence']??0.5);
			}
			if ($score>$bestScore) {
				$bestScore=$score;
				$best=['eventid'=>$root['eventid'],'hostid'=>$root['hostid'],'host'=>$root['host'],
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
				if (!fnmatch($rule['trigger_pattern'],$evt['trigger_name'],FNM_CASEFOLD)) continue;
				if (!empty($rule['trigger_type'])&&$evt['type']!==$rule['trigger_type']) continue;
				$we=$evt['clock']+(int)$rule['window_seconds']; $ef=false;
				foreach ($events as $eff) {
					if ($eff['clock']<$evt['clock']||$eff['clock']>$we) continue;
					if (fnmatch($rule['expected_pattern'],$eff['trigger_name'],FNM_CASEFOLD)){$ef=true;break;}
				}
				if (!$ef) $gaps[]=(['rule_id'=>$rule['id'],'trigger_event'=>$evt['eventid'],
				    'trigger_host'=>$evt['host'],'trigger_name'=>$evt['trigger_name'],
				    'expected'=>$rule['expected_pattern'],'window_s'=>$rule['window_seconds'],
				    'severity'=>$rule['gap_severity'],'message'=>$rule['message'],'clock'=>$evt['clock']]);
			}
		}
		return $gaps;
	}

	private function buildSummary(array $events, array $chains, array $gaps, ?array $rc, int $tf, int $tt): array {
		$sev=$c=array_column($events,'severity'); $clocks=array_column($events,'clock');
		return ['total'=>count($events),
			'disaster'=>count(array_filter($sev,fn($s)=>$s==5)),
			'high'=>count(array_filter($sev,fn($s)=>$s==4)),
			'average'=>count(array_filter($sev,fn($s)=>$s==3)),
			'warning'=>count(array_filter($sev,fn($s)=>$s==2)),
			'critical'=>count(array_filter($sev,fn($s)=>$s>=4)),
			'affected_hosts'=>count(array_unique(array_column($events,'hostid'))),
			'chain_count'=>count($chains),'gap_count'=>count($gaps),'root_identified'=>$rc!==null,
			'span_seconds'=>!empty($clocks)?max($clocks)-min($clocks):0,
			'span_fmt'=>!empty($clocks)?$this->formatSpan(max($clocks)-min($clocks)):'0s',
			'first_clock'=>!empty($clocks)?min($clocks):$tf,'last_clock'=>!empty($clocks)?max($clocks):$tt];
	}

	private function loadRegistry(): array {
		$f=__DIR__.'/../config/rca_registry.json';
		if (!file_exists($f)) return [];
		$d=json_decode(file_get_contents($f),true);
		return is_array($d)?$d:[];
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
