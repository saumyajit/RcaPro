<?php
/**
 * RCA View template — renders the full RCA module page.
 *
 * CSS/JS loaded directly here. Module.php handles menu only.
 * Module folder name detected dynamically from __DIR__ so it works
 * regardless of whether the folder is named 'rca', 'RcaPro', etc.
 *
 * @var array $data  ['is_super_admin', 'environments', 'customers']
 */

$isSuperAdmin = $data['is_super_admin'] ?? false;
$environments = $data['environments']   ?? [];
$customers    = $data['customers']      ?? [];

// Detect module folder name dynamically — views/ is one level inside the module root
// __DIR__ = /usr/share/zabbix/modules/RcaPro/views
// dirname(__DIR__) = /usr/share/zabbix/modules/RcaPro
// basename(dirname(__DIR__)) = RcaPro
$moduleId  = basename(dirname(__DIR__));
$assetBase = 'modules/' . $moduleId . '/assets';

$ajaxUrl     = (new CUrl('zabbix.php'))->setArgument('action', 'RcaData')->getUrl();
$registryUrl = (new CUrl('zabbix.php'))->setArgument('action', 'RcaRegistry')->getUrl();

$jsConfig = json_encode([
	'is_super_admin' => $isSuperAdmin,
	'ajax_url'       => $ajaxUrl,
	'registry_url'   => $registryUrl,
], JSON_HEX_TAG | JSON_HEX_AMP);
?>
<link rel="stylesheet" type="text/css" href="<?= $assetBase ?>/css/rca.css">

<div id="rca-module" class="rca-wrap">

	<!-- FILTER BAR -->
	<div class="rca-filterbar" id="rca-filterbar">
		<div class="rca-filter-group">
			<span class="rca-filter-label"><?= _('Window') ?></span>
			<div class="rca-time-presets" id="rca-time-presets">
				<button class="rca-tp" data-minutes="10">10m</button>
				<button class="rca-tp" data-minutes="30">30m</button>
				<button class="rca-tp rca-tp-active" data-minutes="60">1h</button>
				<button class="rca-tp" data-minutes="180">3h</button>
				<button class="rca-tp" data-minutes="360">6h</button>
				<button class="rca-tp" data-minutes="720">12h</button>
				<button class="rca-tp" data-minutes="custom"><?= _('Custom') ?></button>
			</div>
			<div class="rca-custom-range" id="rca-custom-range" style="display:none">
				<input type="datetime-local" id="rca-from" class="rca-input" />
				<span style="color:var(--rca-text3)">→</span>
				<input type="datetime-local" id="rca-till" class="rca-input" />
			</div>
		</div>

		<div class="rca-filter-sep-v"></div>

		<div class="rca-filter-group">
			<span class="rca-filter-label"><?= _('Correlate') ?></span>
			<div class="rca-corr-tags" id="rca-corr-tags">
				<span class="rca-ctag rca-ctag-on" data-key="alert_name"><?= _('Alert Name') ?></span>
				<span class="rca-ctag rca-ctag-on" data-key="time"><?= _('Time') ?></span>
				<span class="rca-ctag rca-ctag-on" data-key="hostgroup"><?= _('Host Group') ?></span>
				<span class="rca-ctag" data-key="trigger_deps"><?= _('Trigger Deps') ?></span>
				<span class="rca-ctag" data-key="tags"><?= _('Tags') ?></span>
			</div>
		</div>

		<div class="rca-filter-sep-v"></div>

		<div class="rca-filter-group">
			<span class="rca-filter-label"><?= _('Env') ?></span>
			<select id="rca-env" class="rca-select">
				<option value=""><?= _('All') ?></option>
				<?php foreach ($environments as $code => $env): ?>
					<option value="<?= htmlspecialchars($code) ?>"><?= htmlspecialchars($env['short'] ?? $code) ?></option>
				<?php endforeach; ?>
			</select>
		</div>

		<div class="rca-filter-group">
			<span class="rca-filter-label"><?= _('Customer') ?></span>
			<select id="rca-customer" class="rca-select">
				<option value=""><?= _('All') ?></option>
				<?php foreach ($customers as $code => $cust): ?>
					<option value="<?= htmlspecialchars($code) ?>"><?= htmlspecialchars($cust['name'] ?? $code) ?></option>
				<?php endforeach; ?>
			</select>
		</div>

		<div class="rca-filter-group">
			<input type="text" id="rca-search" class="rca-input rca-search-input"
				placeholder="<?= _('host / trigger / tag…') ?>" />
		</div>

		<div class="rca-filter-group rca-ml-auto">
			<div class="rca-view-tabs" id="rca-view-tabs">
				<button class="rca-vtab rca-vtab-active" data-view="timeline"><?= _('Timeline') ?></button>
				<button class="rca-vtab" data-view="matrix"><?= _('Matrix') ?></button>
				<?php if ($isSuperAdmin): ?>
					<button class="rca-vtab" data-view="registry"><?= _('Registry') ?></button>
				<?php endif; ?>
			</div>
			<button id="rca-analyze-btn" class="rca-btn-analyze"><?= _('▶ Analyze') ?></button>
		</div>
	</div>

	<!-- SUMMARY STRIP -->
	<div class="rca-summary-strip" id="rca-summary">
		<div class="rca-stat"><div class="rca-stat-val rca-crit" id="sval-critical">—</div><div class="rca-stat-label"><?= _('Critical') ?></div></div>
		<div class="rca-stat"><div class="rca-stat-val rca-warn" id="sval-warning">—</div><div class="rca-stat-label"><?= _('Warning') ?></div></div>
		<div class="rca-stat"><div class="rca-stat-val rca-info" id="sval-hosts">—</div><div class="rca-stat-label"><?= _('Affected Hosts') ?></div></div>
		<div class="rca-stat"><div class="rca-stat-val rca-purple" id="sval-chains">—</div><div class="rca-stat-label"><?= _('Cascade Chains') ?></div></div>
		<div class="rca-stat"><div class="rca-stat-val rca-teal" id="sval-gaps">—</div><div class="rca-stat-label"><?= _('Gap Detections') ?></div></div>
		<div class="rca-stat"><div class="rca-stat-val rca-ok" id="sval-span">—</div><div class="rca-stat-label"><?= _('First→Last Span') ?></div></div>
		<div class="rca-root-badge" id="rca-root-badge" style="display:none">
			<span class="rca-root-icon">⚑</span>
			<span id="rca-root-text"><?= _('Root cause identified') ?></span>
		</div>
	</div>

	<!-- MAIN AREA -->
	<div class="rca-main" id="rca-main">

		<div class="rca-loading" id="rca-loading" style="display:none">
			<div class="rca-spinner"></div>
			<div class="rca-loading-text"><?= _('Analyzing alerts…') ?></div>
		</div>

		<div class="rca-empty" id="rca-empty">
			<div class="rca-empty-icon">🔍</div>
			<div class="rca-empty-title"><?= _('No analysis yet') ?></div>
			<div class="rca-empty-desc"><?= _('Select a time window and click Analyze to start Root Cause Analysis.') ?></div>
		</div>

		<!-- TIMELINE VIEW -->
		<div class="rca-view-content" id="view-timeline" style="display:none">
			<div class="rca-tl-layout" id="rca-tl-layout">
				<div class="rca-tl-panel" id="rca-tl-panel">
					<div class="rca-tl-header">
						<span class="rca-panel-title"><?= _('Trigger Timeline') ?></span>
						<div class="rca-tl-header-right">
							<span class="rca-chip rca-chip-active" id="rca-incident-chip" style="display:none"><?= _('INCIDENT ACTIVE') ?></span>
							<span class="rca-tl-timerange" id="rca-tl-timerange"></span>
						</div>
					</div>
					<div class="rca-tl-ruler-wrap" id="rca-tl-ruler"></div>
					<div class="rca-tl-body" id="rca-tl-body"></div>
					<div class="rca-tl-legend">
						<div class="rca-leg-item"><div class="rca-leg-root"></div><?= _('Root Cause') ?></div>
						<div class="rca-leg-item"><div class="rca-leg-sw rca-sw-crit"></div><?= _('Critical') ?></div>
						<div class="rca-leg-item"><div class="rca-leg-sw rca-sw-warn"></div><?= _('Warning') ?></div>
						<div class="rca-leg-item"><div class="rca-leg-sw rca-sw-ok"></div><?= _('Recovery') ?></div>
						<div class="rca-leg-item rca-leg-right"><?= _('Click any event for details') ?></div>
					</div>
				</div>
				<div class="rca-detail-panel" id="rca-detail-panel" style="display:none">
					<div class="rca-detail-header">
						<div class="rca-detail-tabs" id="rca-detail-tabs">
							<button class="rca-dtab rca-dtab-active" data-tab="event"><?= _('Event') ?></button>
							<button class="rca-dtab" data-tab="chain"><?= _('Cascade Chain') ?></button>
							<button class="rca-dtab" data-tab="gaps"><?= _('Gap Detection') ?></button>
							<button class="rca-dtab" data-tab="map"><?= _('Dep Map') ?></button>
						</div>
						<button class="rca-detail-close" id="rca-detail-close" title="<?= _('Close') ?>">✕</button>
					</div>
					<div class="rca-detail-body" id="rca-detail-body"></div>
				</div>
			</div>
		</div>

		<!-- MATRIX VIEW -->
		<div class="rca-view-content" id="view-matrix" style="display:none">
			<div class="rca-matrix-wrap" id="rca-matrix-wrap"></div>
		</div>

		<!-- REGISTRY VIEW (Super Admin only) -->
		<?php if ($isSuperAdmin): ?>
		<div class="rca-view-content" id="view-registry" style="display:none">
			<div class="rca-registry-wrap" id="rca-registry-wrap"></div>
		</div>
		<?php endif; ?>

	</div>

</div>

<script type="text/javascript">window.RCA_CONFIG = <?= $jsConfig ?>;</script>
<script type="text/javascript" src="<?= $assetBase ?>/js/rca.js"></script>
