/**
 * RCA Module — Frontend JS
 * Handles: data fetching, timeline rendering, detail panel,
 *          matrix view, registry management (super admin).
 * No external dependencies beyond what Zabbix already loads.
 */

(function () {
	'use strict';

	// ── STATE ────────────────────────────────────────────────────────────
	const RCA = {
		config:       window.RCA_CONFIG || {},
		currentData:  null,
		selectedEvent:null,
		currentTab:   'event',
		currentView:  'timeline',
		activeMinutes: 60,
		correlateBy:  ['alert_name', 'time', 'hostgroup'],
	};

	// ── INIT ─────────────────────────────────────────────────────────────
	document.addEventListener('DOMContentLoaded', () => {
		bindFilterBar();
		bindViewTabs();
		bindDetailTabs();
		bindAnalyzeButton();
		bindDetailClose();
		initTooltip();
		// Auto-analyze on load with default 1h window
		runAnalysis();
	});

	// ── FILTER BAR ───────────────────────────────────────────────────────
	function bindFilterBar() {
		// Time presets
		document.querySelectorAll('.rca-tp').forEach(btn => {
			btn.addEventListener('click', () => {
				document.querySelectorAll('.rca-tp').forEach(b => b.classList.remove('rca-tp-active'));
				btn.classList.add('rca-tp-active');
				const min = btn.dataset.minutes;
				if (min === 'custom') {
					document.getElementById('rca-custom-range').style.display = 'flex';
					RCA.activeMinutes = 'custom';
				} else {
					document.getElementById('rca-custom-range').style.display = 'none';
					RCA.activeMinutes = parseInt(min);
				}
			});
		});

		// Correlation tags
		document.querySelectorAll('.rca-ctag').forEach(tag => {
			tag.addEventListener('click', () => {
				tag.classList.toggle('rca-ctag-on');
				RCA.correlateBy = Array.from(document.querySelectorAll('.rca-ctag.rca-ctag-on'))
					.map(t => t.dataset.key);
			});
		});
	}

	// ── VIEW TABS ─────────────────────────────────────────────────────────
	function bindViewTabs() {
		document.querySelectorAll('.rca-vtab').forEach(btn => {
			btn.addEventListener('click', () => {
				document.querySelectorAll('.rca-vtab').forEach(b => b.classList.remove('rca-vtab-active'));
				btn.classList.add('rca-vtab-active');
				RCA.currentView = btn.dataset.view;
				showView(RCA.currentView);
			});
		});
	}

	function showView(view) {
		['timeline','matrix','registry'].forEach(v => {
			const el = document.getElementById('view-' + v);
			if (el) el.style.display = v === view ? 'flex' : 'none';
		});

		if (view === 'matrix' && RCA.currentData) renderMatrix(RCA.currentData);
		if (view === 'registry') renderRegistry();
	}

	// ── ANALYZE ──────────────────────────────────────────────────────────
	function bindAnalyzeButton() {
		document.getElementById('rca-analyze-btn').addEventListener('click', runAnalysis);
	}

	async function runAnalysis() {
		const { timeFrom, timeTill } = getTimeRange();
		const env      = document.getElementById('rca-env').value;
		const customer = document.getElementById('rca-customer').value;
		const search   = document.getElementById('rca-search').value;

		setLoading(true);
		hideEmpty();
		// Clear previous error banners
		document.querySelectorAll('.rca-err-banner').forEach(e => e.remove());

		// Build params — ajax_url already contains ?action=RcaData, don't duplicate it
		const params = new URLSearchParams();
		params.set('time_from', timeFrom);
		params.set('time_till', timeTill);
		if (env)      params.set('env',    env);
		if (search)   params.set('search', search);
		// customer select value is now a groupid (numeric string from Zabbix)
		if (customer) params.set('customer_groupid', customer);

		// Correlation filters — send each active one as correlate_by[]
		const activeCorrelate = Array.from(
			document.querySelectorAll('.rca-ctag.rca-ctag-on')
		).map(el => el.dataset.key);
		activeCorrelate.forEach(c => params.append('correlate_by[]', c));
		RCA.correlateBy = activeCorrelate;

		try {
			const resp = await fetch(RCA.config.ajax_url + '&' + params.toString(), {
				headers: { 'X-Requested-With': 'XMLHttpRequest' }
			});

			// Guard: ensure response is JSON before parsing
			const contentType = resp.headers.get('content-type') || '';
			if (!contentType.includes('json') && !contentType.includes('javascript')) {
				const text = await resp.text();
				showError('Server returned non-JSON response. Check PHP logs.', { response_preview: text.substring(0, 500) });
				return;
			}

			const data = await resp.json();

			if (data.debug) console.log('[RCA Debug]', data.debug);

			if (data.error) {
				showError(data.error, data.debug || null);
				return;
			}

			RCA.currentData = data;
			renderSummary(data.summary, data.root_cause);

			if (!data.events || data.events.length === 0) {
				showNoAlerts();
				return;
			}

			renderTimeline(data);
			showView(RCA.currentView);

		} catch (e) {
			showError('Network error: ' + e.message);
		} finally {
			setLoading(false);
		}
	}

	function showNoAlerts() {
		// Show friendly empty state instead of generic error
		const empty = document.getElementById('rca-empty');
		if (empty) {
			empty.style.display = 'flex';
			empty.querySelector('.rca-empty-icon').textContent = '✅';
			empty.querySelector('.rca-empty-title').textContent = 'No Active Alerts Found';
			empty.querySelector('.rca-empty-desc').textContent =
				'No alerts matching severity Warning or above were found in the selected time window.';
		}
		// Hide all view content panels
		document.querySelectorAll('.rca-view-content').forEach(v => v.style.display = 'none');
	}

	function getTimeRange() {
		if (RCA.activeMinutes === 'custom') {
			const from = document.getElementById('rca-from').value;
			const till = document.getElementById('rca-till').value;
			return {
				timeFrom: from ? Math.floor(new Date(from).getTime() / 1000) : Math.floor(Date.now()/1000) - 3600,
				timeTill: till ? Math.floor(new Date(till).getTime() / 1000) : Math.floor(Date.now()/1000),
			};
		}
		return {
			timeFrom: Math.floor(Date.now()/1000) - (RCA.activeMinutes * 60),
			timeTill: Math.floor(Date.now()/1000),
		};
	}

	// ── SUMMARY STRIP ─────────────────────────────────────────────────────
	function renderSummary(summary, rootCause) {
		if (!summary) return;

		// 4 actionable severity levels (Information and Not classified excluded)
		const sevKeys = ['disaster', 'high', 'average', 'warning'];
		sevKeys.forEach(k => setText('sval-' + k, summary[k] ?? 0));

		// Aggregate stats
		setText('sval-hosts',  summary.affected_hosts ?? '—');
		setText('sval-chains', summary.chain_count    ?? '—');
		setText('sval-gaps',   summary.gap_count      ?? '—');
		setText('sval-span',   summary.span_fmt        ?? '—');

		const badge = document.getElementById('rca-root-badge');
		if (rootCause) {
			badge.style.display = 'flex';
			document.getElementById('rca-root-text').textContent =
				'Root: ' + truncate(rootCause.trigger, 40) + ' on ' + rootCause.host;
		} else {
			badge.style.display = 'none';
		}
	}

	// ── TIMELINE RENDER ───────────────────────────────────────────────────
	function renderTimeline(data) {
		const { events, summary, root_cause } = data;
		if (!events || events.length === 0) {
			showEmpty();
			return;
		}

		const tFrom = data.time_from;
		const tTill = data.time_till;
		const span  = tTill - tFrom || 1;

		// Update time range label
		const chip = document.getElementById('rca-incident-chip');
		chip.style.display = summary.root_identified ? 'flex' : 'none';
		setText('rca-tl-timerange', formatTime(tFrom) + ' – ' + formatTime(tTill));

		// Build ruler
		renderRuler(tFrom, tTill);

		// Group events by host
		const byHost = {};
		events.forEach(evt => {
			if (!byHost[evt.hostid]) byHost[evt.hostid] = { meta: evt, events: [] };
			byHost[evt.hostid].events.push(evt);
		});

		// Sort hosts by type layer (infrastructure first)
		const hostOrder = Object.values(byHost).sort((a,b) => a.meta.type_layer - b.meta.type_layer);

		const body = document.getElementById('rca-tl-body');
		body.innerHTML = '';

		hostOrder.forEach(({ meta, events: hostEvts }) => {
			const row = buildHostRow(meta, hostEvts, tFrom, span, root_cause);
			body.appendChild(row);
		});

		document.getElementById('view-timeline').style.display = 'flex';
		document.getElementById('rca-empty').style.display = 'none';
	}

	function renderRuler(tFrom, tTill) {
		const ruler = document.getElementById('rca-tl-ruler');
		ruler.innerHTML = '';
		const steps = 4;
		const step  = (tTill - tFrom) / steps;
		for (let i = 0; i <= steps; i++) {
			const tick = document.createElement('div');
			tick.className = 'rca-ruler-tick';
			tick.textContent = formatTime(Math.round(tFrom + i * step));
			ruler.appendChild(tick);
		}
	}

	function buildHostRow(meta, hostEvts, tFrom, span, rootCause) {
		const row = document.createElement('div');
		row.className = 'rca-host-row';
		row.dataset.hostid = meta.hostid;

		// Label
		const label = document.createElement('div');
		label.className = 'rca-host-label';

		const envBadge = meta.env_short
			? `<span class="rca-env-badge rca-env-${meta.env}">${escHtml(meta.env_short)}</span>`
			: '';
		const unresolved = meta.unresolved
			? `<span class="rca-unresolved-badge" title="Hostname partially resolved">⚠</span>`
			: '';

		label.innerHTML = `
			<div class="rca-host-name">${escHtml(meta.host)}${unresolved}</div>
			<div class="rca-host-meta">${envBadge}${escHtml(meta.customer_short || meta.customer_name || '')}${meta.type_name ? ' · ' + escHtml(meta.type_name) : ''}</div>
		`;

		// Track
		const track = document.createElement('div');
		track.className = 'rca-track';

		// Cascade marker (delta indicator)
		hostEvts.forEach(evt => {
			if (evt.delta_seconds !== null && evt.delta_seconds > 0 && evt.rca_role === 'cascade') {
				const marker = document.createElement('div');
				marker.className = 'rca-cascade-marker';
				marker.style.left = pct(evt.clock - tFrom, span);
				marker.dataset.delta = '+' + formatDelta(evt.delta_seconds);
				track.appendChild(marker);
			}
		});

		// Event blocks
		hostEvts.forEach(evt => {
			const evtEl = buildEventBlock(evt, tFrom, span, rootCause);
			track.appendChild(evtEl);

			evtEl.addEventListener('click', (e) => {
				e.stopPropagation();
				selectEvent(evt);
			});

			// Tooltip
			evtEl.addEventListener('mouseenter', (e) => showTooltip(e, evt));
			evtEl.addEventListener('mousemove',  (e) => moveTooltip(e));
			evtEl.addEventListener('mouseleave', hideTooltip);
		});

		row.appendChild(label);
		row.appendChild(track);

		row.addEventListener('click', () => {
			if (hostEvts.length > 0) selectEvent(hostEvts[0]);
		});

		return row;
	}

	function buildEventBlock(evt, tFrom, span) {
		const el = document.createElement('div');
		const leftPct = Math.max(0, ((evt.clock - tFrom) / span) * 100);

		// Width: if resolved, show duration bar; otherwise fixed minimum
		let widthPct = 5;
		if (evt.r_clock && evt.r_clock > evt.clock) {
			const dur = Math.max(0.5, ((evt.r_clock - evt.clock) / span) * 100);
			widthPct  = Math.min(60, dur);
		}

		// Resolved events get green OK styling
		const isResolved = evt.r_clock && evt.r_clock > 0;
		const sevClass   = isResolved ? 'rca-evt-ok' : severityCls(evt.severity);

		el.className     = 'rca-evt ' + sevClass;
		el.style.left    = leftPct + '%';
		el.style.width   = widthPct + '%';
		el.dataset.eventid = evt.eventid;

		// Root cause crown
		if (evt.rca_role === 'root_cause') {
			el.classList.add('rca-evt-root');
			const crown = document.createElement('span');
			crown.className   = 'rca-evt-root-icon';
			crown.textContent = '★';
			el.appendChild(crown);
		}

		// Resolved badge
		if (isResolved) {
			const ok = document.createElement('span');
			ok.className   = 'rca-evt-ok-badge';
			ok.textContent = '✓ OK';
			el.appendChild(ok);
		}

		const label = document.createElement('span');
		label.className   = 'rca-evt-label';
		label.textContent = (evt.type_icon ? evt.type_icon + ' ' : '') + evt.trigger_name;
		el.appendChild(label);

		return el;
	}

	// ── EVENT SELECTION → DETAIL PANEL ────────────────────────────────────
	function selectEvent(evt) {
		RCA.selectedEvent = evt;

		// Highlight row and event
		document.querySelectorAll('.rca-host-row').forEach(r => r.classList.remove('rca-row-selected'));
		document.querySelectorAll('.rca-evt').forEach(e => e.classList.remove('rca-evt-selected'));

		const evtEl = document.querySelector(`.rca-evt[data-eventid="${evt.eventid}"]`);
		if (evtEl) {
			evtEl.classList.add('rca-evt-selected');
			evtEl.closest('.rca-host-row')?.classList.add('rca-row-selected');
		}

		// Open panel (push timeline to 70%)
		openDetailPanel();
		renderDetailTab(RCA.currentTab, evt);
	}

	function openDetailPanel() {
		const panel  = document.getElementById('rca-detail-panel');
		const layout = document.getElementById('rca-tl-layout');
		panel.style.display = 'flex';
		layout.classList.add('rca-detail-open');
	}

	function closeDetailPanel() {
		const panel  = document.getElementById('rca-detail-panel');
		const layout = document.getElementById('rca-tl-layout');
		panel.style.display = 'none';
		layout.classList.remove('rca-detail-open');
		document.querySelectorAll('.rca-evt').forEach(e => e.classList.remove('rca-evt-selected'));
		document.querySelectorAll('.rca-host-row').forEach(r => r.classList.remove('rca-row-selected'));
	}

	function bindDetailClose() {
		document.getElementById('rca-detail-close').addEventListener('click', closeDetailPanel);
	}

	// ── DETAIL TABS ──────────────────────────────────────────────────────
	function bindDetailTabs() {
		document.getElementById('rca-detail-tabs').addEventListener('click', (e) => {
			const btn = e.target.closest('.rca-dtab');
			if (!btn) return;
			document.querySelectorAll('.rca-dtab').forEach(b => b.classList.remove('rca-dtab-active'));
			btn.classList.add('rca-dtab-active');
			RCA.currentTab = btn.dataset.tab;
			if (RCA.selectedEvent) renderDetailTab(RCA.currentTab, RCA.selectedEvent);
		});
	}

	function renderDetailTab(tab, evt) {
		const body = document.getElementById('rca-detail-body');
		const data = RCA.currentData;

		switch (tab) {
			case 'event':  body.innerHTML = renderEventTab(evt, data); break;
			case 'chain':  body.innerHTML = renderChainTab(evt, data); break;
			case 'gaps':   body.innerHTML = renderGapsTab(data); break;
			case 'map':    body.innerHTML = renderMapTab(evt, data); break;
		}

		// Bind action buttons
		body.querySelector('#rca-open-zabbix')?.addEventListener('click', () => {
			window.open('zabbix.php?action=problem.view&eventid=' + evt.eventid, '_blank');
		});
	}

	// ── EVENT TAB ─────────────────────────────────────────────────────────
	function renderEventTab(evt, data) {
		const rootCause = data.root_cause;
		const isRoot    = evt.rca_role === 'root_cause';
		const dotCls    = 'rca-sev-dot-' + (evt.severity_class || 'nc');

		// Find matching registry pattern
		let patternHtml = '';
		const registry  = data; // pattern data isn't in data directly; we show from root_cause context
		if (isRoot) {
			patternHtml = `
				<div class="rca-section-title">Registry Pattern Match</div>
				<div class="rca-gap-alert" style="background:rgba(255,107,107,.07);border-color:rgba(255,107,107,.3)">
					<div class="rca-gap-icon">⚡</div>
					<div>
						<div class="rca-gap-title" style="color:var(--rca-critical)">Root Cause — RCA Score: ${rootCause?.rca_score ?? '—'}</div>
						<div class="rca-gap-desc">${rootCause?.cascade_count ?? 0} downstream cascades identified</div>
					</div>
				</div>`;
		}

		// Tags HTML
		const tagsHtml = (evt.tags || [])
			.map(t => `<span class="rca-tag"><b>${escHtml(t.tag)}:</b>${escHtml(t.value)}</span>`)
			.join('') || '<span style="color:var(--rca-text3);font-size:11px">No tags</span>';

		return `
		<div class="rca-evt-hdr">
			<div class="rca-sev-dot ${dotCls}"></div>
			<div>
				<div class="rca-evt-title">${escHtml(evt.type_icon || '')} ${escHtml(evt.trigger_name)}</div>
				<div class="rca-evt-subline">${escHtml(evt.host)} · ${escHtml(evt.type_name || '')} · ${escHtml(evt.customer_name || '')} · ${escHtml(evt.env_short || '')}</div>
			</div>
		</div>

		<div class="rca-kv-grid">
			<div class="rca-kv"><div class="rca-kv-k">Severity</div><div class="rca-kv-v rca-${evt.severity>=4?'crit':evt.severity>=2?'warn':'ok'}">${escHtml(evt.severity_name)}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Status</div><div class="rca-kv-v ${evt.r_clock ? 'rca-ok' : 'rca-crit'}">${evt.r_clock ? '✓ RESOLVED' : '● PROBLEM'}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Triggered</div><div class="rca-kv-v">${escHtml(evt.clock_fmt)}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Resolved At</div>
				<div class="rca-kv-v ${evt.r_clock ? 'rca-ok' : 'rca-text3'}">${evt.r_clock ? formatTime(evt.r_clock) : '—'}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Error Duration</div>
				<div class="rca-kv-v ${evt.r_clock ? '' : 'rca-text3'}">${evt.r_clock ? formatDuration(evt.r_clock - evt.clock) : '—'}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Event ID</div><div class="rca-kv-v">#${escHtml(String(evt.eventid))}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Chain</div><div class="rca-kv-v">${escHtml(evt.chain_id || 'None')}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">RCA Role</div><div class="rca-kv-v rca-${isRoot?'crit':'info'}">${isRoot?'★ ROOT CAUSE': escHtml(evt.rca_role || 'cascade')}</div></div>
		</div>

		<div class="rca-section-title">Host Metadata</div>
		<div class="rca-kv-grid">
			<div class="rca-kv"><div class="rca-kv-k">Environment</div><div class="rca-kv-v rca-${evt.env_color}">${escHtml(evt.env_name || evt.env_short || '—')}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Customer</div><div class="rca-kv-v">${escHtml(evt.customer_name || '—')}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Product</div><div class="rca-kv-v">${escHtml(evt.product_name || '—')}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Server Type</div><div class="rca-kv-v">${escHtml(evt.type_name || '—')}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Parse Source</div><div class="rca-kv-v" style="font-size:10px">${escHtml(evt.parse_source || '—')}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Confidence</div><div class="rca-kv-v">${Math.round((evt.parse_confidence||0)*100)}%</div></div>
		</div>

		<div class="rca-section-title">Tags</div>
		<div class="rca-tag-row">${tagsHtml}</div>

		${patternHtml}

		<div class="rca-action-row">
			<button id="rca-open-zabbix" class="rca-action-link">Open in Zabbix ↗</button>
			<button class="rca-action-link" style="color:var(--rca-text2)" onclick="navigator.clipboard?.writeText('${evt.eventid}')">Copy ID</button>
		</div>`;
	}

	// ── CHAIN TAB ─────────────────────────────────────────────────────────
	function renderChainTab(evt, data) {
		const chains = data.chains || [];
		if (chains.length === 0) return '<div style="color:var(--rca-text3);padding:20px;text-align:center">No cascade chains detected in this window.</div>';

		// Find the chain this event belongs to
		const myChain = chains.find(c => c.chain_id === evt.chain_id)
			|| chains.find(c => c.root_event?.eventid === evt.eventid)
			|| chains[0];

		const allEvents = data.events || [];

		let html = `<div class="rca-section-title" style="margin-top:0">Cascade sequence · ${chains.length} chain(s)</div>`;

		chains.forEach(chain => {
			const root  = chain.root_event;
			const links = chain.links || [];
			const isActive = chain.chain_id === evt.chain_id;

			html += `<div class="rca-chain-list" style="margin-bottom:14px;${isActive?'':'opacity:.6'}">`;

			// Root
			html += `
			<div class="rca-chain-item rca-chain-root" onclick="">
				<div class="rca-chain-icon">★</div>
				<div class="rca-chain-info">
					<div class="rca-chain-name">${escHtml(root.trigger_name)}</div>
					<div class="rca-chain-host">${escHtml(root.host)} · ${escHtml(root.type_name || '')}</div>
				</div>
				<div class="rca-chain-time">${escHtml(root.clock_fmt)}</div>
				<span class="rca-badge rca-badge-root">ROOT</span>
			</div>`;

			links.forEach(link => {
				const lEvt = allEvents.find(e => e.eventid === link.eventid);
				if (!lEvt) return;
				const isFocus = lEvt.eventid === evt.eventid;

				html += `<div class="rca-chain-connector"></div>`;
				html += `
				<div class="rca-chain-item ${isFocus?'rca-chain-focus':''}">
					<div class="rca-chain-icon">${escHtml(lEvt.type_icon || '🔸')}</div>
					<div class="rca-chain-info">
						<div class="rca-chain-name">${escHtml(lEvt.trigger_name)}</div>
						<div class="rca-chain-host">${escHtml(lEvt.host)} · ${escHtml(lEvt.type_name || '')}</div>
					</div>
					<div class="rca-chain-time">+${formatDelta(link.delta_seconds)}</div>
					<span class="rca-badge rca-badge-casc">CASCADE</span>
				</div>`;
			});

			// Confidence bars
			html += `</div>`;
		});

		// Confidence summary
		html += `<div class="rca-section-title">Correlation confidence</div>`;
		chains.forEach(chain => {
			(chain.links || []).forEach(link => {
				const lEvt = (data.events || []).find(e => e.eventid === link.eventid);
				if (!lEvt) return;
				const pct = Math.round((link.corr_score || 0) * 100);
				const col = pct >= 70 ? 'var(--rca-ok)' : pct >= 50 ? 'var(--rca-warning)' : 'var(--rca-critical)';
				html += `
				<div class="rca-conf-row">
					<span style="color:var(--rca-text2)">${escHtml(chain.root_event?.type_name||'')} → ${escHtml(lEvt.type_name||'')}</span>
					<span style="color:${col}">${pct}%</span>
				</div>
				<div class="rca-conf-bar"><div class="rca-conf-fill" style="width:${pct}%;background:${col}"></div></div>`;
			});
		});

		return html;
	}

	// ── GAPS TAB ──────────────────────────────────────────────────────────
	function renderGapsTab(data) {
		const gaps = data.gap_alerts || [];
		if (gaps.length === 0) {
			return '<div style="color:var(--rca-text3);padding:20px;text-align:center">No gaps detected. All expected alert patterns fired within their windows.</div>';
		}

		let html = `<div class="rca-section-title" style="margin-top:0">${gaps.length} gap(s) detected</div>`;

		gaps.forEach(gap => {
			const isPurple = gap.severity === 'info';
			html += `
			<div class="rca-gap-alert ${isPurple?'rca-gap-purple':''}">
				<div class="rca-gap-icon">${gap.severity === 'warning' ? '🔍' : '⚡'}</div>
				<div>
					<div class="rca-gap-title ${isPurple?'rca-gap-purple-title':''}">${escHtml(gap.message.split('.')[0])}</div>
					<div class="rca-gap-desc">${escHtml(gap.message)}<br><span style="color:var(--rca-text3)">Host: ${escHtml(gap.trigger_host)} · window: ${gap.window_s}s</span></div>
				</div>
			</div>`;
		});

		html += `
		<div class="rca-section-title">Train registry with this incident</div>
		<div style="font-size:11px;color:var(--rca-text2);margin-bottom:10px">
			Confirming gaps as real missed alerts will increase pattern confidence over time.
		</div>
		<button class="rca-btn-primary" onclick="RCA_UI.trainIncident()">＋ Train Registry</button>`;

		return html;
	}

	// ── MAP TAB ───────────────────────────────────────────────────────────
	function renderMapTab(evt, data) {
		const events  = data.events || [];
		const affectedTypes = [...new Set(events.map(e => e.type))];

		// Layer order for display
		const layerMap = { '07':'storage','03':'db','04':'db','02':'app','06':'app','01':'web','05':'lb' };
		const icons    = { '07':'STG','03':'DB','04':'ODB','02':'APP','06':'CTX','01':'WEB','05':'LB' };
		const dcClass  = { '07':'rca-dc-storage','03':'rca-dc-db','04':'rca-dc-db','02':'rca-dc-app','06':'rca-dc-citrix','01':'rca-dc-web','05':'rca-dc-lb' };

		const chain = [
			{ types: ['07'],     label: 'Storage' },
			{ types: ['03','04'],label: 'Database' },
			{ types: ['02','06'],label: 'App/Citrix' },
			{ types: ['01'],     label: 'Web' },
			{ types: ['05'],     label: 'Load Balancer' },
		];

		let nodesHtml = '<div class="rca-dep-row">';
		let first = true;

		chain.forEach(tier => {
			const tierTypes = tier.types.filter(t => affectedTypes.includes(t));
			if (tierTypes.length === 0) return;

			if (!first) nodesHtml += '<div class="rca-dep-arrow rca-dep-hot">→</div>';
			first = false;

			tierTypes.forEach(t => {
				const isAffected = events.some(e => e.type === t);
				const isRoot     = data.root_cause && data.root_cause.type_name && events.find(e=>e.type===t && e.rca_role==='root_cause');
				nodesHtml += `
				<div class="rca-dep-node">
					<div class="rca-dep-circle ${dcClass[t]||'rca-dc-app'} ${isAffected?'rca-dc-affected':''}">${icons[t]||'?'}</div>
					<div class="rca-dep-label">${escHtml(tier.label)}<br>${isRoot?'<span style="color:var(--rca-critical)">★ ROOT</span>':(isAffected?'<span style="color:var(--rca-warning)">affected</span>':'')}</div>
				</div>`;
			});
		});
		nodesHtml += '</div>';

		// Hostname decode table
		const sample = evt;
		const decodeHtml = `
		<div class="rca-section-title">Hostname decode</div>
		<div class="rca-kv-grid">
			<div class="rca-kv"><div class="rca-kv-k">Raw hostname</div><div class="rca-kv-v" style="font-family:var(--rca-mono);font-size:10px">${escHtml(sample.host)}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Decoded</div><div class="rca-kv-v" style="font-size:10px">${escHtml(sample.display_name)}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Parse method</div><div class="rca-kv-v" style="font-size:10px">${escHtml(sample.parse_source)}</div></div>
			<div class="rca-kv"><div class="rca-kv-k">Confidence</div><div class="rca-kv-v">${Math.round((sample.parse_confidence||0)*100)}%</div></div>
		</div>`;

		return `
		<div class="rca-section-title" style="margin-top:0">Dependency path · ${escHtml(evt.customer_name||'')}</div>
		<div class="rca-dep-map">${nodesHtml}</div>
		${decodeHtml}`;
	}

	// ── MATRIX VIEW ───────────────────────────────────────────────────────
	function renderMatrix(data) {
		const wrap   = document.getElementById('rca-matrix-wrap');
		const events = data.events || [];
		const tFrom  = data.time_from;
		const tTill  = data.time_till;

		if (events.length === 0) {
			wrap.innerHTML = '<div class="rca-empty-desc" style="padding:40px;text-align:center">No events to display in matrix.</div>';
			return;
		}

		// Build time buckets (12 columns)
		const COLS   = 12;
		const step   = (tTill - tFrom) / COLS;
		const hosts  = [...new Set(events.map(e => e.host))];

		let html = '<table class="rca-matrix-table"><thead><tr><th>Host</th>';
		for (let i = 0; i < COLS; i++) {
			html += `<th>${formatTime(Math.round(tFrom + i * step))}</th>`;
		}
		html += '</tr></thead><tbody>';

		// Build table using DOM (not innerHTML) so click handlers work
		const table = document.createElement('table');
		table.className = 'rca-matrix-table';

		// Header
		const thead = table.createTHead();
		const hRow  = thead.insertRow();
		hRow.insertCell().textContent = 'Host';
		for (let i = 0; i < COLS; i++) {
			const th = document.createElement('th');
			th.textContent = formatTime(Math.round(tFrom + i * step));
			hRow.appendChild(th);
		}

		// Body
		const tbody = table.createTBody();
		hosts.forEach(host => {
			const hostEvts = events.filter(e => e.host === host);
			const tr       = tbody.insertRow();
			const nameTd   = tr.insertCell();
			nameTd.textContent = host;
			nameTd.style.cssText = 'padding:2px 8px;color:var(--rca-text2);font-size:11px;white-space:nowrap';

			for (let i = 0; i < COLS; i++) {
				const bucketStart = tFrom + i * step;
				const bucketEnd   = bucketStart + step;
				const inBucket    = hostEvts.filter(e => e.clock >= bucketStart && e.clock < bucketEnd);
				const maxSev      = inBucket.reduce((m, e) => Math.max(m, e.severity), 0);

				const td   = tr.insertCell();
				const cell = document.createElement('div');
				cell.className = 'rca-matrix-cell rca-mc-' + maxSev;
				cell.title     = inBucket.length + ' event(s) — click to view in timeline';

				if (inBucket.length > 0) {
					cell.style.cursor = 'pointer';
					cell.addEventListener('click', () => {
						// Switch to timeline, scroll to / highlight events in this bucket
						showView('timeline');
						document.querySelector('[data-view="timeline"]')?.classList.add('rca-vtab-active');
						document.querySelectorAll('[data-view]').forEach(b => {
							b.classList.toggle('rca-vtab-active', b.dataset.view === 'timeline');
						});
						RCA.currentView = 'timeline';

						// Highlight matching event blocks in the timeline
						document.querySelectorAll('.rca-evt').forEach(el => {
							const evtId  = el.dataset.eventid;
							const match  = inBucket.find(e => e.eventid == evtId);
							el.classList.toggle('rca-matrix-highlight', !!match);
						});

						// Auto-select first event in bucket if only one
						if (inBucket.length === 1) selectEvent(inBucket[0]);

						// Remove highlight after 3s
						setTimeout(() => {
							document.querySelectorAll('.rca-matrix-highlight')
								.forEach(el => el.classList.remove('rca-matrix-highlight'));
						}, 3000);
					});
				}

				td.appendChild(cell);
			}
		});

		wrap.innerHTML = '';
		wrap.appendChild(table);

		const hint = document.createElement('div');
		hint.style.cssText = 'margin-top:12px;font-size:10px;color:var(--rca-text3)';
		hint.textContent = 'Cells show max severity per time bucket. Click a highlighted cell to jump to that slot in the timeline.';
		wrap.appendChild(hint);
	}

	// ── REGISTRY VIEW (Super Admin) ───────────────────────────────────────
	async function renderRegistry() {
		if (!RCA.config.is_super_admin) {
			document.getElementById('rca-registry-wrap').innerHTML =
				'<div class="rca-empty-desc" style="padding:40px;text-align:center;color:var(--rca-critical)">Access denied — Super Admin only.</div>';
			return;
		}

		const wrap = document.getElementById('rca-registry-wrap');
		wrap.innerHTML = '<div style="color:var(--rca-text3);padding:20px">Loading registry…</div>';

		try {
			const resp = await fetch(RCA.config.registry_url + '&action_type=read', {
				headers: { 'X-Requested-With': 'XMLHttpRequest' }
			});
			const result = await resp.json();
			if (result.error) { wrap.innerHTML = `<div style="color:var(--rca-critical);padding:20px">${escHtml(result.error)}</div>`; return; }

			const reg = result.data;
			wrap.innerHTML = buildRegistryHTML(reg);
			bindRegistryActions();

		} catch (e) {
			wrap.innerHTML = `<div style="color:var(--rca-critical);padding:20px">Failed to load registry: ${escHtml(e.message)}</div>`;
		}
	}

	function buildRegistryHTML(reg) {
		const patterns  = reg.alert_patterns?.patterns || [];
		const rels      = reg.ci_relationships?.relationships || [];
		const gaps      = reg.gap_rules?.rules || [];
		const trainLog  = reg.training_log?.entries || [];

		let html = `
		<div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
			<div style="font-size:13px;font-weight:700">RCA Registry</div>
			<div style="font-size:11px;color:var(--rca-text3)">v${reg._version||'1.0'} · ${reg._trained_incident_count||0} incidents trained</div>
			${reg._last_trained ? `<div style="font-size:10px;color:var(--rca-text3);margin-left:auto">Last trained: ${reg._last_trained}</div>` : ''}
		</div>`;

		// ── Alert Patterns
		html += `<div class="rca-reg-section">
		<div class="rca-reg-toolbar">
			<div class="rca-section-title" style="margin:0;border:none">Alert Cascade Patterns (${patterns.length})</div>
			<button class="rca-btn-primary" onclick="RCA_UI.openPatternModal()">＋ Add Pattern</button>
		</div>`;

		patterns.forEach(p => {
			const conf = Math.round((p.confidence||0)*100);
			const col  = conf >= 70 ? 'var(--rca-ok)' : conf >= 50 ? 'var(--rca-warning)' : 'var(--rca-critical)';
			html += `
			<div class="rca-reg-item" data-id="${escHtml(p.id)}">
				<div class="rca-reg-item-main">
					<div class="rca-reg-pattern">"${escHtml(p.cause_pattern)}" <span style="color:var(--rca-border)">→</span> "${escHtml(p.effect_pattern)}"</div>
					<div class="rca-reg-meta">
						<span>⏱ ${p.window_seconds}s window</span>
						<span>🔁 ${p.seen_count} incidents</span>
						<span style="color:${col}">confidence: ${conf}%</span>
						${p.note ? `<span style="color:var(--rca-text2)">${escHtml(p.note)}</span>` : ''}
					</div>
				</div>
				<div class="rca-reg-actions">
					<button class="rca-icon-btn" onclick="RCA_UI.editPattern('${escHtml(p.id)}')">✎ Edit</button>
					<button class="rca-icon-btn rca-btn-danger" onclick="RCA_UI.deletePattern('${escHtml(p.id)}')">✕</button>
				</div>
			</div>`;
		});
		html += '</div>';

		// ── CI Relationships
		html += `<div class="rca-reg-section">
		<div class="rca-reg-toolbar">
			<div class="rca-section-title" style="margin:0;border:none">CI Relationships (${rels.length})</div>
			<button class="rca-btn-primary" onclick="RCA_UI.openRelModal()">＋ Add Relationship</button>
		</div>`;

		rels.forEach(r => {
			html += `
			<div class="rca-reg-item" data-id="${escHtml(r.id)}">
				<div class="rca-reg-item-main">
					<div class="rca-reg-pattern">${escHtml(r.from_name||r.from_type)} <span style="color:var(--rca-border)">→</span> ${escHtml(r.to_name||r.to_type)}</div>
					<div class="rca-reg-meta">
						<span>type: ${escHtml(r.relationship)}</span>
						<span>cascade: ${r.expected_cascade_seconds}s</span>
						${r.note ? `<span>${escHtml(r.note)}</span>` : ''}
					</div>
				</div>
				<div class="rca-reg-actions">
					<button class="rca-icon-btn rca-btn-danger" onclick="RCA_UI.deleteRel('${escHtml(r.id)}')">✕</button>
				</div>
			</div>`;
		});
		html += '</div>';

		// ── Gap Rules
		html += `<div class="rca-reg-section">
		<div class="rca-reg-toolbar">
			<div class="rca-section-title" style="margin:0;border:none">Gap Detection Rules (${gaps.length})</div>
			<button class="rca-btn-primary" onclick="RCA_UI.openGapModal()">＋ Add Gap Rule</button>
		</div>`;

		gaps.forEach(g => {
			html += `
			<div class="rca-reg-item">
				<div class="rca-reg-item-main">
					<div class="rca-reg-pattern">If "${escHtml(g.trigger_pattern)}" fires but "${escHtml(g.expected_pattern)}" does not within ${g.window_seconds}s</div>
					<div class="rca-reg-meta">
						<span>severity: ${escHtml(g.gap_severity)}</span>
						<span>${escHtml(g.message)}</span>
					</div>
				</div>
				<div class="rca-reg-actions">
					<button class="rca-icon-btn rca-btn-danger" onclick="RCA_UI.deleteGap('${escHtml(g.id)}')">✕</button>
				</div>
			</div>`;
		});
		html += '</div>';

		// ── Training log
		if (trainLog.length > 0) {
			html += `<div class="rca-reg-section"><div class="rca-section-title" style="margin-top:0">Training Log (last ${Math.min(5,trainLog.length)})</div>`;
			trainLog.slice(-5).reverse().forEach(entry => {
				html += `<div style="font-size:11px;color:var(--rca-text2);padding:6px 0;border-bottom:1px solid var(--rca-border2)">
					${entry.incident_id} — ${entry.event_count} events — by ${escHtml(entry.trained_by)} — ${new Date(entry.trained_at*1000).toLocaleString()}
				</div>`;
			});
			html += '</div>';
		}

		return html;
	}

	function bindRegistryActions() {
		// Actions bound inline via onclick — RCA_UI namespace below
	}

	// Public API for inline onclick handlers
	window.RCA_UI = {
		openPatternModal() { showModal(buildPatternModal(null)); },
		editPattern(id) {
			const reg = RCA.currentData; // simplified — in real: re-fetch or cache registry
			showModal(buildPatternModal(id));
		},
		async deletePattern(id) {
			if (!confirm('Delete pattern ' + id + '?')) return;
			await registryAction('delete_pattern', { id });
			renderRegistry();
		},
		openRelModal()  { showModal(buildRelModal()); },
		async deleteRel(id) {
			if (!confirm('Delete relationship ' + id + '?')) return;
			await registryAction('delete_relationship', { id });
			renderRegistry();
		},
		openGapModal()  { showModal(buildGapModal()); },
		async deleteGap(id) {
			if (!confirm('Delete gap rule ' + id + '?')) return;
			await registryAction('delete_gap_rule', { id });
			renderRegistry();
		},
		async trainIncident() {
			if (!RCA.currentData || !RCA.currentData.root_cause) {
				alert('No root cause identified. Analyze first, then train.');
				return;
			}
			const confirmed = confirm('Train registry with current incident data? This will update pattern confidence scores.');
			if (!confirmed) return;
			const payload = {
				incident_id:    'INC_' + Date.now(),
				confirmed_root: RCA.currentData.root_cause,
				events:         RCA.currentData.events,
				pattern_matches:[],
			};
			const result = await registryAction('train', payload);
			if (result.success) {
				alert('Registry trained. Total incidents: ' + result.trained_count);
			}
		},
	};

	async function registryAction(actionType, payload) {
		const resp = await fetch(RCA.config.registry_url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest' },
			body: new URLSearchParams({ action: 'RcaRegistry', action_type: actionType, payload: JSON.stringify(payload) }),
		});
		return resp.json();
	}

	// ── MODAL BUILDERS ────────────────────────────────────────────────────
	function buildPatternModal(id) {
		return `
		<div class="rca-modal">
			<h3>${id ? 'Edit' : 'Add'} Alert Pattern</h3>
			<div class="rca-form-row"><label class="rca-form-label">Cause pattern (glob, e.g. "Disk I/O*")</label><input class="rca-form-input" id="mp-cause" placeholder="Disk I/O latency*" /></div>
			<div class="rca-form-row"><label class="rca-form-label">Effect pattern</label><input class="rca-form-input" id="mp-effect" placeholder="MySQL slow query*" /></div>
			<div class="rca-form-row rca-form-row-2">
				<div><label class="rca-form-label">Window (seconds)</label><input class="rca-form-input" id="mp-window" type="number" value="180" /></div>
				<div><label class="rca-form-label">Initial confidence (0–1)</label><input class="rca-form-input" id="mp-conf" type="number" step="0.01" min="0" max="1" value="0.5" /></div>
			</div>
			<div class="rca-form-row rca-form-row-2">
				<div><label class="rca-form-label">Cause server type code</label><input class="rca-form-input" id="mp-ctype" placeholder="07" /></div>
				<div><label class="rca-form-label">Effect server type code</label><input class="rca-form-input" id="mp-etype" placeholder="03" /></div>
			</div>
			<div class="rca-form-row"><label class="rca-form-label">Note</label><input class="rca-form-input" id="mp-note" placeholder="Explanation…" /></div>
			<div class="rca-modal-actions">
				<button class="rca-btn-secondary" onclick="closeModal()">Cancel</button>
				<button class="rca-btn-primary" onclick="submitPatternModal('${id||''}')">Save</button>
			</div>
		</div>`;
	}

	function buildRelModal() {
		return `
		<div class="rca-modal">
			<h3>Add CI Relationship</h3>
			<div class="rca-form-row rca-form-row-2">
				<div><label class="rca-form-label">From type code</label><input class="rca-form-input" id="mr-from" placeholder="07 (Storage)" /></div>
				<div><label class="rca-form-label">From name</label><input class="rca-form-input" id="mr-fromname" placeholder="Storage" /></div>
			</div>
			<div class="rca-form-row rca-form-row-2">
				<div><label class="rca-form-label">To type code</label><input class="rca-form-input" id="mr-to" placeholder="03 (SQL DB)" /></div>
				<div><label class="rca-form-label">To name</label><input class="rca-form-input" id="mr-toname" placeholder="SQL DB" /></div>
			</div>
			<div class="rca-form-row rca-form-row-2">
				<div><label class="rca-form-label">Relationship type</label><input class="rca-form-input" id="mr-rel" placeholder="storage_dependency" /></div>
				<div><label class="rca-form-label">Expected cascade (seconds)</label><input class="rca-form-input" id="mr-secs" type="number" value="180" /></div>
			</div>
			<div class="rca-form-row"><label class="rca-form-label">Note</label><input class="rca-form-input" id="mr-note" /></div>
			<div class="rca-modal-actions">
				<button class="rca-btn-secondary" onclick="closeModal()">Cancel</button>
				<button class="rca-btn-primary" onclick="submitRelModal()">Save</button>
			</div>
		</div>`;
	}

	function buildGapModal() {
		return `
		<div class="rca-modal">
			<h3>Add Gap Detection Rule</h3>
			<div class="rca-form-row"><label class="rca-form-label">Trigger pattern (when this fires…)</label><input class="rca-form-input" id="mg-trigger" placeholder="Disk I/O latency*" /></div>
			<div class="rca-form-row"><label class="rca-form-label">Expected pattern (…and this does NOT)</label><input class="rca-form-input" id="mg-expected" placeholder="Storage*health*" /></div>
			<div class="rca-form-row rca-form-row-2">
				<div><label class="rca-form-label">Window (seconds)</label><input class="rca-form-input" id="mg-window" type="number" value="60" /></div>
				<div><label class="rca-form-label">Severity</label>
					<select class="rca-form-input" id="mg-sev"><option value="info">Info</option><option value="warning" selected>Warning</option><option value="high">High</option></select>
				</div>
			</div>
			<div class="rca-form-row"><label class="rca-form-label">Message to display</label><input class="rca-form-input" id="mg-msg" placeholder="Expected alert did not fire…" /></div>
			<div class="rca-modal-actions">
				<button class="rca-btn-secondary" onclick="closeModal()">Cancel</button>
				<button class="rca-btn-primary" onclick="submitGapModal()">Save</button>
			</div>
		</div>`;
	}

	function showModal(html) {
		const overlay = document.createElement('div');
		overlay.className = 'rca-modal-overlay';
		overlay.id = 'rca-modal-overlay';
		overlay.innerHTML = html;
		overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });
		document.body.appendChild(overlay);
	}

	window.closeModal = () => document.getElementById('rca-modal-overlay')?.remove();

	window.submitPatternModal = async (id) => {
		const payload = {
			cause_pattern:  document.getElementById('mp-cause').value,
			effect_pattern: document.getElementById('mp-effect').value,
			window_seconds: document.getElementById('mp-window').value,
			confidence:     document.getElementById('mp-conf').value,
			cause_type:     document.getElementById('mp-ctype').value,
			effect_type:    document.getElementById('mp-etype').value,
			note:           document.getElementById('mp-note').value,
		};
		if (id) payload.id = id;
		await registryAction(id ? 'update_pattern' : 'add_pattern', payload);
		closeModal();
		renderRegistry();
	};

	window.submitRelModal = async () => {
		const payload = {
			from_type: document.getElementById('mr-from').value,
			from_name: document.getElementById('mr-fromname').value,
			to_type:   document.getElementById('mr-to').value,
			to_name:   document.getElementById('mr-toname').value,
			relationship: document.getElementById('mr-rel').value,
			expected_cascade_seconds: document.getElementById('mr-secs').value,
			note:      document.getElementById('mr-note').value,
		};
		await registryAction('add_relationship', payload);
		closeModal();
		renderRegistry();
	};

	window.submitGapModal = async () => {
		const payload = {
			trigger_pattern:  document.getElementById('mg-trigger').value,
			expected_pattern: document.getElementById('mg-expected').value,
			window_seconds:   document.getElementById('mg-window').value,
			gap_severity:     document.getElementById('mg-sev').value,
			message:          document.getElementById('mg-msg').value,
		};
		await registryAction('add_gap_rule', payload);
		closeModal();
		renderRegistry();
	};

	// ── TOOLTIP ──────────────────────────────────────────────────────────
	let tooltipEl = null;

	function initTooltip() {
		tooltipEl = document.createElement('div');
		tooltipEl.className = 'rca-tooltip';
		tooltipEl.innerHTML = `
			<div class="rca-tooltip-title" id="tt-title"></div>
			<div class="rca-tooltip-row"><span>Host</span><span class="rca-tooltip-val" id="tt-host"></span></div>
			<div class="rca-tooltip-row"><span>Severity</span><span class="rca-tooltip-val" id="tt-sev"></span></div>
			<div class="rca-tooltip-row"><span>Time</span><span class="rca-tooltip-val" id="tt-time"></span></div>
			<div class="rca-tooltip-row"><span>Role</span><span class="rca-tooltip-val" id="tt-role"></span></div>`;
		document.body.appendChild(tooltipEl);
	}

	function showTooltip(e, evt) {
		if (!tooltipEl) return;
		tooltipEl.querySelector('#tt-title').textContent = evt.trigger_name;
		tooltipEl.querySelector('#tt-host').textContent  = evt.host;
		tooltipEl.querySelector('#tt-sev').textContent   = evt.severity_name;
		tooltipEl.querySelector('#tt-time').textContent  = evt.clock_fmt;
		tooltipEl.querySelector('#tt-role').textContent  = evt.rca_role || '—';
		tooltipEl.classList.add('rca-tooltip-show');
		moveTooltip(e);
	}

	function moveTooltip(e) {
		if (!tooltipEl) return;
		tooltipEl.style.left = (e.clientX + 14) + 'px';
		tooltipEl.style.top  = (e.clientY - 70) + 'px';
	}

	function hideTooltip() {
		tooltipEl?.classList.remove('rca-tooltip-show');
	}

	// ── HELPERS ──────────────────────────────────────────────────────────
	function severityCls(sev) {
		// Matches all 6 Zabbix severity levels
		switch(sev) {
			case 5: return 'rca-evt-disaster';
			case 4: return 'rca-evt-high';
			case 3: return 'rca-evt-average';
			case 2: return 'rca-evt-warning';
			case 1: return 'rca-evt-info';
			default: return 'rca-evt-nc';
		}
	}

	function pct(val, total) { return Math.max(0, Math.min(100, (val/total)*100)) + '%'; }

	function formatTime(unix) {
		const d = new Date(unix * 1000);
		return d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0') + ':' + d.getSeconds().toString().padStart(2,'0');
	}

	function formatDelta(secs) {
		if (secs < 60)   return secs + 's';
		if (secs < 3600) return Math.floor(secs/60) + 'm ' + (secs%60) + 's';
		return Math.floor(secs/3600) + 'h ' + Math.floor((secs%3600)/60) + 'm';
	}

	function truncate(str, n) { return str && str.length > n ? str.slice(0,n) + '…' : (str||''); }
	function setText(id, txt) { const el = document.getElementById(id); if (el) el.textContent = txt; }
	function escHtml(str) {
		return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
	}

	function setLoading(on) {
		document.getElementById('rca-loading').style.display = on ? 'flex' : 'none';
		document.getElementById('rca-analyze-btn').disabled = on;
	}

	function showEmpty()  { document.getElementById('rca-empty').style.display  = 'flex'; }
	function hideEmpty()  { document.getElementById('rca-empty').style.display  = 'none'; }

	function showError(msg) {
		const wrap = document.getElementById('rca-main');
		const err  = document.createElement('div');
		err.style.cssText = 'color:var(--rca-critical);padding:20px;font-size:12px';
		err.textContent   = '⚠ ' + msg;
		wrap.insertBefore(err, wrap.firstChild);
		setTimeout(() => err.remove(), 6000);
	}

})();
