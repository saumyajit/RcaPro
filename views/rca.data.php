<?php
/**
 * RCA Data view — outputs JSON for the RcaData AJAX endpoint.
 *
 * In Zabbix 7.0, the correct way to return JSON from a module action
 * is to NOT call ob_end_clean() or exit — instead let Zabbix render
 * this view normally but output only JSON content.
 *
 * The trick: this view is rendered INSIDE Zabbix's layout, but since
 * RcaData uses CControllerResponseData (not CControllerResponseFatal),
 * Zabbix renders it without the full HTML shell when the request has
 * no 'ajax_request' wrapper — so we just echo JSON cleanly.
 *
 * @var array $data  Response data from RcaData::doAction()
 */

// Remove the flawed ob_end_clean approach.
// Instead: Zabbix 7.0 modules should use CControllerResponseData
// which gets rendered by this view. We output JSON directly.
// Zabbix does NOT wrap this in HTML layout for AJAX actions.

echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
