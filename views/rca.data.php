<?php
/**
 * RCA Data view — outputs raw JSON for the RcaData AJAX endpoint.
 *
 * Zabbix includes view files inside its HTML page wrapper by default.
 * We must clear the output buffer and exit to return pure JSON.
 *
 * @var array $data  Response data from RcaData::doAction()
 */

// Clear everything Zabbix has buffered (HTML doctype, headers, layout, etc.)
while (ob_get_level() > 0) {
	ob_end_clean();
}

header('Content-Type: application/json; charset=utf-8');

echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);

exit;
