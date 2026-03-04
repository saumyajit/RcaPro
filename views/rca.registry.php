<?php
/**
 * RCA Registry view — outputs raw JSON for the RcaRegistry AJAX endpoint.
 *
 * @var array $data  Response data from RcaRegistry::doAction()
 */

while (ob_get_level() > 0) {
	ob_end_clean();
}

header('Content-Type: application/json; charset=utf-8');

echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);

exit;
