<?php
/**
 * RCA Data view — outputs JSON response for the RcaData AJAX endpoint.
 * Zabbix MVC requires every action to have a matching view file.
 *
 * @var array $data  Response data from RcaData::doAction()
 */

// Output pure JSON — no HTML wrapper
header('Content-Type: application/json');
echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
