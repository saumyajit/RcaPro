<?php
/**
 * RcaView — Main page controller for the RCA module.
 * Renders the full RCA page with timeline, filters, and detail panel.
 *
 * Namespace: Modules\RCA
 */

namespace Modules\RCA\Actions;

use CController;
use CControllerResponseData;
use CWebUser;

class RcaView extends CController {

	protected function init(): void {
		$this->disableCsrfValidation();
	}

	protected function checkInput(): bool {
		return true;
	}

	protected function checkPermissions(): bool {
		return CWebUser::isLoggedIn();
	}

	protected function doAction(): void {
		// Load hostname_map for filter dropdowns (env / customer lists)
		$mapFile  = __DIR__ . '/../config/hostname_map.json';
		$map      = file_exists($mapFile) ? (json_decode(file_get_contents($mapFile), true) ?? []) : [];

		$this->setResponse(new CControllerResponseData([
			'is_super_admin' => (CWebUser::getType() == \USER_TYPE_SUPER_ADMIN),
			'environments'   => $map['environments'] ?? [],
			'customers'      => $map['customers'] ?? [],
			'module_url'     => $this->getModuleUrl(),
		]));
	}

	private function getModuleUrl(): string {
		return \CWebApp::getInstance()->getRequest()->getServerName();
	}
}
