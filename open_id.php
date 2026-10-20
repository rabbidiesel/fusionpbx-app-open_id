<?php

/*
 * FusionPBX
 * Version: MPL 1.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is FusionPBX
 *
 * The Initial Developer of the Original Code is
 * Mark J Crane <markjcrane@fusionpbx.com>
 * Portions created by the Initial Developer are Copyright (C) 2008-2025
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 * Mark J Crane <markjcrane@fusionpbx.com>
 * Tim Fry <tim@fusionpbx.com>
 */

require_once dirname(__DIR__, 2) . '/resources/require.php';

//redirect to open_id authentication
if (isset($_GET['action']) && $settings->get('open_id', 'enabled', false)) {

	//decode url
	$open_id_authenticator = urldecode($_GET['action']);

	//sanitize the name like auto_loader
	$open_id_authenticator = preg_replace('[^a-zA-Z0-9_]', '', $open_id_authenticator);

	//make sure the class exists
	if (!class_exists($open_id_authenticator)) {
		exit();
	}

	//create the authenticator
	$authenticator = new $open_id_authenticator();

	//make sure it implements the open_id_authenticator
	if (!($authenticator instanceof open_id_authenticator)) {
		exit();
	}

	//remember the "Remember Me" checkbox from the login form while the user is sent to the identity provider
	if (!isset($_GET['code'])) {
		$_SESSION['open_id_remember_me'] = (($_GET['remember_me'] ?? '') === 'true');
	}

	//get the result array from the authenticator
	$result = $authenticator->authenticate();
	if (!empty($result)) {
		//create the user session
		authentication::create_user_session($result, $settings);

		//the remember me choice only applies to this login attempt
		$remember_me_requested = !empty($_SESSION['open_id_remember_me']);
		unset($_SESSION['open_id_remember_me']);

		if (!empty($result['authorized'])) {
			//issue a remember me token when requested on the login form and allowed by the login settings
			if ($remember_me_requested && $settings->get('login', 'remember_me', false) && class_exists('remember_me')) {
				$remember_me = new remember_me(['settings' => $settings]);
				$token_data = $remember_me->issue_token();
				$result['remember_selector'] = $token_data['selector'];
				$result['remember_validator'] = $token_data['hashed_validator'];
			}

			//log the successful login, this also stores the remember me token
			user_logs::add($result);
		}

		//redirect to landing page
		$landing_page = $settings->get('login', 'destination', '/core/dashboard');
		header('Location: ' . $landing_page);

		//finished successfully
		exit();
	}
}

exit;
