<?php
/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @file
 */

use MediaWiki\Session\SessionInfo;
use MediaWiki\Session\UserInfo;

/**
 * Session provider for apache/authz authenticated users.
 *
 * Class AuthRemoteuser
 */
class AuthRemoteuser extends MediaWiki\Session\CookieSessionProvider {

    /**
     * @param array $params Keys include:
     *  - priority: (required) Set the priority
     *  - sessionCookieName: Session cookie name. Default is '_AuthRemoteuserSession'.
     *  - sessionCookieOptions: Options to pass to WebResponse::setCookie().
     */
    public function __construct(array $params = []) {
        parent::__construct( $params );

        if ( !isset( $params['priority'] ) ) {
            throw new \InvalidArgumentException(__METHOD__ . ': priority must be specified');
        }
        if ($params['priority'] < SessionInfo::MIN_PRIORITY ||
            $params['priority'] > SessionInfo::MAX_PRIORITY
        ) {
            throw new \InvalidArgumentException(__METHOD__ . ': Invalid priority');
        }

        $this->priority = $params['priority'];
    }

	/**
	 *
	 * @param WebRequest $request
	 * @return SessionInfo
	 */
	public function provideSessionInfo( WebRequest $request ) {
		$sessionId = $this->getCookie( $request, $this->params['sessionName'], '' );
		$info = [
			'provider' => $this,
			'forceHTTPS' => $this->getCookie( $request, 'forceHTTPS', '', false )
		];
		if ( MediaWiki\Session\SessionManager::validateSessionId( $sessionId ) ) {
			$info['id'] = $sessionId;
			$info['persisted'] = true;
		}


		list( $userId, $userName, $token ) = $this->getUserInfoFromCookies( $request );
		if ( $userId !== null ) {
			try {
				$userInfo = UserInfo::newFromId( $userId );
			} catch ( \InvalidArgumentException $ex ) {
				return null;
			}

			// Sanity check
			if ( $userName !== null && $userInfo->getName() !== $userName ) {
				$this->logger->warning(
					'Session "{session}" requested with mismatched UserID and UserName cookies.',
					[
						'session' => $sessionId,
						'mismatch' => [
							'userid' => $userId,
							'cookie_username' => $userName,
							'username' => $userInfo->getName(),
						],
				] );
				return null;
			}

			if ( $token !== null ) {
				if ( !hash_equals( $userInfo->getToken(), $token ) ) {
					$this->logger->warning(
						'Session "{session}" requested with invalid Token cookie.',
						[
							'session' => $sessionId,
							'userid' => $userId,
							'username' => $userInfo->getName(),
					 ] );
					return null;
				}
				$info['userInfo'] = $userInfo->verified();
				$info['persisted'] = true; // If we have user+token, it should be
			} elseif ( isset( $info['id'] ) ) {
				$info['userInfo'] = $userInfo;
			} else {
				// No point in returning, loadSessionInfoFromStore() will
				// reject it anyway.
				return null;
			}
		} elseif ( isset( $info['id'] ) ) {
			// No UserID cookie, so insist that the session is anonymous.
			// Note: this event occurs for several normal activities:
			// * anon visits Special:UserLogin
			// * anon browsing after seeing Special:UserLogin
			// * anon browsing after edit or preview
			$this->logger->debug(
				'Session "{session}" requested without UserID cookie',
				[
					'session' => $info['id'],
			] );
			$userInfo = UserInfo::newFromName( $this->getRemoteUsername() );
			$info['userInfo'] = $userInfo->verified();
		} else {
			// No session ID and no user is the same as an empty session, so
			$userInfo = UserInfo::newFromName( $this->getRemoteUsername() );
			$info['userInfo'] = $userInfo->verified();
			// there's no point.
			//return null;
		}

		return new SessionInfo( $this->priority, $info );
	}

    /**
     * @inheritDoc
     */
    public function newSessionInfo($id = null)
    {

        return null;
    }

    /**
     * @param $username
     * @param WebRequest $request
     * @return SessionInfo
     */
    protected function newSessionForRequest($username, WebRequest $request)
    {
        $id = $this->getSessionIdFromCookie($request);

        $user = User::newFromName($username, 'usable');
        if (!$user) {
            throw new \InvalidArgumentException('Invalid user name');
        }

        $this->initUser($user, $username);

        $info = new SessionInfo(SessionInfo::MAX_PRIORITY, [
            'provider' => $this,
            'id' => $id,
            'userInfo' => UserInfo::newFromUser($user, true),
            'persisted' => false
        ]);
        $session = $this->getManager()->getSessionFromInfo($info, $request);
        $session->persist();

        return $info;
    }

    /**
     * When creating a user account, optionally fill in
     * preferences and such.  For instance, you might pull the
     * email address or real name from the external user database.
     *
     * @param $user User object.
     * @param $autocreate bool
     */
    protected function initUser(&$user, $username)
    {
        if (Hooks::run("AuthRemoteUserInitUser",
            array($user, true))
        ) {
            $this->setRealName($user);

            $this->setEmail($user);

			$this->setGroups($user);

            $user->mEmailAuthenticated = wfTimestampNow();
            $user->setToken();

            $this->setNotifications($user);
        }

        $user->saveSettings();
    }

    /**
     * Sets the real name of the user.
     *
     * @param User
     */
    protected function setRealName(User $user)
    {
        $wgAuthRemoteuserName = isset( $_SERVER["HTTP_AD_DISPLAYNAME"] )
            ? $_SERVER["HTTP_AD_DISPLAYNAME"]
            : '';
        if ($wgAuthRemoteuserName) {
            $user->setRealName($wgAuthRemoteuserName);
        } else {
            $user->setRealName('');
        }
    }

    /**
     * Return the username to be used.  Empty string if none.
     *
     * @return string
     */
    protected function getRemoteUsername()
    {
        global $wgAuthRemoteuserDomain;

        if (isset($_SERVER['HTTP_AUTH_USER'])) {
            $username = $_SERVER['HTTP_AUTH_USER'];

            if ($wgAuthRemoteuserDomain) {
                $username = str_replace("$wgAuthRemoteuserDomain\\",
                    "", $username);
                $username = str_replace("@$wgAuthRemoteuserDomain",
                    "", $username);
            }
        } else {
            $username = "";
        }

        return $username;
    }

	/**
	 *
	 * @param User $user
	 */
	protected function setGroups( User $user ){
		$wgAuthRemoteuserGroups = isset( $_SERVER["HTTP_AD_GROUPS"] )
            ? $_SERVER["HTTP_AD_GROUPS"]
            : '';
		$arrGroups = array();
		preg_match_all( '/CN=(.*?),.*?;/', $wgAuthRemoteuserGroups, $arrGroups ); //put user groups into $arrString[1][x]
		//assign user to groups
		foreach ( $arrGroups[ 1 ] as $group ) {
			$user->addGroup( $group );
		}
	}

    /**
     * Sets the email address of the user.
     *
     * @param User
     * @param String username
     */
    protected function setEmail(User $user)
    {
        /* User's Mail */
        $wgAuthRemoteuserMail = isset( $_SERVER["HTTP_AD_MAIL"] )
            ? $_SERVER["HTTP_AD_MAIL"]
            : '';

        if ($wgAuthRemoteuserMail) {
            $user->setEmail($wgAuthRemoteuserMail);
        }
    }

    /**
     * Set up notifications for the user.
     *
     * @param User
     */
    protected function setNotifications(User $user)
    {
        global $wgAuthRemoteuserNotify;

        // turn on e-mail notifications
        if ($wgAuthRemoteuserNotify) {
            $user->setOption('enotifwatchlistpages', 1);
            $user->setOption('enotifusertalkpages', 1);
            $user->setOption('enotifminoredits', 1);
            $user->setOption('enotifrevealaddr', 1);
        }
    }


}
