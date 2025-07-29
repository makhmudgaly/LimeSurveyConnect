<?php

use LimeSurvey\PluginManager\AuthPluginBase;
use LimeSurvey\PluginManager\PluginEvent;
use LimeSurvey\PluginManager\PluginManager;

class LimeSurveyConnect extends AuthPluginBase
{
    protected const SESSION_NONCE_KEY = 'sso_nonce';
    protected $storage = 'DbStorage';

    static protected $name = 'LimeSurveyConnect';
    static protected $description = 'Enable Single Sign-On using DiscourseConnect';

    protected $settings = [];

    public function __construct(PluginManager $manager, $id)
    {
        parent::__construct($manager, $id);

        $this->settings = [
            'sso_url' => [
                'type' => 'string',
                'label' => $this->gT('SSO Provider URL'),
                'help' => $this->gT('Example: https://your-discourse-site/session/sso_provider')
            ],
            'shared_secret' => [
                'type' => 'password',
                'label' => $this->gT('Shared Secret'),
                'help' => $this->gT('Must match the secret configured in your SSO provider')
            ],
            'auto_create_users' => [
                'type' => 'checkbox',
                'label' => $this->gT('Automatically create users'),
                'help' => $this->gT('If enabled, users that do not exist yet will be created after successful login.'),
                'default' => true
            ],
            'default_lang' => [
                'type' => 'select',
                'label' => $this->gT('Default Language'),
                'options' => [
                    'en' => $this->gT('English'),
                    'es' => $this->gT('Spanish'),
                    'fr' => $this->gT('French'),
                    'de' => $this->gT('German'),
                    'ru' => $this->gT('Russian')
                ],
                'default' => 'en'
            ],
            'is_default' => [
                'type' => 'checkbox',
                'label' => $this->gT('Use as default login'),
                'help' => $this->gT('If enabled, users will be redirected directly to SSO login instead of showing the LimeSurvey login form'),
                'default' => false
            ]
        ];

        if (method_exists(Permissiontemplates::class, 'applyToUser')) {
                        $roles = [];
                        foreach (Permissiontemplates::model()->findAll() as $role) {
                                $roles[$role->ptid] = $role->name;
                        }

                        $this->settings['autocreate_roles'] = [
                                'type' => 'select',
                                'label' => $this->gT('Global roles for new users'),
                                'help' => $this->gT('Global user roles to be assigned to users that are automatically created.'),
                                'options' => $roles,
                                'htmlOptions' => [
                                        'multiple' => true
                                ],
                        ];
                }

                $this->settings['autocreate_permissions'] = [
                        'type' => 'json',
                        'label' => $this->gT('Global permissions for new users'),
                        'help' => sprintf(
                                $this->gT('A JSON object describing the default permissions to be assigned to users that are automatically created. The JSON object has the follwing form: %s'),
                                CHtml::tag('pre', [], "{\n\t\"surveys\": { ... },\n\t\"templates\": {\n\t\t\"create\": false,\n\t\t\"read\": false,\n\t\t\"update\": false,\n\t\t\"delete\": false,\n\t\t\"import\": false,\n\t\t\"export\": false,\n\t},\n\t\"users\": { ... },\n\t...\n}")
                        ),
                        'editorOptions'=>array('mode'=>'tree'),
                        'default' => json_encode([
                                'users' => [
                                        'create' => false,
                                        'read' => false,
                                        'update' => false,
                                        'delete' => false,
                                ],
                                'usergroups' => [
                                        'create' => false,
                                        'read' => false,
                                        'update' => false,
                                        'delete' => false,
                                ],
                                'labelsets' => [
                                        'create' => false,
                                        'read' => false,
                                        'update' => false,
                                        'delete' => false,
                                        'import' => false,
                                        'export' => false,
                                ],
                                'templates' => [
                                        'create' => false,
                                        'read' => false,
                                        'update' => false,
                                        'delete' => false,
                                        'import' => false,
                                        'export' => false,
                                ],
                                'settings' => [
                                        'read' => false,
                                        'update' => false,
                                        'import' => false,
                                ],
                                'surveys' => [
                                        'create' => false,
                                        'read' => false,
                                        'update' => false,
                                        'delete' => false,
                                        'export' => false,
                                ],
                                'participantpanel' => [
                                        'create' => false,
                                        'read' => false,
                                        'update' => false,
                                        'delete' => false,
                                        'import' => false,
                                        'export' => false,
                                ],
                                'auth_db' => [
                                        'read' => false,
                                ],
                        ]),
                ];

        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('newLoginForm');
    }

    public function init()
    {
        // Subscriptions are now handled in constructor
    }

    public function newLoginForm()
    {
        $event = $this->getEvent();
        $event->getContent($this)->addContent('');
    }

    public function beforeLogin()
    {
        $request = $this->api->getRequest();

        // Check if this is an SSO callback
        if ($request->getParam('sso') && $request->getParam('sig')) {
            $this->handleSSOCallback();
            return;
        }

        // Check if we should initiate SSO
        $defaultAuth = $this->get('is_default') ? get_class($this) : null;
        if ($request->getParam('authMethod', $defaultAuth) !== get_class($this)) {
            return;
        }

        $this->handleSSOInit();
    }

    protected function handleSSOInit()
    {
        try {
            $nonce = bin2hex(random_bytes(16));
            Yii::app()->session[self::SESSION_NONCE_KEY] = $nonce;

            $payload = base64_encode(http_build_query([
                'nonce' => $nonce,
                'return_sso_url' => $this->api->createUrl('admin/authentication/sa/login', [])
            ]));

            $signature = hash_hmac('sha256', $payload, $this->get('shared_secret'));

            $ssoUrl = $this->get('sso_url');
            if (empty($ssoUrl)) {
                throw new \CHttpException(500, 'SSO URL not configured');
            }

            Yii::app()->request->redirect($ssoUrl . '?' . http_build_query([
                'sso' => $payload,
                'sig' => $signature
            ]));
        } catch (\Exception $e) {
            throw new \CHttpException(500, 'SSO Initialization Failed: ' . $e->getMessage());
        }
    }

    protected function handleSSOCallback()
    {
        try {
            $sso = Yii::app()->request->getParam('sso');
            $sig = Yii::app()->request->getParam('sig');

            if (empty($sso) || empty($sig)) {
                throw new \CHttpException(400, 'Missing SSO parameters');
            }

            $this->validateSignature($sso, $sig);

            $payload = base64_decode($sso);
            if ($payload === false) {
                throw new \CHttpException(400, 'Invalid SSO payload');
            }

            parse_str($payload, $ssoData);

            if (empty($ssoData['email'])) {
                throw new \CHttpException(400, 'Email not provided in SSO data');
            }

            if (!isset(Yii::app()->session[self::SESSION_NONCE_KEY]) ||
                Yii::app()->session[self::SESSION_NONCE_KEY] !== $ssoData['nonce']) {
                throw new \CHttpException(401, 'Invalid nonce');
            }

            $this->setUsername($ssoData['email']);
            $this->setAuthPlugin();

        } catch (\Exception $e) {
            throw new \CHttpException(401, 'SSO Authentication Failed: ' . $e->getMessage());
        }
    }

    public function newUserSession()
    {
        $identity = $this->getEvent()->get('identity');
        if ($identity->plugin !== get_class($this)) {
            return;
        }

        $userEmail = $this->getUserName();
        $user = User::model()->findByAttributes(['email' => $userEmail]);

        if (!$user && !$this->get('auto_create_users')) {
            throw new \CHttpException(401, 'User not found and auto-creation disabled');
        }

        if (!$user) {
            $user = new User();
            $user->email = $userEmail;
            $user->users_name = $userEmail;
            $user->full_name = $ssoData['name'] ?? '';
            $user->password = password_hash(random_bytes(32), PASSWORD_DEFAULT);
            $user->lang = $this->get('default_lang');

            if (!$user->save()) {
                throw new \CHttpException(500, 'Failed to create user: ' . print_r($user->getErrors(), true));
            }

            $defaultPermissions = json_decode($this->get('autocreate_permissions', null, null, []), true);
                        if (!empty($defaultPermissions)) {
                                Permission::setPermissions($user->uid, 0, 'global', $defaultPermissions, true);
                        }

                        if (method_exists(Permissiontemplates::class, 'applyToUser')) {
                                foreach ($this->get('autocreate_roles', null, null, []) as $role) {
                                        Permissiontemplates::model()->applyToUser($user->uid, $role);
                                }
                        }
        }

        $this->setAuthSuccess($user);
    }

    protected function validateSignature($payload, $signature)
    {
        $secret = $this->get('shared_secret');
        if (empty($secret)) {
            throw new \CHttpException(500, 'Shared secret not configured');
        }

        $calculated = hash_hmac('sha256', $payload, $secret);

        if (!hash_equals($calculated, $signature)) {
            throw new \CHttpException(401, 'Invalid signature');
        }
    }

    public function getAuthName()
    {
        return $this->gT('LimeSurveyConnect');
    }
}