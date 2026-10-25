<?php
include __DIR__ . "/settings.pantheon.php";
$settings['config_sync_directory'] = '../config/sync';
if (isset($_ENV['PANTHEON_ENVIRONMENT']) && $_ENV['PANTHEON_ENVIRONMENT'] === 'live') {
  $config['system.logging']['error_level'] = 'hide';
}
$databases['default']['default']['password'] = 'hunter2-secret';
