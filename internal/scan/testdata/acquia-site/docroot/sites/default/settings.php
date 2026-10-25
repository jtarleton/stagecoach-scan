<?php
if (file_exists('/var/www/site-php')) {
  require '/var/www/site-php/mysite/mysite-settings.inc';
}
if (isset($_ENV['AH_SITE_ENVIRONMENT'])) { $settings['file_private_path'] = '/mnt/files/mysite.prod/files-private'; }
