<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

class gus_StrayFiles extends gus_TestBase
{
	protected $test_table_show = true;
	protected $test_table_headers = false;
	protected $test_table_fail_only = false;
    
	protected function main_check()
	{
        $this->check_vim_backup();
        $this->check_vim_swap();
        $this->check_nano_backup();
        $this->check_backups();
        $this->check_db_backups();
        $this->check_logs();
        $this->check_git();
        $this->check_svn();
        $this->check_webadmin();
        $this->check_adminer();
        $this->check_phpinfo();
	}

    protected function sub_test($args)
    {
        $pass = 'pass';
        
        $args['risk'] = (isset($args['risk'])) ? $args['risk'] : 'high';
        $args['url'] = (isset($args['url'])) ? $args['url'] : '';
    
        if($args['url_blocked'] === true)
        {
            $blocked = 'Blocked';
            $pass = 'pass';
        }
        else
        {
            $blocked = '<span class="error">Accessible</span>';
        }
        $blocked = "<a href='" . $args['url'] . "' target='_blank'>" . $blocked . "</a>";
        
        if($args['url_blocked'] === false && $args['path_exists'])
        {
            $pass = 'critical';
        }
        if($args['path_exists'] === true)
        {
            $exists = '<span class="error">Exists</span>';
        }
        else
        {
            $exists = "Doesn't exist";
            $blocked = '';
        }
        if( ! $args['url'] && $args['url_blocked'] === true)
        {
            $exists = 'None found';
        }
        if( $args['risk'] == 'low' && $pass == 'critical' )
        {
            $pass = 'fail';
        }
        
		$sub_test = array(
			'pass' => $pass,
			'table_columns' => array(
				'Description' => $args['description'],
                'Path' => $args['path'],
				'Path Exists' => $exists,
				'URL blocked' => $blocked,
			),
		);
		
		return $sub_test;
    }


    private function check_phpinfo()
    {
        $description = 'PHP info';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array(
            ABSPATH . 'phpinfo.php',
            ABSPATH . 'info.php',
        );

        $test_paths = $common_paths;

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
            if($description !== '')
            {
                $description = '';
            }
        }
    }
    
    private function check_vim_backup()
    {
        $description = 'Vim backups';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array();

        // Find existing files
        $existing_paths_root = $this->find_file_by_postfix('~', ABSPATH);
        $existing_paths_theme = $this->find_file_by_postfix('~', get_stylesheet_directory());

        $test_paths = array_merge($common_paths, $existing_paths_root, $existing_paths_theme);

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
        }
        
        if( ! $test_paths )
        {
            $this->run_sub_test( array(
                'description' => $description,
                'path' => 'eg: filename.php~',
                'path_exists' => false,
                'url_blocked' => true
            ) );
            if($description !== '')
            {
                $description = '';
            }
        }
    }
    
    private function check_vim_swap()
    {
        $description = 'Vim swap files';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array();

        // Find existing files
        $existing_paths_root = $this->find_file_by_extension('swp', ABSPATH);
        $existing_paths_theme = $this->find_file_by_extension('swp', get_stylesheet_directory());

        $test_paths = array_merge($common_paths, $existing_paths_root, $existing_paths_theme);

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
        }
        
        if( ! $test_paths )
        {
            $this->run_sub_test( array(
                'description' => $description,
                'path' => 'eg: filename.php.swp',
                'path_exists' => false,
                'url_blocked' => true
            ) );
            if($description !== '')
            {
                $description = '';
            }
        }
    }
    
    private function check_nano_backup()
    {
        $description = 'Nano backups';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array();

        // Find existing files
        $existing_paths_root = $this->find_file_by_extension('save', ABSPATH);
        $existing_paths_theme = $this->find_file_by_extension('save', get_stylesheet_directory());

        $test_paths = array_merge($common_paths, $existing_paths_root, $existing_paths_theme);

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
        }
        
        if( ! $test_paths )
        {
            $this->run_sub_test( array(
                'description' => $description,
                'path' => 'eg: filename.php.save',
                'path_exists' => false,
                'url_blocked' => true
            ) );
            if($description !== '')
            {
                $description = '';
            }
        }
    }
    
    private function check_backups()
    {
        $description = 'Backup files';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array();

        // Find existing files
        $existing_paths_root = $this->find_file_by_extension('bak', ABSPATH);
        $existing_paths_theme = $this->find_file_by_extension('bak', get_stylesheet_directory());

        $test_paths = array_merge($common_paths, $existing_paths_root, $existing_paths_theme);

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
        }
        
        if( ! $test_paths )
        {
            $this->run_sub_test( array(
                'description' => $description,
                'path' => 'eg: filename.php.bak',
                'path_exists' => false,
                'url_blocked' => true
            ) );
            if($description !== '')
            {
                $description = '';
            }
        }
    }
    
    private function check_git()
    { 
        $description = 'Git version control';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array(
            ABSPATH . '.git/HEAD',
            WP_CONTENT_DIR . '/.git/HEAD',
            get_stylesheet_directory() . '/.git/HEAD',
        );

        // Find existing files
        $existing_paths_root = array();
        $existing_paths_theme = array();

        $test_paths = array_merge($common_paths, $existing_paths_root, $existing_paths_theme);

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
            if($description !== '')
            {
                $description = '';
            }
        }
    }
    
    private function check_svn()
    { 
        $description = 'SVN version control';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array(
            ABSPATH . '.svn/wc.db',
            WP_CONTENT_DIR . '/.svn/wc.db',
            get_stylesheet_directory() . '/.svn/wc.db',
        );

        // Find existing files
        $existing_paths_root = array();
        $existing_paths_theme = array();

        $test_paths = array_merge($common_paths, $existing_paths_root, $existing_paths_theme);

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
            if($description !== '')
            {
                $description = '';
            }
        }
    }
    
    private function check_db_backups()
    { 
        $description = 'Database backups';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array();

        // Find existing files
        $existing_paths_root = $this->find_file_by_string('.sql', ABSPATH);
        $existing_paths_content = $this->find_file_by_string('.sql', WP_CONTENT_DIR);
        $existing_paths_theme = $this->find_file_by_string('.sql', get_stylesheet_directory());

        $test_paths = array_merge($common_paths, $existing_paths_root, $existing_paths_content, $existing_paths_theme);

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
        }
        
        if( ! $test_paths )
        {
            $this->run_sub_test( array(
                'description' => $description,
                'path' => 'eg: backup.sql, backup.sql.gz',
                'path_exists' => false,
                'url_blocked' => true
            ) );
        }
    }
    
    private function check_logs()
    { 
        $description = 'Logs';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array();

        // Find existing files
        $existing_paths_root = $this->find_file_by_extension('log', ABSPATH);
        $existing_paths_content = $this->find_file_by_extension('log', WP_CONTENT_DIR);
        $existing_paths_theme = $this->find_file_by_extension('log', get_stylesheet_directory());

        $test_paths = array_merge($common_paths, $existing_paths_root, $existing_paths_content, $existing_paths_theme);

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
        }
        
        if( ! $test_paths )
        {
            $this->run_sub_test( array(
                'description' => $description,
                'path' => 'eg: debug.log',
                'path_exists' => false,
                'url_blocked' => true
            ) );
        }
    }
    
    private function check_webadmin()
    {
        $description = 'Web-based file manager';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array(
            ABSPATH . 'webadmin.php',
        );

        // Find existing files
        $existing_paths_root = array();
        $existing_paths_theme = array();

        $test_paths = array_merge($common_paths, $existing_paths_root, $existing_paths_theme);

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
        }
    }
    
    private function check_adminer()
    {
        $description = 'Web-based database manager';
        
        // Common git locations: WP root and Active theme root
        $common_paths = array(
            ABSPATH . 'adminer.php',
        );

        // Find existing files
        $existing_paths_root = array();
        $existing_paths_theme = array();

        $test_paths = array_merge($common_paths, $existing_paths_root, $existing_paths_theme);

        foreach($test_paths as $p)
        {
            $u = $this->url_from_path($p);
            $path_exists = $this->does_file_exist($p);
            $url_blocked = $this->is_file_blocked($u);
            $this->run_sub_test( array(
                'description' => $description,
                'path' => $this->strip_site_root($p),
                'path_exists' => $path_exists,
                'url' => $u,
                'url_blocked' => $url_blocked
            ) );
        }
    }
    
    
    /*
        Check that file / path exists
    */
    private function does_file_exist( $test_path )
    {
        return is_file($test_path);
    }
    
    /*
        Find files by extension
    */
    private function find_file_by_extension( $extension, $root = ABSPATH )
    {
        $paths = array();

        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD // Ignore "Permission denied"
        );
        $iter->setMaxDepth(0);
        foreach ($iter as $fileinfo) 
        {
            if ( $fileinfo->isFile() && pathinfo($fileinfo->getFilename(), PATHINFO_EXTENSION) == $extension) 
            {
                $paths[] = $fileinfo->getPathname();
            }
        }

        return $paths;
    }
    
    /*
        Find files by last characters
    */
    private function find_file_by_postfix( $postfix, $root = ABSPATH )
    {
        $paths = array();

        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD // Ignore "Permission denied"
        );
        $iter->setMaxDepth(0);
        foreach ($iter as $fileinfo) 
        {
            $filename = $fileinfo->getFilename();
            if ( $fileinfo->isFile() && strpos($filename, $postfix) === strlen($filename) - strlen($postfix)) 
            {
                $paths[] = $fileinfo->getPathname();
            }
        }

        return $paths;
    }
    
    /*
        Find files by any string anywhere in name
    */
    private function find_file_by_string( $string, $root = ABSPATH )
    {
        $paths = array();

        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST,
            RecursiveIteratorIterator::CATCH_GET_CHILD // Ignore "Permission denied"
        );
        $iter->setMaxDepth(0);
        foreach ($iter as $fileinfo) 
        {
            $filename = $fileinfo->getFilename();
            if ( $fileinfo->isFile() && strpos($filename, $string) !== false ) 
            {
                $paths[] = $fileinfo->getPathname();
            }
        }

        return $paths;
    }
    
    /*
        Check if path is browser accessible
    */
    private function is_file_blocked( $test_url )
    {
        // if using a self-signed ssl cert
        $args = (is_ssl()) ? array('sslverify' => false) : array() ; 
		$response = wp_remote_request( $test_url, $args );

		if( is_array($response) && isset($response['response']['code']) )
		{
			return $response['response']['code'] >= 400;
		}
		else
		{
            return false;
		}
    }
    
    
    
	
	public function title()
	{
		switch($this->pass)
		{
			case 'pass':
			return "No stray files could be found that are accessible and could be useful to attackers";
			break;
			
			case 'fail':
			case 'critical':
			return "There are stray files accessible which could be useful to attackers";
			break;
			
			case 'undetermined':
			default:
			return "Prevent access to any stray files which could be useful to attackers";
			break;			
		}
	}
	
	protected function result_text()
	{
        return <<<EOD
            
        This test looks for commonly used non-WordPress files in locations hackers are most likely to look for them. 
        Common locations are: the root web directory, the WordPress content directory, and the active theme directory.
EOD;
	}
	
	protected function why_important()
	{
		return <<<EOD
            
        <p>Files such as backups, logs, version control directories, and temporary test files 
           could expose sensitive information.</p>
         
EOD;
	}
	
	protected function how_to_fix()
	{
        $code1 = <<<EOD

# Block dot directories such as Git and SVN
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{REQUEST_URI} "!(^|/)\.well-known/([^./]+./?)+$" [NC]
    RewriteCond %{SCRIPT_FILENAME} -d [OR]
    RewriteCond %{SCRIPT_FILENAME} -f
    RewriteRule "(^|/)\." - [F]
</IfModule>

# Block backup, swap, and log files 
<FilesMatch "(^#.*#|\.(bak|conf|dist|fla|in[ci]|log|psd|save|sh|sql|sw[op])|~)$">

    # Apache < 2.3
    <IfModule !mod_authz_core.c>
        Order allow,deny
        Deny from all
        Satisfy All
    </IfModule>

    # Apache >= 2.3
    <IfModule mod_authz_core.c>
        Require all denied
    </IfModule>

</FilesMatch>

EOD;
        $code1 = htmlentities(trim($code1));
            
		return <<<EOD
            
        <p>Temporary PHP scripts used for testing or server administration should be deleted 
        as soon as they're no longer needed. </p>

        <p>It's possible to block files with extensions that should never be accessed from a browser.
                Rather than rely on yourself to detect and delete these files, it's safer to
                block access.</p>

        <p>The following code should be placed within the htaccess file in the root web directory. </p>

        <code class='prettyprint'>{$code1}</code>
		
EOD;
	}
	
	protected function fix_difficulty()
	{
		return 'Intermediate';
	}
    protected function references()
    {
        return <<<EOD
            
        <a href='http://feross.org/cmsploit/'>Feross: 1% of CMS-Powered Sites Expose Their Database Passwords</a><br>
        <a href='https://github.com/h5bp/server-configs-apache'>H5BP: Apache Server Configs</a><br>

EOD;
    }
	
}