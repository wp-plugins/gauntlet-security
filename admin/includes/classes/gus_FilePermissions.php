<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

class gus_FilePermissions extends gus_TestBase
{
	protected $test_table_show = true;
	protected $test_table_headers = true;
	protected $test_table_fail_only = false;

	protected function main_check()
	{
		$paths = array();
		$file_paths = array();
        
        
        // All top-level directory & file paths
        
        $iter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator(ABSPATH, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST,
                    RecursiveIteratorIterator::CATCH_GET_CHILD // Ignore "Permission denied"
                );
        $iter->setMaxDepth(0);
        foreach ($iter as $path => $dir) 
        {
            $path_name = $dir->getPathname();
            $extension = pathinfo($path_name, PATHINFO_EXTENSION);
            
            // Skip content dir, for now
            if ( $dir->isDir() && $path_name !== WP_CONTENT_DIR ) 
            {
                $paths[] = array('Directory', $path_name, 705, 755, 755, 775);
            }
            if ( $dir->isFile() ) 
            {
                // If file is wp-config.php, php.ini, or .htacces... skip it
                if(
                    $path_name == $this->wp_config_path() ||
                    $path_name == ABSPATH . 'php.ini' ||
                    $path_name == ABSPATH . '.htaccess'                        
                )
                {
                    continue;
                }
                
                if($extension == 'php')
                {
                    $file_paths[] = array('File', $path_name, 600, 644, 640, 664);
                }
                else
                {
                    $file_paths[] = array('File', $path_name, 644, 644, 640, 664);
                }

            }
        }


        // The content directory
        
        $paths[] = array('Directory', WP_CONTENT_DIR, 705, 755, 755, 775);
        

        // All directories within content directory
        
        $multiple_iter = new AppendIterator();
        $multiple_iter->append( new DirectoryIterator(WP_CONTENT_DIR) );
        foreach ($multiple_iter as $path => $dir) 
        {
            if ( $dir->isDir() && ! $dir->isDot() ) 
            {
                $paths[] = array('Directory', $dir->getPathname(), 705, 755, 755, 775);
            }
        }

        
        // Append file paths to directory paths
        
        $paths = array_merge($paths, $file_paths);
        
        
        // Special files...

		$paths[] = array('.htaccess', ABSPATH . '.htaccess', 644, 644, 440, 640);		
		$paths[] = array('php.ini', ABSPATH . 'php.ini', 400, 644, 440, 640);
        $paths[] = array('wp-config.php', $this->wp_config_path(), 400, 440, 440, 640);
        
        
		clearstatcache();
        
        $this->start_timer();
        
		foreach($paths as $path_arr)
		{
            $this->run_sub_test( array('path_arr' => $path_arr) );
		}

        $this->stop_timer();
	}
    
	protected function sub_test( $args )
	{
		$path_arr = $args['path_arr'];
		$name_plural = $path_arr[0];
		$path = $path_arr[1];
		
        if( $this->is_suphp_like() == true )
        {
            $best_permissions = $path_arr[2];
            $min_permissions = $path_arr[3];
        }
        else
        {
            $best_permissions = $path_arr[4];
            $min_permissions = $path_arr[5];
        }
		
        $recommended = ($best_permissions !== $min_permissions) ? $best_permissions . ' &ndash; ' . $min_permissions : $best_permissions;

        $path_name = ($path !== '') ? $this->strip_site_root( $path ) : '';
        
		$sub_test = array(
			'pass' => 'undetermined',
			'table_columns' => array(
				'Recommended' => $recommended,
				'Current' => '',
				'Description' => $name_plural,
				'Path' => $path_name,
			),
		);

        if( is_dir($path) || is_file($path) )
		{
		    $current_permissions = substr(sprintf("%o", fileperms($path)), -3);

			if($best_permissions == $current_permissions)
			{
    			$sub_test['table_columns']['Current'] = $current_permissions;
				$sub_test['pass'] = 'pass';
			}
			elseif($current_permissions <= $min_permissions)
			{
    			$sub_test['table_columns']['Current'] = $current_permissions;
				$sub_test['pass'] = 'pass';
			}
			else
			{
    			$sub_test['table_columns']['Current'] = "<span class='error'>$current_permissions</span>";
				$sub_test['pass'] = 'fail';
			}
		}
        elseif($path == '')
        {
			$sub_test['pass'] = 'pass';
			$sub_test['table_columns']['Current'] = '-';
			$sub_test['table_columns']['Path'] = 'Not checked';
        }
		else
		{
            // Test not found, skip this test
            return false;
		}		
		
		return $sub_test;
	}

	
	public function title()
	{
		switch($this->pass)
		{
			case 'pass':
			return 'File and directory permissions allow for a minimum amount of access';
			break;
			
			case 'fail':
			case 'critical':
			return 'File and directory permissions allow for more access than necessary';
			break;
			
			case 'undetermined':
			default:
			return 'Set correct file and directory permissions';
			break;			
		}
	}
	
	protected function result_text()
	{
        if( $this->get_sapi() == 'mod_php' )
        {
            $html = "<p><strong>It looks like your site's PHP handler is an Apache module (mod_php).</strong>
                    If your site is hosted on a shared server (multiple users on the 
                    same machine), you should be using FastCGI or suPHP instead. 
                    It's safer and easier to configure than mod_php.</p>";
            $html .= "<p>
                    As usual, the more restrictive the permissions the better, but 
                    this often prevents WordPress from being able to auto-update.
                    The recommended permissions below may not be ideal for your specific server configuration.
                    </p>";
        }
        elseif( $this->is_suphp_like() == true )
        {
            $html = "<p><strong>It looks like your site's PHP handler is FastCGI or suPHP.</strong></p>";
        }
        else
        {
            $html = "<p><strong>It's not clear what PHP handler your server is using.</strong></p>";
            $html .= "<p>The recommended permissions below are only best for sites on shared servers using a FastCGI or suPHP PHP handler.</p>";
        }
        
        $html .= "<p>Only checking WordPress root and top-level content directories...</p>";
        
        
		switch($this->pass)
		{
			case 'pass':
			case 'fail':
			case 'critical':
			return $html;
			break;

            case 'undetermined':
            return '';
            break;
		}
	}
	
	protected function why_important()
	{
		return <<<EOD
			
        <p>Setting restrictive file permissions can help protect against attacks from two fronts...</p>
        <ol>
        <li>Other users on the same server could have access to files in your web directories if permissions are not restrictive enough.</li>
        <li>Exploitable scripts already in your web directory (perhaps part of plugins or themes) can alter other files and directories on your site.</li>
        </ol>
        
        <p>In an ideal permissions scheme...</p> 
        <ul>
        <li>Only your user can write to WordPress files</li>
        <li>The WordPress user (Apache) can read most files but only write to files in the uploads directory</li>
        <li>WordPress can do automatic core updates and install and update plugins without using FTP</li>
        </ul>        
        <p>Especially on shared servers, this is not practical and compromises need to be made.</p>
        
EOD;
	}

	protected function how_to_fix()
	{
        $config_path = $this->wp_config_path();
		return <<<EOD

    		<p>If you don't know how to read or set file permissions from the command line, the Codex has a good introduction: <a href='http://codex.wordpress.org/Changing_File_Permissions' target='_blank'>codex.wordpress.org/Changing_File_Permissions</a>.</p>

            <p>The biggest variable that will affect how you set WordPress's file permissions is the PHP handler that's being used by the server. Apache can be configured to run PHP in several ways but as far as file permissions go, we can split the most common PHP handlers into two types: FastCGI/suPHP and mod_php.</p> 
    
            <p><strong><em>If your site is on a shared server (has user accounts out of your control)</em></strong>, FastCGI or suPHP is more secure than mod_php. Either of those handlers simplify managing PHP file permissions by running Apache as the same user as the file owner. If all WordPress files are owned by your user account, then when WordPress tries to update itself, Apache (running as you) can successfully read and write the same files as you can. Any new files added by Apache will have the same owner and group as your user. This is all much more straightforward than if PHP were handled by mod_php. The trade-off is that any vulnerable plugins will also have your permissions and can do more damage than if Apache was restricted to writing to only specific directories.</p>
         
            <p>If your site is using FastCGI or suPHP use the recommended permissions in the 'Result' section above. Try the most restrictive permission mode first. If something breaks, increase the permission and try again. For PHP files, first try 600. If the site breaks or updates fail increase the permission mode to 640, then 644.</p> 
        
            <p><strong><em>If your site is alone on it's own VPS or dedicated host</em></strong>, mod_php would be the better option. If permissions are set properly, you can better protect your files and directories from exploits from within your WordPress installation. There are a few strategies for setting file permissions using mod_php.
            
            <ol>
            <li>Set strict file permissions and use FTP every time a plugin or core update is needed. Open up the uploads directory to allow WordPress to manage the media library. FTP is an insecure protocol so this method should be avoided.</li>
            <li>Set looser file permissions so that both your user and the Apache user have read/write privileges on all WordPress files. This allows auto-updates without FTP or SSH but opens up the files to exploits from inside the WordPress directory and from other users on the server. Only consider this strategy if all users on the server are trusted. If that's the case, the security of this method is similar to using FastCGI or suPHP.</li>
            <li>Set strict file permissions and configure WordPress to use a unique SSH user account to perform updates. Open up the uploads directory to allow WordPress to manage the media library. This method is described here: <a href='https://www.digitalocean.com/community/tutorials/how-to-configure-secure-updates-and-installations-in-wordpress-on-ubuntu'>Digital Ocean: How To Configure Secure Updates and Installations in WordPress on Ubuntu</a></li>
            </ol>
            
            </p>
    

EOD;
	}
	
	protected function fix_difficulty()
	{
		return 'Advanced';
	}
    
    protected function references()
    {
        return <<<EOD
            
            <a href='http://codex.wordpress.org/Hardening_WordPress#File_Permissions'>Codex: File Permissions - Hardening Wordpress</a><br>
            <a href='http://codex.wordpress.org/Changing_File_Permissions'>Codex: Changing File Permissions</a><br>
            <a href='http://boomshadow.net/tech/php-handlers/'>Boom Shadow: DSO (mod_php) vs. CGI vs. suPHP vs. FastCGI</a><br>
            <a href='https://wordpress.org/plugins/background-update-tester/'>Plugin: Background Update Tester</a><br>
                
        
EOD;
    }
    
    protected function get_sapi()
    {
        $your_sapi = strtolower(php_sapi_name());
        
        if(strpos($your_sapi, 'apache') !== false)
        {
            return 'mod_php';
        } 
        elseif(strpos($your_sapi, 'fcgi') !== false || strpos($your_sapi, 'fastcgi') !== false)
        {
            return 'FastCGI';
        }
        else
        {
            return 'unsure';
        }
        
    }
    
    protected function is_suphp_like()
    {
        if( $this->get_sapi() == 'mod_php')
        {
            return false;
        }
        
        if( $this->get_sapi() == 'FastCGI')
        {
            return true;
        }
        
        // Get PHP process user name
        if( function_exists('posix_getpwuid') && function_exists('posix_geteuid') )
        {
            $process_user = posix_getpwuid(posix_geteuid());
            $process_user = $process_user['name'];
        
            if(get_current_user() == $process_user)
            {
                return true;
            }
        }
        
        return null; // don't know
    }
}