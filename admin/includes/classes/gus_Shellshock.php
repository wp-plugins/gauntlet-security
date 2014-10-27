<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

class gus_Shellshock extends gus_TestBase
{
	protected $test_table_show = true;
	protected $test_table_headers = true;
	protected $test_table_fail_only = false;
    
	protected function main_check()
	{
        /*
            Check common CGI scripts to test against
        */
        $port = ( isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : '80';
        $url = site_url('', 'http');
        $url_no_port = str_replace(':' . $port, '', site_url());    
        $url_no_port_ssl = str_replace(':' . $port, '', site_url('', 'https'));
        
        $test_urls = array(
            array($url . '/cgi-bin/', 'test.cgi', 'System Info'),
            array($url . '/cgi-bin/', 'test-cgi', 'System Info'),
            array($url . '/cgi-mod/', 'index.cgi', 'Barracuda Appliance'),
            array($url . '/cgi-sys/', 'defaultwebpage.cgi', 'cPanel'),
            array($url_no_port . ':2082/cgi-sys/', 'defaultwebpage.cgi', 'cPanel'),
            array($url_no_port_ssl . ':2083/cgi-sys/', 'defaultwebpage.cgi', 'cPanel'),
            array($url . '/cgi-sys/', 'entropysearch.cgi', 'cPanel'),
            array($url_no_port . ':2082/cgi-sys/', 'entropysearch.cgi', 'cPanel'),
            array($url_no_port_ssl . ':2083/cgi-sys/', 'entropysearch.cgi', 'cPanel'),
            array($url . '/cgi-bin/test/', 'test.cgi', 'Plesk'),
            array($url_no_port . ':8880/cgi-bin/test/', 'test.cgi', 'Plesk'),
            array($url_no_port_ssl . ':8443/cgi-bin/test/', 'test.cgi', 'Plesk'),
        );
        
        
        // Create a temp file for testing 
        // (Saved to PHP temp directory, which is often 1777)

        $temp_path = tempnam(@sys_get_temp_dir(), 'gus');
        
        // Make sure file was saved
        
        clearstatcache();

        if( ! file_exists($temp_path) )
        {
            $this->undetermined();
            return;
        }
        
        // Change permissions so that CGI user can write to file
        
        chmod($temp_path, 0777);



        $num_passes = 0;
        $num_criticals = 0;
		foreach ($test_urls as $url)
		{
            $sub_test = $this->run_sub_test( array(
                'type' => $url[2],
                'temp_path' => $temp_path,
                'cgi_url' => $url[0] . $url[1],
            ) );
            
            if( $sub_test['pass'] == 'pass' )
            {
                $num_passes++;
            }
            if( $sub_test['pass'] == 'critical' )
            {
                $num_criticals++;
            }
		}
        
        if($num_passes > 0 && $num_criticals == 0)
        {
            $this->pass();
        }
        
        
        // Delete temp file

        unlink($temp_path);
	}
	
	protected function sub_test( $args )
	{
		$type = $args['type'];
		$temp_path = $args['temp_path'];
		$cgi_url = $args['cgi_url'];


		$sub_test = array(
			'pass' => 'undetermined',
			'table_columns' => array(
				'Test URL' => $cgi_url,
				'Type' => $type,
                'Result' => '',
			),
		);


        // Is CGI file testable?

        $result = $this->is_cgi_testable($cgi_url);
        if( $result !== true )
        {
            $sub_test['table_columns']['Result'] = $result;
            return $sub_test;
        }
        
        

        // Try writing to temp file using shellshock & CGI file

        if( ! $response_code = $this->write_tempfile_using_ss($cgi_url, $temp_path) )
        {
            $sub_test['table_columns']['Result'] = 'Failed';
            return $sub_test;
        }
        

        // See if temp file is longer than 0 bytes

        clearstatcache();
        
        if( filesize($temp_path) > 0 )
        {
            $sub_test['pass'] = 'critical';
            $sub_test['table_columns']['Result'] = $response_code . ' - Vulnerable';
        }
        else
        {
            $sub_test['pass'] = 'pass';
            $sub_test['table_columns']['Result'] = '<strong>' . $response_code . ' - Not vulnerable</strong>';
        }

		return $sub_test;
	}

    private function is_cgi_testable($cgi_url)
    {
        $response = wp_remote_head( $cgi_url, array() );

        if( is_object($response) || ! isset($response['response']['code']) )
        {
            return 'Failed';
        }
        if( $response['response']['code'] >= 400 && $response['response']['code'] < 500 )
        {
            return $response['response']['code'] . ' - Not found';
        }
        elseif($response['response']['code'] >= 500)
        {
            return $response['response']['code'] . ' - Error';
        }
        
        return true;
    }

    private function write_tempfile_using_ss($cgi_url, $temp_path)
    {
        $args = array(
            'headers' => array(
                'gauntlet-bash-test' => '() { :;}; echo "This file may be deleted" > ' . $temp_path,
            )
        );
        $response = wp_remote_get( $cgi_url, $args );
        
        if( is_object($response) || ! isset($response['response']['code']) )
        {
            return false;
        }
        else
        {
            return $response['response']['code'];
        }
    }

	public function title()
	{
		switch($this->pass)
		{
			case 'pass':
			return "Your server does not appear to be vulnerable to the Shellshock Bash bug";
			break;
			
			case 'fail':
			case 'critical':
			return "Your server is vulnerable to the Shellshock Bash bug";
			break;
			
			case 'undetermined':
			default:
			return "Make sure your server is not vulnerable to the Shellshock Bash bug";
			break;			
		}
	}
	
	protected function result_text()
	{
		switch($this->pass)
		{
			case 'pass':
			$result_text = <<<EOD
                
    <p>This test failed to remotely inject executable code through a call to a CGI script.</p>
            
EOD;
            break;
		
			case 'fail':
			case 'critical':
			$result_text = <<<EOD
    
    <p>It is possible to remotely inject executable code through a call to a CGI script on this server.</p>
            
EOD;
			break;
		
			case 'undetermined':
			default:
			$result_text = <<<EOD

    <p>It wasn't possible to check for the Shellshock vulnerability. 
            The test couldn't find a CGI shell script to test with.
            Check with your web host to be sure they have patched their servers.</p>

EOD;
			break;
		}
        
        return $result_text;
	}
	
	protected function why_important()
	{    
		return <<<EOD
            
        <p>The Shellshock bug can be very easy to exploit and can give the hacker an enormous amount of control over a web server.</p>

        <h3>About the test</h3>

        <p>
        There are several specific vulnerabilities related to the Bash flaw. 
        The first (CVE-2014-6271) is the most dangerous for web servers as it easily allows remote code execution.
        This test looks for and attempts to run CGI shell scripts that are commonly found on many web servers.
        If a script is found it will be called along with a custom header. 
        On an upatched server, the code inside that header will be executed and a test file will be 
        added to the system "temp" directory.</p>

        <p>Here is an example header including the exploit:</p>
        
        <code class='prettyprint'>gauntlet-bash-test: () { :;}; echo "This file may be deleted" > /tmp/gus46oi1c</code>
 
EOD;
	}
	
	protected function how_to_fix()
	{
		return <<<EOD

    <p>This flaw in Bash was made public September 24, 2014 and
        new ways of exploiting the Bash bug could still be discovered. 
        Most web hosts have been quick to patch their servers.</p>

EOD;
	}
	
	protected function fix_difficulty()
	{
		return <<<EOD
EOD;
	}

    protected function references()
    {
        return <<<EOD
            
        <a href='https://blog.cloudflare.com/inside-shellshock/'>CloudFlare: Inside Shellshock: How hackers are using it to exploit systems</a><br>
        <a href='http://shellshock.brandonpotter.com/'>Test a specific CGI script URL</a><br>

EOD;
    }
}