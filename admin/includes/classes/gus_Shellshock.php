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
        

        $num_passes = 0;
		foreach ($test_urls as $url)
		{
            $sub_test = $this->run_sub_test( array(
                'url_base' => $url[0],
                'file' => $url[1],
                'type' => $url[2],
            ) );
            
            if( $sub_test['pass'] == 'pass' )
            {
                $num_passes++;
            }
		}
        
        if($num_passes > 0)
        {
            $this->pass();
        }
	}
	
	protected function sub_test( $args )
	{
		$url_base = $args['url_base'];
		$file = $args['file'];
		$type = $args['type'];
        
        /*
            Temp file
        */
        $url_hash = md5($url_base . $file);
		$temp_file = 'tmp-' . $url_hash . '.txt';
        $upload_dir = wp_upload_dir();
		$temp_path = $upload_dir['basedir'] . '/' . $temp_file;

		$sub_test = array(
			'pass' => 'undetermined',
			'table_columns' => array(
				'Test URL' => $url_base . $file,
				'Type' => $type,
                'Result' => '',
			),
		);

        /*
            First check if CGI file is testable
        */
        $response = wp_remote_request( $url_base . $file, array() );

        if( is_object($response) || ! isset($response['response']['code']) )
        {
            $sub_test['table_columns']['Result'] = 'Failed';
            return $sub_test;
        }

        if( $response['response']['code'] >= 400 && $response['response']['code'] < 500 )
        {
            $sub_test['table_columns']['Result'] = $response['response']['code'] . ' - Not found';
            return $sub_test;
        }
        elseif($response['response']['code'] >= 500)
        {
            $sub_test['table_columns']['Result'] = $response['response']['code'] . ' - Error';
            return $sub_test;
        }
            
        
        /*
            Test CGI file
        */        
        $args = array(
            'headers' => array(
                'gauntlet-bash-test' => '() { :;}; echo "This file may be deleted" > ' . $temp_path,
            )
        );
        $response = wp_remote_request( $url_base . $file, $args );
        
        if( ! is_object($response) && isset($response['response']['code']) )
        {
            $sub_test['table_columns']['Result'] = $response['response']['code'];
            
            // Check if file was saved through the shellshock hack
            if( file_exists($temp_path) )
            {
                $sub_test['pass'] = 'critical';
                $sub_test['table_columns']['Result'] .= ' - Vulnerable';
                
                unlink($temp_path);
            }
            else
            {
                $sub_test['pass'] = 'pass';
                $sub_test['table_columns']['Result'] = '<strong>' . $sub_test['table_columns']['Result'] . ' - Not vulnerable</strong>';
            }
        }
        else
        {
            $sub_test['table_columns']['Result'] = ' - Not found';
        }


		
		return $sub_test;
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
        $md5 = md5(time());
		return <<<EOD

        <p>The Shellshock bug can be very easy to exploit and can give the hacker an enormous amount of control over a web server.</p>

        <h3>About the test</h3>

        <p>
        There are several specific exploits related to the Bash flaw. 
        The first exploit (CVE-2014-6271) is the most dangerous for web servers as it easily allows
        remote code execution.
        This test looks for and attempts to run CGI shell scripts that are commonly found on many web servers.
        If a script is found it will be called along with a custom header. 
        On an upatched server, the code inside that header will be executed and a test file will be saved to your WordPress uploads directory.</p>

        <p>Here is an example header including the exploit:</p>
        
        <code class='prettyprint'>gauntlet-bash-test: () { :;}; echo "This file may be deleted" > /path/to/wp-content/uploads/tmp-{$md5}.txt</code>
 
EOD;
	}
	
	protected function how_to_fix()
	{
		return <<<EOD

    <p>This flaw in Bash was made public September 24, 2014 and as of September 27 new patches are still being tested 
        and new ways of exploiting the Bash bug could still be discovered. 
        Most web hosts have been quick to patch their servers.
        If your web host has a status blog or Twitter feed, check to make sure they are addressing the problem.</p>

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
            
        <a href='http://en.wikipedia.org/wiki/Shellshock_(software_bug)'>Wikipedia: Shellshock (software bug)</a><br>
        <a href='http://shellshock.brandonpotter.com/'>Test a specific CGI script URL</a><br>

EOD;
    }
}