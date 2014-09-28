<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

class gus_PhpDisplayErrors extends gus_TestBase
{
	protected $test_table_show = true;
	protected $test_table_headers = false;
	protected $test_table_fail_only = false;

	protected function main_check()
	{
        $wp_debug = ( WP_DEBUG ) ? 'true' : 'false' ;
        $wp_debug_log = ( WP_DEBUG_LOG ) ? 'true' : 'false' ;
        $ini_display_errors = ( ini_get('display_errors') == '1' ) ? 'on' : 'off';
        
		if ( WP_DEBUG_DISPLAY )
        {
            $wp_debug_display = 'true';
        }
		elseif ( null !== WP_DEBUG_DISPLAY )
        {
            $wp_debug_display = 'false';
        }
        else
        {
            $wp_debug_display = 'null';
        }

        $configs = array(
            'WP_DEBUG' => $wp_debug,
            'WP_DEBUG_LOG' => $wp_debug_log,
            'WP_DEBUG_DISPLAY' => $wp_debug_display,
            "ini_set( 'display_errors' )" => $ini_display_errors,
        );        

        $this->run_sub_test( array(
            'config' =>  'WP_DEBUG',
            'configs' => $configs,
        ) );
        
        /*
            Only display WP_DEBUG_LOG if WP_DEBUG is true
        */
        if( WP_DEBUG )
        {
            $this->run_sub_test( array(
                'config' =>  "WP_DEBUG_LOG",
                'configs' => $configs,
            ) );
        }

        /*
            Only display WP_DEBUG_DISPLAY if WP_DEBUG is true
        */
        if( WP_DEBUG )
        {
            $this->run_sub_test( array(
                'config' =>  "WP_DEBUG_DISPLAY",
                'configs' => $configs,
            ) );
        }

        if( (WP_DEBUG && WP_DEBUG_DISPLAY) || (WP_DEBUG && WP_DEBUG_DISPLAY == false) )
        {
            // No need to run the ini display_errors check
        }
        else
        {
    		$this->run_sub_test( array(
                'config' =>  "ini_set( 'display_errors' )",
                'configs' => $configs,
    		) );
        }

	}

	protected function sub_test($args)
	{
		$config = $args['config'];
		$configs = $args['configs'];


        // Critical Fails...
        
        // WP_DEBUG         = true      (should be false)
        // display_errors   = true      (should be false)      

        // WP_DEBUG         = false
        // display_errors   = true      (should be false)


        // Fails...
        
        // WP_DEBUG         = true      (should be false)
        // display_errors   = false


        // Passes...
        
        // WP_DEBUG         = false
        // display_errors   = false




        if( $config == 'WP_DEBUG' )
        {
            if( WP_DEBUG && $configs["ini_set( 'display_errors' )"] == 'on' )
            {
                $pass = 'critical';
            }
            elseif( WP_DEBUG && $configs["ini_set( 'display_errors' )"] == 'off' )
            {
                $pass = 'fail';
                $configs['WP_DEBUG'] = "<span class='error'>" . $configs['WP_DEBUG'] . "</span>";
            }
            else
            {
                $pass = 'pass';
            }
        }
        
        if( $config == 'WP_DEBUG_LOG' )
        {
            if( $configs['WP_DEBUG_LOG'] == 'true' )
            {
                $pass = 'fail';
                $configs['WP_DEBUG_LOG'] = "<span class='error'>" . $configs['WP_DEBUG_LOG'] . "</span>";
            }
            else
            {
                $pass = 'pass';
            }
        }       
        
        if( $config == 'WP_DEBUG_DISPLAY' )
        {
            if( WP_DEBUG && $configs['WP_DEBUG_DISPLAY'] == 'null' && $configs["ini_set( 'display_errors' )"] == 'on' )
            {
                $pass = 'critical';
            }
            elseif( WP_DEBUG && $configs['WP_DEBUG_DISPLAY'] == 'true' )
            {
                $pass = 'critical';
            }
            else
            {
                $pass = 'pass';
            }
        }       
        
        if( $config == "ini_set( 'display_errors' )" )
        {
            if( $configs["ini_set( 'display_errors' )"] == 'on' )
            {
                $pass = 'critical';
            }
            else
            {
                $pass = 'pass';
            }
        }       
        
		return array(
			'pass' => $pass,
			'table_columns' => array(
				'Config' => $config,
				'Value' => $configs[$config],
			),
		);
        
    }


	public function title()
	{
		switch($this->pass)
		{
			case 'pass':
			return "PHP errors are not being displayed to the user";
			break;
			
			case 'fail':
			return 'PHP errors are not being displayed to the user';
			break;
			
			case 'critical':
			return 'PHP errors are being displayed to the user';
			break;
			
			case 'undetermined':
			default:
			return "Turn off the display of PHP errors";
			break;			
		}
	}
	
	protected function result_text()
	{
		switch($this->pass)
		{
			case 'pass':
			return "PHP errors are not being displayed to the user";
			break;
			
			case 'fail':
			return 'PHP errors are not being displayed to the user, but WP_DEBUG should be false';
			break;
			
			case 'critical':
			return "PHP errors are being displayed to the user";
			break;
		}
	}
	
	protected function why_important()
	{
		return <<<EOD
			
		When errors are displayed on the public site, it not only makes your site look bad, it 
		can reveal the structure of the files on the server and potential opportunities for attack.
		
EOD;
	}
	
	protected function how_to_fix()
	{
        $code1 = <<<EOD

define( 'WP_DEBUG', false );
ini_set( 'display_errors', 'off' );

EOD;
        $code1 = trim($code1);
        
        $code2 = <<<EOD

define( 'WP_DEBUG', true );           // turn on debugging
define( 'WP_DEBUG_LOG', true );       // save debug info to a file
define( 'WP_DEBUG_DISPLAY', false );  // do not display debug info in the HTML

EOD;
        $code2 = trim($code2);
        
        $content_dir = $this->strip_site_root( WP_CONTENT_DIR );
        
		return <<<EOD

        If you are not doing any debugging on a public site then add this to your wp-config.php:
	
        <code class='prettyprint'>{$code1}</code>

        If you are temporarily debugging a production site, then use this combination of settings:
        
        <code class='prettyprint'>{$code2}</code>

        The debugging info will be saved to a log file here: <br>
        <code>{$content_dir}/debug.log</code>
        
        When you're done, delete that log file since it's easily accessible.
        
EOD;
	}
	
	protected function fix_difficulty()
	{
		return 'Easy';
	}	

    protected function references()
    {
        return <<<EOD
            
        <a href='http://codex.wordpress.org/Debugging_in_WordPress'>Codex: Debugging in WordPress</a><br>

EOD;
    }
    
}