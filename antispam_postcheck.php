<?php
// https://github.com/roundcube/roundcubemail/wiki/Plugin-Hooks#task-mail
class antispam_postcheck extends rcube_plugin
{
    public $task = 'mail';

    public function init()
    {
        $rcmail = rcmail::get_instance();
        $this->load_config();
        $this->add_hook('storage_init', array($this, 'storage_init'));
        $this->add_hook('message_objects', array($this, 'message_objects'));
    }
    public function storage_init($p)
    {
        $rcmail             = rcmail::get_instance();
        $add_headers        = array('Received');
        $p['fetch_headers'] = trim($p['fetch_headers'] . ' ' . strtoupper(join(' ', $add_headers)));
        return $p;
    }
    public function message_objects($p)
    {
        $rcmail          = rcmail::get_instance();
        $ignore_received = $rcmail->config->get('antispam_ignore_received');
        if (isset($p['message']->headers->others['received'])) {
            $n = 0;

            while (isset($p['message']->headers->others['received'][$n])) {
                foreach ($ignore_received as $value) {
                    if (strpos($p['message']->headers->others['received'][$n], $value) !== false) {
                        $n++;
                        continue;
                    }
                }
                break;
            }
            $color_box = "#cccccc";
            if (preg_match("/^from (\S+) \((\S+) \[(\S+)\]\).*/", $p['message']->headers->others['received'][$n], $array_parsed)) {
                $octets      = explode('.', $array_parsed[3]);
                $name_lookup = $octets[3] . "." . $octets[2] . "." . $octets[1] . "." . $octets[0] . ".origin.asn.cymru.com";
                $ret         = dns_get_record($name_lookup, DNS_TXT);
                if (isset($ret[0]['entries'][0])) {
                    $display = $array_parsed[3] . " ASINFO:" . $ret[0]['entries'][0];
                    if (preg_match("/^([0-9]+) /", $ret[0]['entries'][0], $arr_asn)) {
                        $name_lookup = "AS" . $arr_asn[1] . ".asn.cymru.com";
                        $ret         = dns_get_record($name_lookup, DNS_TXT);
                        if (isset($ret[0]['entries'][0])) {
                            $display .= " ASNAME:" . $ret[0]['entries'][0];
                        }
                    }
                }
                $name_lookup = $octets[3] . "." . $octets[2] . "." . $octets[1] . "." . $octets[0] . ".dnsbl-1.uceprotect.net";
                $ret         = dns_get_record($name_lookup, DNS_A);
                
                if (isset($ret[0])) {
                    $color_box = '#FF0000';
                    //$display .= " ADD ".$ret[0]['entries'][0];
                }

                if ($color_box == "#cccccc") {
                    $name_lookup = $octets[3] . "." . $octets[2] . "." . $octets[1] . "." . $octets[0] . ".bl.mailspike.net";
                    $ret         = dns_get_record($name_lookup, DNS_A);
                    if (isset($ret[0])) {
                        $color_box = 'pink';
                        //$display .= " ADD ".$ret[0]['entries'][0];
                    }

                }

            } else {
                $display = $p['message']->headers->others['received'][$n];
            }
            $attrib['id']    = 'antispam-infobox';
            $attrib['class'] = 'notice';
            $attrib['style'] = 'background-color: ' . $color_box . ';';

            $msg            = html::span(null, rcube::Q($display));
            $p['content'][] = html::div($attrib, $msg . '&nbsp;');

            /*
        $p['content'][] = html::p(array('class' => 'aligned-buttons boxinformation'),
        html::span(null, rcube::Q($display))
        );
         */
        }
        return ($p);
    }
}
