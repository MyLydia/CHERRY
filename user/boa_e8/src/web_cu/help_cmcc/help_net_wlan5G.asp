<!-- add by liuxiao 2008-01-22 -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>�й��ƶ�</title>
<meta http-equiv=pragma content=no-cache>
<meta http-equiv=cache-control content="no-cache, must-revalidate">
<meta http-equiv=content-type content="text/html; charset=gbk">
<meta http-equiv=content-script-type content=text/javascript>
<style type=text/css>
@import url(/style/default.css);
</style>
<script language="javascript" src="/common.js"></script>
<SCRIPT language="javascript" type="text/javascript">
var user_mode = <% checkWrite("user_mode"); %>;
function on_init()
{
	if(user_mode == 0){
		document.getElementById("ntwk_cfgWLAN_band_mode").style.display = "none";
		document.getElementById("ntwk_cfgWLAN_sgi").style.display = "none";
		document.getElementById("wlan_share").style.display = "none";
	}
}
</script>
</head>
<body onload="on_init()">
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left">
              <table width="90%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                <td width=20>&nbsp;</td>
				<td><!-- 4. --><b>WLAN5G��������</b></td>
                </tr>
                <tr >
                  <td width=20>&nbsp;</td>
                  <td class="tabdataleft"><ul>
                      <li>ʹ������:������ر�WLAN</li>
					  <div id="ntwk_cfgWLAN_band_mode">
                      <li>ģʽѡ��:��ѡ��<i><b>802.11a</b></i>,<i><b>802.11ac</b></i>�Լ�<i><b>802.11n/a���</b></i>ģʽ</li>
                      <li>�ŵ�ѡ��:�����������ô��б���ѡ��ǡ�����ŵ���Ϊ�����źŸ���,Ӧ��ÿ��<strong><em>AP</em></strong>���䲻ͬ���ŵ�������ʹ���Զ��ŵ�ѡ��ģʽ��</li>
                      <li>���͹���ǿ��:�趨������Ƶģ��ʹ�õķ��书�ʡ� </li>
                      <li>SSID����: �趨��ǰ�����õ�SSID����š�</li>
					  </div>
                      <li>SSID: ����SSID���ơ��������������ַ�,���Ȳ��ܳ���32���ַ�,���ִ�Сд��</li>
					  <div id="ntwk_cfgWLAN_sgi">
					  <li>����: ѡ���������ӹ������ʣ����е��Զ����ʸ����ŵ��������Զ�ѡ����ʵ�������ʡ�</li>
                      <li>Ƶ��ģʽѡ��:ѡ������������802.11ac�Լ�802.11n/a���ģʽ�µ�Ƶ������</li>
                      <li>�������:ѡ������������802.11ac�Լ�802.11n/a���ģʽ�µı���ʱ������</li>
					  </div>
                      <li>SSIDʹ��:ѡ���Ƿ�ʹ�ܵ�ǰ��SSID��</li>
                      <li>�㲥ȡ��:�Ƿ�ʹ�ܶ�ӦSSID�Ĺ㲥ȡ�����ܣ����ʹ�ܣ������ز������㲥SSID��</li>
                      <li>��ȫ����:�ɶ�SSID���ð�ȫ����������֧�ֿ���ϵͳ��WEP��WPA-PSK��WPA2-PSK��WPA-PSK/WPA2-PSK����֤��ʽ�Ͷ�Ӧ�ļ��ܷ�ʽ��</li>
                      <li>WPA Ԥ��֤������Կ:���ù�����Կ��</li>
                      <li>WPA ����:ѡ����ܷ�����</li>
                    </ul></td>
                </tr>
              </table>				
			  </div>
			</div>
	</blockquote>
</body>
</html>
<!-- add end by liuxiao 2008-01-22 -->

