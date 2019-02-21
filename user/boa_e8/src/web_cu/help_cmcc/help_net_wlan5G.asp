<!-- add by liuxiao 2008-01-22 -->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html>
<head>
<title>中国移动</title>
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
				<td><!-- 4. --><b>WLAN5G参数配置</b></td>
                </tr>
                <tr >
                  <td width=20>&nbsp;</td>
                  <td class="tabdataleft"><ul>
                      <li>使能无线:开启或关闭WLAN</li>
					  <div id="ntwk_cfgWLAN_band_mode">
                      <li>模式选择:可选择<i><b>802.11a</b></i>,<i><b>802.11ac</b></i>以及<i><b>802.11n/a混合</b></i>模式</li>
                      <li>信道选择:根据网络设置从列表中选择恰当的信道。为避免信号干扰,应对每个<strong><em>AP</em></strong>分配不同的信道，建议使用自动信道选择模式。</li>
                      <li>发送功率强度:设定无线射频模块使用的发射功率。 </li>
                      <li>SSID索引: 设定当前所配置的SSID的序号。</li>
					  </div>
                      <li>SSID: 设置SSID名称。可以输入任意字符,长度不能超过32个字符,区分大小写。</li>
					  <div id="ntwk_cfgWLAN_sgi">
					  <li>速率: 选择无线连接工作速率，其中的自动速率根据信道环境，自动选择合适的最大速率。</li>
                      <li>频宽模式选择:选择无线网络在802.11ac以及802.11n/a混合模式下的频道带宽。</li>
                      <li>保护间隔:选择无线网络在802.11ac以及802.11n/a混合模式下的保护时间间隔。</li>
					  </div>
                      <li>SSID使能:选择是否使能当前的SSID。</li>
                      <li>广播取消:是否使能对应SSID的广播取消功能，如果使能，则网关不会对外广播SSID。</li>
                      <li>安全设置:可对SSID设置安全参数，网关支持开放系统、WEP、WPA-PSK、WPA2-PSK、WPA-PSK/WPA2-PSK等认证方式和对应的加密方式。</li>
                      <li>WPA 预认证共享密钥:设置共享密钥。</li>
                      <li>WPA 加密:选择加密方法。</li>
                    </ul></td>
                </tr>
              </table>				
			  </div>
			</div>
	</blockquote>
</body>
</html>
<!-- add end by liuxiao 2008-01-22 -->

