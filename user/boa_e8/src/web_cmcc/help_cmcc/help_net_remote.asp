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
		document.getElementById("itms_stats").style.display = "none";
		document.getElementById("itms_server").style.display = "none";
		document.getElementById("itms_action").innerHTML = "&nbsp;(1).操作";
		document.getElementById("itms_register").style.display = "none";
	}
}
</script>
</head>
<body onload="on_init()">
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left">
				<div id="itms">
				<table width="90%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td width=20>&nbsp;</td>
                  <td><b>远程管理</b></td>
                </tr>
                <tr id="itms_stats">
                 <td width=20>&nbsp;</td>
                  <td>&nbsp;(1).状态显示</td>
                </tr>
                <tr id="itms_server">
                  <td width=20>&nbsp;</td>
                  <td><ul>
                      <li>省级数字家庭管理平台服务器</li>
                      <li><!-- OLT -->认证</li>
                    </ul></td>
                </tr>
                <tr>
                  <td width=20>&nbsp;</td>
                  <td id="itms_action">&nbsp;(2).操作</td>
                </tr>
                <tr >
                 <td  width=20>&nbsp;</td>
                 <td><ul>
                      <li id="itms_register">用于设置省级数字家庭管理平台服务器的URL或者IP地址，RMS认证网关的用户名和密码，以及网关认证RMS的用户名和密码。同时还可以配置网关是否发送周期性上报报文，以及上报报文的周期。另外还可以进行证书认证的启用或禁用。</li>
                      <li><!-- OLT -->认证注册</li>
                    </ul></td>
                </tr>
				</table>	
				</div>			  
			  </div>
		</div>
	</blockquote>
</body>
</html>
<!-- add end by liuxiao 2008-01-22 -->

