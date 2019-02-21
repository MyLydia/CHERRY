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
		document.getElementById("reset_default").innerText ="恢复配置:恢复默认配置。";
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
                  <td >&nbsp;</td>
                  <td><!-- 2. --><b>设备管理</b></td>
                </tr>
                <tr>
                  <td width=20>&nbsp;</td>
                  <td><ul>
                      <li>设备重启:使用该操作,重新启动网关。</li>
                      <li  style="display:none">清除日志记录:使用该操作,清除当前所有日志。</li>
					  <li id="reset_default">恢复配置:恢复默认配置和恢复出厂配置功能。</li>
                    </ul></td>
                </tr>
            </table>			
			</div>
		</div>
	</blockquote>
</body>
</html>
<!-- add end by liuxiao 2008-01-22 -->

