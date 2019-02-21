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
		document.getElementById("admin_only_1").style ="display:none";
		document.getElementById("admin_only_2").style ="display:none";
		document.getElementById("admin_only_3").style ="display:none";
}
}
</script>
</head>
<body>
	<blockquote>
		<div align="left" style="padding-left:20px;"><br>
			<div align="left">
			<table width="90%" border="0" cellspacing="0" cellpadding="0">
			
                <tr>
                  <td width=20>&nbsp;</td>
                  <td><!-- 1. --><b>用户管理<b/></td>
                </tr>
                <tr id="admin_only_1">
                  <td width=20>&nbsp;</td>
                  <td>&nbsp;(1)维护账号</td>
                </tr>
                <tr id="admin_only_2">
                  <td width=20>&nbsp;</td>
                  <td><ul>
                      <li>密码设置:使用维护帐号登录后，可以修改用户管理帐号的密码，而不需要校验原密码。</li>
                    </ul></td>
                </tr>
                <tr id="admin_only_3">
                  <td width=20>&nbsp;</td>
                  <td>&nbsp;(2)用户管理帐号</td>
                </tr>
                <tr>
                  <td width=20>&nbsp;</td>
                  <td><ul>
                      <li>用户管理帐号和密码设置:使用用户管理帐号登录后,可修改用户管理帐号的密码，需要校验原密码。 </li>
                    </ul></td>
                </tr>
            </table>			
			</div>
		</div>
		<script>
		on_init();
		</script>			

	</blockquote>
</body>
</html>
<!-- add end by liuxiao 2008-01-22 -->

