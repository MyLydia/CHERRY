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
		document.getElementById("itms_stats").style.display = "none";
		document.getElementById("itms_server").style.display = "none";
		document.getElementById("itms_action").innerHTML = "&nbsp;(1).����";
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
                  <td><b>Զ�̹���</b></td>
                </tr>
                <tr id="itms_stats">
                 <td width=20>&nbsp;</td>
                  <td>&nbsp;(1).״̬��ʾ</td>
                </tr>
                <tr id="itms_server">
                  <td width=20>&nbsp;</td>
                  <td><ul>
                      <li>ʡ�����ּ�ͥ����ƽ̨������</li>
                      <li><!-- OLT -->��֤</li>
                    </ul></td>
                </tr>
                <tr>
                  <td width=20>&nbsp;</td>
                  <td id="itms_action">&nbsp;(2).����</td>
                </tr>
                <tr >
                 <td  width=20>&nbsp;</td>
                 <td><ul>
                      <li id="itms_register">��������ʡ�����ּ�ͥ����ƽ̨��������URL����IP��ַ��RMS��֤���ص��û��������룬�Լ�������֤RMS���û��������롣ͬʱ���������������Ƿ����������ϱ����ģ��Լ��ϱ����ĵ����ڡ����⻹���Խ���֤����֤�����û���á�</li>
                      <li><!-- OLT -->��֤ע��</li>
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

