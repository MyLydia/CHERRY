<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>DMZ Host</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<!--ϵͳ����css-->
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<!--ϵͳ�����ű�-->
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<script type="text/javascript" src="share.js"></script>
<SCRIPT language="javascript" type="text/javascript">
var links = new Array();
with(links){<% listWanif("rt"); %>}

function on_init()
{
	with ( document.forms[0] )
	{
		for(var i = 0; i < links.length; i++)
		{
			ifname.options.add(new Option(links[i].name, links[i].ifIndex));
		}
	}
}

function skip () { this.blur(); }
function saveClick()
{
  if (document.formDMZ.dmzcap.checked)
 	return true;

  if (!checkHostIP(document.formDMZ.ip, 1))
	return false;
	
	
  return true;
}

function updateState()
{
//  if (document.formDMZ.enabled.checked) {
  if (document.formDMZ.dmzcap.checked) {
 	enableTextField(document.formDMZ.ip);
  }
  else {
 	disableTextField(document.formDMZ.ip);
  }
}

function checkChange(cb)
{
	if(cb.checked==true){
		cb.value = 1;
	}
	else{
		cb.value = 0;
	}
	updateState();
}
</SCRIPT>
</head>

<body>
<blockquote>

<DIV align="left" style="padding-left:20px; padding-top:5px">
<form action=/boaform/formDMZ method=POST name="formDMZ">
<br><br>
<p>���������ı������û�ж˿�ӳ�䣬�ᱻת����DMZ�����ϡ�</p>
<table border="0" cellpadding="0" cellspacing="0">
<tr>
	<td>�ӿ�����: </td>
	<td>
		<select name="ifname" style="width:200px "> <% if_wan_list("rt"); %> </select>
	</td>
</tr>
<tr><td>ʹ�ܣ�</td>
      <td>
		<input type="checkbox" name="dmzcap" onChange="checkChange(this)" <% checkWrite("dmz_enable"); %>>
      </td>
</tr>
<tr>
	<td>LAN��IP��ַ: </td>
	<td><input type="text" name="ip" size="15" maxlength="15" value=<% getInfo("dmzHost"); %> ></td>
</tr>
<tr>
	<td><input class="btnsaveup" type="submit" value="����/Ӧ��" name="save" onClick="return saveClick()">&nbsp;&nbsp;</td>
</tr>
<tr><td>
   <br>
        <!--input type="reset" value="Reset" name="reset"-->
        <input type="hidden" value="/fw-dmz.asp" name="submit-url">
</td></tr>
</table>
<script> 
	ifIdx = <% getInfo("dmzWan"); %>;
	if (ifIdx != 65535)
		document.formDMZ.ifname.value = ifIdx;
	else
		document.formDMZ.ifname.selectedIndex = 0;
	 updateState(); 
</script>
</form>
</DIV>
</blockquote>
</body>
</html>
