<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<HTML>
<HEAD>
<TITLE>��VLAN�鲥����</TITLE>
<META http-equiv=pragma content=no-cache>
<META http-equiv=cache-control content="no-cache, must-revalidate">
<META http-equiv=content-type content="text/html; charset=gbk">
<META http-equiv=content-script-type content=text/javascript>
<STYLE type=text/css>
@import url(/style/default.css);
</STYLE>
<SCRIPT language="javascript" src="common.js"></SCRIPT>
<SCRIPT language="javascript" type="text/javascript">
var vlanArray=new Array();
<% initVlanRange(); %>
<% initCrossVlan(); %>

function getObj(id)
{
	return(document.getElementById(id));
}

function getValue(id)
{
	return(document.getElementById(id).value);
}

function setValue(id,value)
{
	document.getElementById(id).value=value;
}

/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	var vlanId;
	for(var i = 0; i < 4; i++)
	{
		vlanId = "crossLan"+i;
		setValue(vlanId, vlanArray[i]);
	}
}

function checkVLANRange(vlan)
{
	var num = reservedVlanA.length;
	for(var i = 0; i<num; i++){
		if(vlan == reservedVlanA[i])
			return false;
	}
	if(sji_checkdigitrange(vlan, otherVlanStart, otherVlanEnd) == true)
		return false;
	return true;
}

function on_submit()
{
	var vlanId;
	var tmp;
	var errstr;
	with ( document.forms[0] )
	{
		for(var i = 0; i < 4; i++)
		{
			vlanId = "crossLan"+i;
			tmp = getValue(vlanId);
			if (isNaN(parseInt(tmp)) )
			{
				alert(tmp+"��ʽ���Ϸ�!");
				return false;
			}
			tmp = parseInt(tmp);
			if (!(tmp >= 0 && tmp <= 4095))
			{
				errstr = "LAN"+(i+1)+" vlan ֵ(" + tmp + ") ���Ϸ�!";
				alert(errstr);
				return false;
			}
		}
		submit();
	}	
}
</script>

</head>

<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
    <div align="left" style="padding-left:20px; padding-top:10px">
	<form action=/boaform/formCrossVlan method=POST name="crossvlan">
		<br>�����Խ��п�VLAN�鲥���ã�ÿ��lan �ڿ�������һ���û�VLAN��</br>
		<br>�û�VLAN��Χ[0-4095]��VLAN 0��ʾ�����á�
        <br>
		<br>
		<table border="0" cellpadding="0" cellspacing="0">
			<tr>
				<td width="150">LAN1 VLAN:</td>
				<td><input type="text" maxlength="4" size="5" name="crossLan0" id="crossLan0" value=""></td>
			</tr>
			<tr>
				<td width="150">LAN2 VLAN:</td>
				<td><input type="text" maxlength="4" size="5" name="crossLan1" id="crossLan1" value=""></td>
			</tr>
			<tr>
				<td width="150">LAN3 VLAN:</td>
				<td><input type="text" maxlength="4" size="5" name="crossLan2" id="crossLan2" value=""></td>
			</tr>
			<tr>
				<td width="150">LAN4 VLAN:</td>
				<td><input type="text" maxlength="4" size="5" name="crossLan3" id="crossLan3" value=""></td>
			</tr>
		</table>
		<input type="button" class="btnsaveup" onClick="on_submit();" value="����">
		<input type="hidden" name="submit-url" value="/net_cross_vlan_cmcc.asp">
    </form>
	</div>
	<blockquote>
</body>
<%addHttpNoCache();%>
</html>

