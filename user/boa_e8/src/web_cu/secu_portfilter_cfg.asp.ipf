<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<!--ϵͳĬ��ģ��-->
<HTML>
<HEAD>
<TITLE>�˿ڹ���</TITLE>
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
<SCRIPT language="javascript" type="text/javascript">

var cgi = new Object();
<%ipPortFilterDirConfig();%>
/********************************************************************
**          on document load
********************************************************************/
function on_init()
{
	sji_docinit(document, cgi);
	//alert("cgi.ipfilterInEnable="+cgi.ipfilterInEnable);
	//alert("cgi.ipfilterOutEnable="+cgi.ipfilterOutEnable);
	//alert("cgi.ipfilterInAction="+cgi.ipfilterInAction);
	//alert("cgi.ipfilterOutAction="+cgi.ipfilterOutAction);	
	
	//down stream
	if(cgi.ipfilterInEnable == false)
	{
		form_in.ipFilterInMode[0].disabled = true;
		form_in.ipFilterInMode[1].disabled = true;
		if(cgi.ipfilterInAction == true){
			form_in.ipFilterInMode[0].checked = true;
		}
		else{
			form_in.ipFilterInMode[1].checked = true;
		}		
		policy_frame_in.src = "about:blank";
	}
	else
	{
		var surl_in = ( (cgi.ipfilterInAction == true)? "secu_portfilter_blk_in.asp" : "secu_portfilter_wht_in.asp");
		policy_frame_in.src = surl_in;
		if(cgi.ipfilterInAction == true){
			form_in.ipFilterInMode[0].checked = true;
		}
		else{
			form_in.ipFilterInMode[1].checked = true;
		}
		
	}
	//upstream
	//alert(cgi.ipfilterOutEnable);
	if(cgi.ipfilterOutEnable == false)
	{
		form_out.ipFilterOutMode[0].disabled = true;
		form_out.ipFilterOutMode[1].disabled = true;
		if(cgi.ipfilterOutAction == true){
			form_out.ipFilterOutMode[0].checked = true;
		}
		else{
			form_out.ipFilterOutMode[1].checked = true;			
		}
		policy_frame_out.src = "about:blank";
	}
	else
	{
		var surl_out = ( (cgi.ipfilterOutAction == true)? "secu_portfilter_blk_out.asp" : "secu_portfilter_wht_out.asp");
		policy_frame_out.src = surl_out;
		if(cgi.ipfilterOutAction == true){
			form_out.ipFilterOutMode[0].checked = true;
		}
		else{
			form_out.ipFilterOutMode[1].checked = true;			
		}		
	}
	
}

function on_action_in(act)
{
	form_in.action.value = act;
	var cur_ipfilterInEnable = 0;
	var cur_ipFilterInMode = 0;
	cur_ipFilterInMode = (form_in.ipFilterInMode.value == "on") ? 1:0;
	//alert("cur_ipFilterInMode="+cur_ipFilterInMode);	
    cur_ipfilterInEnable =  (form_in.ipfilterInEnable.value == "on") ? 1:0;
	//alert("cur_ipfilterInEnable="+cur_ipfilterInEnable);
	if(cur_ipfilterInEnable == 0)
	{
		if(cur_ipFilterInMode)
			form_in.ipFilterInMode[0].checked = true;
		else
			form_in.ipFilterInMode[1].checked = true;
		policy_frame_in.src = "about:blank";		
	}else{
		form_in.ipFilterInMode[0].disabled = false;
		form_in.ipFilterInMode[1].disabled = false;
		if(cur_ipFilterInMode)
			form_in.ipFilterInMode[0].checked = true;
		else
			form_in.ipFilterInMode[1].checked = true;	
		var surl_in = ( (form_in.ipFilterInMode[0].checked == true)? "secu_portfilter_blk_in.asp" : "secu_portfilter_wht_in.asp");
		policy_frame_in.src = surl_in;	
	}
	with(form_in)
	{
		submit();
	}
}

function on_action_out(act)
{
	form_out.action.value = act;
	var cur_ipfilterOutEnable = 0;
	var cur_ipFilterOutMode = 0;
	cur_ipFilterOutMode = (form_out.ipFilterOutMode.value == "on") ? 1:0;
	//alert(cur_ipFilterOutMode);
	//alert("cur_ipFilterOutMode="+cur_ipFilterOutMode);	
	cur_ipfilterOutEnable = (form_out.ipfilterOutEnable.value == "on") ? 1:0;
	//alert("cur_ipfilterOutEnable="+cur_ipfilterOutEnable);	
	//alert(cur_ipfilterOutEnable);
	if(cur_ipfilterOutEnable == 0)
	{
		if(cur_ipFilterOutMode)
			form_out.ipFilterOutMode[0].checked = true;
		else
			form_out.ipFilterOutMode[1].checked = true;
		//form_out.ipFilterOutMode[1].disabled = true;
		policy_frame_out.src = "about:blank";		
	}else{
		form_out.ipFilterOutMode[0].disabled = false;
		form_out.ipFilterOutMode[1].disabled = false;
		if(cur_ipFilterOutMode)
			form_out.ipFilterOutMode[0].checked = true;
		else
			form_out.ipFilterOutMode[1].checked = true;		
		var surl_out = ( (form_out.ipFilterOutMode[0].checked == true)? "secu_portfilter_blk_out.asp" : "secu_portfilter_wht_out.asp");
		policy_frame_out.src = surl_out;	
	}
	with(form_out)
	{
		submit();
	}	
}


function on_mode_in()
{
	var surl_in = ( (form_in.ipFilterInMode[0].checked == true)? "secu_portfilter_blk_in.asp" : "secu_portfilter_wht_in.asp");
	policy_frame_in.src = surl_in;
	with(form_in)
	{
		submit();
	}	
}

function on_mode_out()
{
	var surl_out = ( (form_out.ipFilterOutMode[0].checked == true)? "secu_portfilter_blk_out.asp" : "secu_portfilter_wht_out.asp");
	policy_frame_out.src = surl_out;
	with(form_out)
	{
		submit();
	}
}
</SCRIPT>
</HEAD>
<!-------------------------------------------------------------------------------------->
<!--��ҳ����-->
<body topmargin="0" leftmargin="0" marginwidth="0" marginheight="0" alink="#000000" link="#000000" vlink="#000000" onLoad="on_init();">
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form_out" action=/boaform/admin/formPortFilterOut method=POST name="form_out">
				<b>�˿ڹ��� -- ������������ 16������.</b><br><br>
				<!--
				<div id="rstip" style="display:none;"><font color="red">��ʾ����ҳ������ã���Ҫ����·����������Ч��</font><br></div>
				-->
				<hr align="left" class="sep" size="1" width="90%">
				<table border="0" cellpadding="2" cellspacing="0">
					<tr>
						<td>�������еĶ˿ڹ��˹���:</td>
						<td><input type="radio" name="ipfilterOutEnable" value="off" onClick="on_action_out('sw')">&nbsp;&nbsp;����</td>
						<td><input type="radio" name="ipfilterOutEnable" value="on" onClick="on_action_out('sw')">&nbsp;&nbsp;����</td>
						<!--
						<td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color="red"><b>ע����Internet���Ӳ������ã�</b></font></td>
						-->
					</tr>
					<tr>
						<td>����ģʽ:</td>
						<td><input type="radio" name="ipFilterOutMode" value="on" onClick="on_action_out('sw')" checked>&nbsp;&nbsp;������</td>
						<td><input type="radio" name="ipFilterOutMode" value="off" onClick="on_action_out('sw')">&nbsp;&nbsp;������</td>
						<!--<td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color="red"><b>ע���ڰ�������ͬʱ�����ģ�</b></font></td>-->
					</tr>
				</table>
				<br>
				<hr align="left" class="sep" size="1" width="90%">
				<input type="hidden" id="action" name="action" value="sw">
				<input type="hidden" name="submit-url" value="/secu_portfilter_cfg.asp" >
			</form>
		</div>
	</blockquote>
	<iframe src="about:blank" id="policy_frame_out" width="90%" frameborder="0" style="border-style:none; height:30%"  scrolling="auto"></iframe>
	<blockquote>
		<DIV align="left" style="padding-left:20px; padding-top:5px">
			<form id="form_in" action=/boaform/admin/formPortFilterIn method=POST name="form_in">
				<b>�˿ڹ��� -- ������������ 16������.</b><br><br>
				<!--
				<div id="rstip" style="display:none;"><font color="red">��ʾ����ҳ������ã���Ҫ����·����������Ч��</font><br></div>
				-->
				<hr align="left" class="sep" size="1" width="90%">
				<table border="0" cellpadding="2" cellspacing="0">
					<tr>
						<td>�������еĶ˿ڹ��˹���:</td>
						<td><input type="radio" name="ipfilterInEnable" value="off" onClick="on_action_in('sw')">&nbsp;&nbsp;����</td>
						<td><input type="radio" name="ipfilterInEnable" value="on" onClick="on_action_in('sw')">&nbsp;&nbsp;����</td>
						<!--
						<td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color="red"><b>ע����Internet���Ӳ������ã�</b></font></td>
						-->
					</tr>
					<tr>
						<td>����ģʽ:</td>
						<td><input type="radio" name="ipFilterInMode" value="on" onClick="on_action_in('sw')" checked>&nbsp;&nbsp;������</td>
						<td><input type="radio" name="ipFilterInMode" value="off" onClick="on_action_in('sw')">&nbsp;&nbsp;������</td>
						<!--<td>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<font color="red"><b>ע���ڰ�������ͬʱ�����ģ�</b></font></td>-->
					</tr>					
				</table>
				<br>
				<hr align="left" class="sep" size="1" width="90%">
				<input type="hidden" id="action" name="action" value="sw">
				<input type="hidden" name="submit-url" value="/secu_portfilter_cfg.asp" >
			</form>
		</div>
	</blockquote>	
	<iframe src="about:blank" id="policy_frame_in" width="90%" frameborder="0" style="border-style:none; height:30%"  scrolling="auto"></iframe>	
</body>
<%addHttpNoCache();%>
</html>
