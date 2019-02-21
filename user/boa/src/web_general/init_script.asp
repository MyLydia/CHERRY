<%SendWebHeadStr(); %>
<title><% multilang(LANG_system_initial_script); %></title>

<script language="javascript">
function openWindow(url, windowName)
{
	var wide=640;
	var high=800;
	if (document.all)
		var xMax = screen.width, yMax = screen.height;
	else if (document.layers)
		var xMax = window.outerWidth, yMax = window.outerHeight;
	else
	   var xMax = 640, yMax=800;

	var xOffset = (xMax - wide)/2;
	var yOffset = (yMax - high)/3;

	var settings = 'width='+wide+',height='+high+',screenX='+xOffset+',screenY='+yOffset+',top='+yOffset+',left='+xOffset+', resizable=yes, toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes';

	window.open( url, windowName, settings );
}

function ShowStartScriptClick(url)
{
	openWindow(url, 'ShowStartScript');
}

function ShowEndScriptClick(url)
{
	openWindow(url, 'ShowEndScript');
}

function confirmAction()
{
	return confirm("Are you sure to delete the script file?")
}
</script>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_system_initial_script); %></p>
	<p class="intro_content"> <% multilang(LANG_SET_SCRIPTS_THAT_ARE_EXECUTED_IN_SYSTEM_INITIALING); %></p>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>Init Start Script</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<td colspan=2>This script is used to run before system initiating.</td>
			</tr>
			<tr>
				<form action=/boaform/formInitStartScript method=POST enctype="multipart/form-data" name="init_st_script">
				<td width=50%><input type="file" value=<% multilang(LANG_CHOOSE_FILE); %> name="start_text" size=36></td>
				<td><input class="inner_btn" type="submit" value=<% multilang(LANG_UPLOAD); %> name="start_upload"></td>
				</form>
			</tr>
		</table>
	</div>
</div>

<div class="btn_ctl">
	<form action=/boaform/formInitStartScriptDel method=POST name="init_st_script_del" onSubmit="return confirmAction()">
		<input class="link_bg" type="submit" value=<% multilang(LANG_SHOW_SCRIPT_CONTENT); %> onClick=ShowStartScriptClick("/StartScriptContent.asp")>&nbsp;
		<input class="link_bg" type="submit" value=<% multilang(LANG_DELETE_SCRIPT); %> name="start_delete">
	</form>
</div>

<div class="column">
	<div class="column_title">
		<div class="column_title_left"></div>
			<p>Init End Script</p>
		<div class="column_title_right"></div>
	</div>
	<div class="data_common">
		<table>
			<tr>
				<td colspan=2>This script is used to run after system initiating.</td>
			</tr>
			<tr>
				<form action=/boaform/formInitEndScript method=POST enctype="multipart/form-data" name="init_ed_script">
					<td width=50%><input type="file" value=<% multilang(LANG_CHOOSE_FILE); %> name="end_text" size=36></td>
					<td><input class="inner_btn" type="submit" value=<% multilang(LANG_UPLOAD); %> name="end_upload"></td>
				</form>
		  	</tr>
		</table>
	</div>
</div>
<div class="btn_ctl">
	<form action=/boaform/formInitEndScriptDel method=POST name="init_ed_script_del" onSubmit="return confirmAction()">
		<input class="link_bg" type="submit" value=<% multilang(LANG_SHOW_SCRIPT_CONTENT); %> onClick=ShowEndScriptClick("/EndScriptContent.asp")>&nbsp;
		<input class="link_bg" type="submit" value=<% multilang(LANG_DELETE_SCRIPT); %> name="end_delete">
	</form>
</div>
<br>
</body>
</html>

