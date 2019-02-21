<%SendWebHeadStr(); %>
<title><% multilang(LANG_GPON_SETTINGS); %></title>

<SCRIPT>
function BundleAction(name,act, bid)
{
	document.osgimgt.bundle_name.value=name;	
	document.osgimgt.bundle_action.value=act;	
	document.osgimgt.bundle_id.value=bid;	
}
</SCRIPT>
</head>

<body>
<div class="intro_main ">
	<p class="intro_title"><% multilang(LANG_BUNDLE_MANAGEMENT); %></p>
	<p class="intro_content"> <% multilang(LANG_THIS_PAGE_IS_USED_TO_MANAGE_OSGI_BUNDLES); %></p>
</div>

<form action=/boaform/admin/formOsgiMgt method=POST name="osgimgt">
<input type="hidden" value="" name="bundle_name">
<input type="hidden" value="" name="bundle_action">
<input type="hidden" value="" name="bundle_id">
  <% getOSGIBundleList("1"); %>
</form>
</body>
</html>
