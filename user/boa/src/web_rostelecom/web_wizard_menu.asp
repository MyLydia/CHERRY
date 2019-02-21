<html>
<! Copyright (c) Realtek Semiconductor Corp., 2003. All Rights Reserved. ->
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>Html Wizard</title>
<link href="reset.css" rel="stylesheet" type="text/css" />
<link href="base.css" rel="stylesheet" type="text/css" />
<link href="style.css" rel="stylesheet" type="text/css" />
<script type="text/javascript" src="share.js"></script>
</head>
<body>
<form action=/boaform/form2WebWizardMenu method=POST name="WebWizardMenu">
    <div class="intro_main ">
        <p class="intro_title"><% multilang(LANG_WIZARD); %></p>
        <p class="intro_content"><% multilang(LANG_SETUP_WIZARD_WILL_HELP_YOU_TO_CONFIGURE_BASIC_PARAMETERS_OF_YOUR_ROUTER); %></p>
    </div>
    <br>
    <div class="adsl clearfix">
        <input class="link_bg" type="submit" name="wizard" value="Wizard"
        onclick="top.location.href='web_wizard_index.asp'">
      <input type="hidden" value="/web_wizard_index.asp" name="submit-url">
    </div>
    </form>
</body>
</html>
