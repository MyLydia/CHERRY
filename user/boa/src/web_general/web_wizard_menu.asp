<%SendWebHeadStr(); %>
<title>Html Wizard</title>

<body>
<form action=/boaform/form2WebWizardMenu method=POST name="WebWizardMenu">
    <div class="intro_main ">
        <p class="intro_title">Wizard</p>
        <p class="intro_content">Wizard will help you to configure basic parameters of your router. </p>
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
