// 原登录的js代码
function login() {

    var $u = $("#un"), $p = $("#pd");

    var u = $u.val().trim();
    if (u == "") {
        $u.focus();
        $("#errormsg").text("账号不能为空。");
        $("#help-link").hide();
        return;
    }

    var p = $p.val().trim();
    if (p == "") {
        $p.focus();
        $("#errormsg").text("密码不能为空。");
        $("#help-link").hide();
        return;
    }

    $u.attr("disabled", "disabled");
    $p.attr("disabled", "disabled");

    var lt = $("#lt").val();

    $("#ul").val(u.length);
    $("#pl").val(p.length);
    $("#sl").val(0);
    $("#rsa").val(strEnc(u + p + lt, '1', '2', '3'));

    $("#loginForm")[0].submit();
}
