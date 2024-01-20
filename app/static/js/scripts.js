$("form[name=signup_form]").submit(function(e) {

    var $form = $(this);
    var $error = $form.find(".error_message");
    var $confirm = $form.find(".confirm_message");
    var data = $form.serialize();

    $.ajax({
        url: "/register",
        type: "POST",
        data: data,
        dataType: "json",
        success: function(resp){ 
            $confirm.text(resp.info);
        },
        error: function(resp){  
            $error.text(resp.responseJSON.error);
        }
    });

    e.preventDefault();
});


$("form[name=login_form]").submit(function(e) {

    var $form = $(this);
    var $error = $form.find(".error");
    var data = $form.serialize();

    $.ajax({
        url: "/user/login",
        type: "POST",
        data: data,
        dataType: "json",
        success: function(resp){ 
            window.location.href = "/dashboard/"; 
        },
        error: function(resp){ 
            $error.text(resp.responseJSON.error).removeClass("error--hidden");
        }
    });
    e.preventDefault();
});

$("form[name=reset_form]").submit(function(e) {

    var $form = $(this);
    var $error = $form.find(".error");
    var $confirm = $form.find(".confirm");
    var data = $form.serialize();

    $.ajax({
        url: "/user/reset",
        type: "POST",
        data: data,
        dataType: "json",
        success: function(resp){
            $confirm.text(resp.info).removeClass("confirm--hidden");
        },
        error: function(resp){
            $error.text(resp.responseJSON.error).removeClass("error--hidden");
        }
    });

    e.preventDefault();
});

$("form[name=change_password_form]").submit(function(e) {

    var $form = $(this);
    var $error = $form.find(".error");
    var $confirm = $form.find(".confirm");
    var data = $form.serialize();

    $.ajax({
        url: window.location.pathname,
        type: "POST",
        data: data,
        dataType: "json",
        success: function(resp){ 
            $confirm.text(resp.info).removeClass("confirm--hidden");
            setTimeout(function() {
                window.location.href = "/login/";
              }, 5000);
             
        },
        error: function(resp){ 
            $error.text(resp.responseJSON.error).removeClass("error--hidden");
        }
    });

    e.preventDefault();
});