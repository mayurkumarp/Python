$(document).ready(function () {
    $('#login-form').validate({

      rules: {
            username :{
                required:true,
            },
            password : {
                required: true,
            },
        },
         messages: {
             username: {
                 required: "Enter your username.",
            },
            password: {
                 required: "Enter your password.",
            },
        },
        errorClass: "my-error-class",


    });
});