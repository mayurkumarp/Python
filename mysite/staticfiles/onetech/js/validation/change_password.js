$(document).ready(function () {
        $('#change-password').validate({
        rules: {
            old_password :{
                required:true,

            },
            new_password1 : {
                required: true,
            },
            new_password2 : {
                required: true,
            },

        },
        messages: {
            old_password : "Please enter your old password",
            new_password1: "Please enter your new password",
            new_password2: "Please enter your confirm password",

        },
        errorClass: "my-error-class",
        validClass: "my-valid-class",


    });
 });