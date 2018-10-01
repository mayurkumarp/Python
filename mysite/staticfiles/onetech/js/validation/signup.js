$(document).ready(function () {
        $('#signup-form').validate({
            rules: {
                username :{
                    required:true,
                    maxlength: 12,
                },
                first_name : {
                    required: true,
                    lettersonly: true,
                    maxlength: 25,

                },
                last_name : {
                    required: true,
                    lettersonly: true,
                    maxlength: 25,

                },
                email : {
                    required: true,
                    maxlength: 50,
                    email:true,
                },
                phone : {
                    required: true,
                    digits: true,
                    maxlength: 10,
                    minlength: 10,
                },
                password1: {
                     required: true,
                },
                password2: {
                     required: true,
                },

            },
            messages: {
                 username: {
                     required: "Enter your username.",
                },
                first_name: "Enter your first name.",
                last_name: "Enter your last name.",
                email: {
                     required: "Enter your email address.",
                     email: "Please enter a valid email address.",

                },
                phone: {
                     required: "Enter your phone number.",
                },
                password1: {
                     required: "Enter your password.",
                },
                password2: {
                     required: "Enter your confirm password.",
                },
            },
            errorClass: "my-error-class",

        });
    });
