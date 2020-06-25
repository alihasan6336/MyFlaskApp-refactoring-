function myFunction() {
    var password = document.querySelector("#passwordlabel");
    var confirm = document.querySelector("#confirmlabel");

    if (password.type === "password") {
        password.type = "text";
        confirm.type = "text";
    } else {
        password.type = "password";
        confirm.type = "password";
    }
}