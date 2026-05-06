document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("captcha_refresh");
    var img = document.getElementById("captcha_image");

    if (btn && img) {
        btn.addEventListener("click", function (e) {
            e.preventDefault();
            img.src = "/captcha?" + Date.now();
        });
    }
});
