document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("form[action='/admin/users/delete']").forEach(function (form) {
        form.addEventListener("submit", function (e) {
            var name = form.closest("tr").cells[1].textContent.trim();
            if (!confirm("Delete " + name + "? This cannot be undone.")) {
                e.preventDefault();
            }
        });
    });
});
