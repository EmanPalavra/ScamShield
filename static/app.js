document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("scan-form");
    const message = document.getElementById("message");
    const characterCount = document.getElementById("character-count");

    function updateCharacterCount() {
        if (!message || !characterCount) {
            return;
        }

        const maximum = Number(message.maxLength) || 0;
        characterCount.textContent = `${message.value.length} / ${maximum}`;
        characterCount.classList.toggle("near-limit", maximum > 0 && message.value.length >= maximum * 0.9);
    }

    if (message) {
        message.addEventListener("input", updateCharacterCount);
        updateCharacterCount();
    }

    if (form) {
        form.addEventListener("submit", (event) => {
            if (!form.checkValidity()) {
                return;
            }

            const submittedButton = event.submitter;
            const buttons = form.querySelectorAll(".scan-submit");
            form.setAttribute("aria-busy", "true");

            if (submittedButton) {
                const label = submittedButton.querySelector("span");
                if (label) {
                    label.textContent = submittedButton.dataset.loadingLabel || "Scanning…";
                }
            }

            buttons.forEach((button) => {
                button.setAttribute("aria-disabled", "true");
                button.classList.add("is-loading");
            });
        });
    }

    const results = document.getElementById("scan-results");
    if (results) {
        const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        results.scrollIntoView({ behavior: reducedMotion ? "auto" : "smooth", block: "start" });
        results.focus({ preventScroll: true });
    }
});
