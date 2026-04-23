document.addEventListener("DOMContentLoaded", () => {
    const canvas = document.getElementById("bg");
    if (!canvas) {
        return;
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) {
        return;
    }

    const glyphs = "01";
    const fontSize = 16;
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let columns = [];
    let lastFrameTime = 0;

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        const columnCount = Math.ceil(canvas.width / 28);
        columns = Array.from({ length: columnCount }, (_, index) => ({
            x: 14 + (index * 28),
            y: Math.random() * (canvas.height + 180) - 180,
            speed: 10 + Math.random() * 14,
            opacity: 0.12 + Math.random() * 0.12,
            glyph: glyphs[Math.floor(Math.random() * glyphs.length)],
        }));
    }

    function drawStaticGrid() {
        ctx.strokeStyle = "rgba(84, 242, 195, 0.035)";
        ctx.lineWidth = 1;

        for (let x = 0; x < canvas.width; x += 56) {
            ctx.beginPath();
            ctx.moveTo(x, 0);
            ctx.lineTo(x, canvas.height);
            ctx.stroke();
        }
    }

    function drawColumns(deltaSeconds) {
        ctx.font = `${fontSize}px monospace`;
        ctx.textAlign = "center";

        columns.forEach((column, index) => {
            column.y += column.speed * deltaSeconds;

            if (column.y > canvas.height + 28) {
                column.y = -20 - Math.random() * 120;
                column.glyph = glyphs[Math.floor(Math.random() * glyphs.length)];
                column.opacity = 0.12 + Math.random() * 0.12;
            }

            if (index % 3 === 0) {
                ctx.fillStyle = `rgba(84, 242, 195, ${column.opacity * 0.55})`;
                ctx.fillRect(column.x - 1, 0, 1, canvas.height);
            }

            ctx.fillStyle = `rgba(92, 208, 255, ${column.opacity})`;
            ctx.fillText(column.glyph, column.x, column.y);
        });
    }

    function render(timestamp) {
        const deltaSeconds = Math.min((timestamp - lastFrameTime) / 1000, 0.05) || 0.016;
        lastFrameTime = timestamp;

        ctx.clearRect(0, 0, canvas.width, canvas.height);
        drawStaticGrid();
        drawColumns(prefersReducedMotion ? 0.12 : deltaSeconds);
        requestAnimationFrame(render);
    }

    resize();
    window.addEventListener("resize", resize);
    requestAnimationFrame(render);
});
