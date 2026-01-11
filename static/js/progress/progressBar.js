import { ETACalculator } from './etaCalculator.js';

export class ProgressBarController {
    constructor(elements) {
        // Expected elements dict: 
        // { container, fill, files, time, eta, status, percentage }
        this.el = elements;
        this.etaCalc = new ETACalculator();
        this.rafId = null;
    }

    reset() {
        this.etaCalc.start();
        this.updateUI(0, 0, 0, "Initializing...");
    }

    show() {
        this.el.container.style.display = 'block'; // Or add class 'active'
        this.el.container.classList.add('active');
    }

    hide() {
        this.el.container.classList.remove('active'); // CSS transition handle display
        // setTimeout(() => this.el.container.style.display = 'none', 300);
    }

    update(statusData) {
        // statusData format from backend:
        // { progress: 0-100, status: "encrypting...", processed_count: N, total_count: M }
        // Note: Backend might need to send counts. If not, we estimate or use pure percentage.
        // For now, let's assume standard task object sends 'progress'.
        // If we want counts, we might need to update backend or parsing logs.

        // Let's assume we can get processed/total from parsed logs or updated backend status.
        // If not available, we rely on percentage for visual and time for ETA.

        const pct = statusData.progress || 0;
        // Mocking counts if missing, based on percentage (Not ideal but fallback)
        // Real implementation: Backend SHOULD send { processed, total } in `process_status`

        const processed = statusData.processed || Math.round(pct); // Fallback
        const total = statusData.total || 100; // Fallback

        const etaSeconds = this.etaCalc.update(processed, total);

        this.updateUI(pct, processed, total, statusData.status, etaSeconds);
    }

    updateUI(pct, processed, total, statusText, etaSeconds) {
        if (this.el.fill) this.el.fill.style.width = `${pct}%`;
        if (this.el.percentage) this.el.percentage.textContent = `${Math.round(pct)}%`;

        if (this.el.files) this.el.files.textContent = `${processed} / ${total}`;

        if (this.el.eta) {
            this.el.eta.textContent = ETACalculator.formatTime(etaSeconds);
        }

        if (this.el.status) this.el.status.textContent = statusText;

        // Elapsed Time Update
        if (this.el.time && this.etaCalc.startTime) {
            const elapsed = (Date.now() - this.etaCalc.startTime) / 1000;
            this.el.time.textContent = ETACalculator.formatTime(elapsed);
        }
    }
}
