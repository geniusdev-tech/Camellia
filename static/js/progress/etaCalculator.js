export class ETACalculator {
    constructor(smoothingFactor = 0.5) {
        this.startTime = null;
        this.lastTime = null;
        this.lastProcessed = 0;
        this.smoothingFactor = smoothingFactor; // 0 to 1 (higher = more reactive, lower = smoother)
        this.avgSpeed = 0; // items per second
    }

    start() {
        this.startTime = Date.now();
        this.lastTime = this.startTime;
        this.lastProcessed = 0;
        this.avgSpeed = 0;
    }

    update(processed, total) {
        const now = Date.now();
        if (!this.startTime) this.start();

        const deltaTime = (now - this.lastTime) / 1000; // seconds
        const deltaItems = processed - this.lastProcessed;

        if (deltaTime > 0 && deltaItems >= 0) {
            const currentSpeed = deltaItems / deltaTime;

            // Initialize avgSpeed if first update
            if (this.avgSpeed === 0) {
                this.avgSpeed = currentSpeed;
            } else {
                // Exponential Moving Average
                this.avgSpeed = (this.smoothingFactor * currentSpeed) + ((1 - this.smoothingFactor) * this.avgSpeed);
            }
        }

        this.lastTime = now;
        this.lastProcessed = processed;

        return this.calculateETA(processed, total);
    }

    calculateETA(processed, total) {
        if (this.avgSpeed <= 0.0001) return null; // Too slow or stalled

        const remaining = total - processed;
        const secondsLeft = remaining / this.avgSpeed;

        return secondsLeft;
    }

    static formatTime(seconds) {
        if (seconds === null || !isFinite(seconds)) return "--:--";
        if (seconds < 60) return `${Math.floor(seconds)}s`;

        const m = Math.floor(seconds / 60);
        const s = Math.floor(seconds % 60);

        if (m < 60) return `${m}m ${s}s`;

        const h = Math.floor(m / 60);
        const remM = m % 60;
        return `${h}h ${remM}m`;
    }
}
