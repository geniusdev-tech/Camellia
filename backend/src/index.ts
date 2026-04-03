import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import * as dotenv from 'dotenv';
import authRouter from './routes/auth';
import accessRouter from './routes/access';
import projectsRouter from './routes/projects';
import auditRouter from './routes/audit';
import opsRouter from './routes/ops';
import { requestObservability, metricsRegistry } from './middleware/observability';
import path from 'path';
import fs from 'fs';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security and utility middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
    },
  },
  crossOriginResourcePolicy: false,
}));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN ? process.env.ALLOWED_ORIGIN.split(',') : '*',
  credentials: true,
}));
app.use(morgan('dev'));
app.use(express.json());
app.use(requestObservability);

// API Routes
app.use('/api/auth', authRouter);
app.use('/api/access', accessRouter);
app.use('/api/projects', projectsRouter);
app.use('/api/audit', auditRouter);
app.use('/api/ops', opsRouter);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: '2.1.0' });
});

// Metrics
app.get('/api/ops/metrics', (req, res) => {
  res.json({ success: true, metrics: metricsRegistry.snapshot() });
});

// Serve frontend static files
const staticPath = path.join(__dirname, '../../static/dist');
app.use(express.static(staticPath));

// Catch-all route for SPA
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not Found' });
  }
  const indexPath = path.join(staticPath, 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({ error: 'Frontend not found' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on 0.0.0.0:${PORT}`);
});
