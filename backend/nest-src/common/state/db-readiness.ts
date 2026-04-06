let dbReady = false;

export function markDbReady(): void {
  dbReady = true;
}

export function isDbReady(): boolean {
  return dbReady;
}

export function setDbReady(value: boolean): void {
  dbReady = value;
}
