export interface ApiStartedLogEvent {
  timestamp: string;
  level: 'info';
  event: 'api.started';
  port: number;
}

export interface HttpRequestCompletedLogEvent {
  timestamp: string;
  level: 'info';
  event: 'http.request.completed';
  requestId: string;
  method: string;
  path: string;
  statusCode: number;
  durationMs: number;
}

export type StructuredLogEvent = ApiStartedLogEvent | HttpRequestCompletedLogEvent;

export interface StructuredLogger {
  write(event: StructuredLogEvent): void;
}

export const consoleStructuredLogger: StructuredLogger = {
  write(event) {
    console.info(JSON.stringify(event));
  },
};

export const noopStructuredLogger: StructuredLogger = {
  write() {},
};
