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

export interface HttpRequestErrorLogEvent {
  timestamp: string;
  level: 'warn' | 'error';
  event: 'http.request.error';
  requestId: string;
  statusCode: number;
  code: 'INVALID_JSON' | 'PAYLOAD_TOO_LARGE' | 'INTERNAL_ERROR';
}

export type StructuredLogEvent =
  ApiStartedLogEvent | HttpRequestCompletedLogEvent | HttpRequestErrorLogEvent;

export interface StructuredLogger {
  write(event: StructuredLogEvent): void;
}

export const consoleStructuredLogger: StructuredLogger = {
  write(event) {
    const message = JSON.stringify(event);

    switch (event.level) {
      case 'error':
        console.error(message);
        break;

      case 'warn':
        console.warn(message);
        break;

      case 'info':
        console.info(message);
        break;
    }
  },
};

export const noopStructuredLogger: StructuredLogger = {
  write() {},
};
