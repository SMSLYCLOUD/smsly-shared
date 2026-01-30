"""
Frontend Audit Client (TypeScript/JavaScript)
==============================================
Copy this to frontend apps for client-side audit logging.
Sends events through Security Gateway.
"""

// audit.ts - Copy to smsly-frontend, smsly-backoffice-web, smsly-desktop-app

interface AuditEvent {
  event_type: string;
  action: string;
  actor_id?: string;
  resource_type?: string;
  resource_id?: string;
  outcome?: 'success' | 'failure' | 'blocked';
  category?: string;
  severity?: string;
  payload?: Record<string, any>;
}

class AuditClient {
  private gatewayUrl: string;
  private serviceName: string;

  constructor() {
    this.gatewayUrl = process.env.NEXT_PUBLIC_GATEWAY_URL || 'http://localhost:8000';
    this.serviceName = process.env.NEXT_PUBLIC_SERVICE_NAME || 'smsly-frontend';
  }

  async logEvent(event: AuditEvent): Promise<boolean> {
    const timestamp = new Date().toISOString();

    const body = JSON.stringify({
      service: this.serviceName,
      event_type: event.event_type,
      event_category: event.category || 'general',
      severity: event.severity || 'info',
      action: event.action,
      actor_id: event.actor_id || 'anonymous',
      actor_type: event.actor_id ? 'user' : 'system',
      resource_type: event.resource_type,
      resource_id: event.resource_id,
      outcome: event.outcome || 'success',
      payload: event.payload || {},
    });

    try {
      const response = await fetch(`${this.gatewayUrl}/api/v1/audit/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Service-Name': this.serviceName,
          'X-Service-Timestamp': timestamp,
        },
        body,
      });

      return response.ok;
    } catch (error) {
      console.error('Audit failed:', error);
      return false;
    }
  }

  // Convenience methods
  async logPageView(page: string, userId?: string) {
    return this.logEvent({
      event_type: 'page.view',
      action: 'view',
      actor_id: userId,
      resource_type: 'page',
      resource_id: page,
      category: 'general',
    });
  }

  async logUserAction(action: string, userId: string, details?: Record<string, any>) {
    return this.logEvent({
      event_type: `user.${action}`,
      action,
      actor_id: userId,
      category: 'general',
      payload: details,
    });
  }

  async logLogin(userId: string, success: boolean, ip?: string) {
    return this.logEvent({
      event_type: 'auth.login',
      action: 'login',
      actor_id: userId,
      outcome: success ? 'success' : 'failure',
      category: 'auth',
      severity: success ? 'info' : 'warning',
      payload: { ip },
    });
  }

  async logApiCall(endpoint: string, method: string, statusCode: number, userId?: string) {
    return this.logEvent({
      event_type: 'api.call',
      action: `${method} ${endpoint}`,
      actor_id: userId,
      resource_type: 'api',
      resource_id: endpoint,
      outcome: statusCode < 400 ? 'success' : 'failure',
      payload: { status_code: statusCode },
    });
  }

  async logError(error: string, context?: Record<string, any>) {
    return this.logEvent({
      event_type: 'error.client',
      action: 'error',
      outcome: 'failure',
      severity: 'error',
      category: 'security',
      payload: { error, ...context },
    });
  }
}

export const auditClient = new AuditClient();
export default auditClient;
