import deepmerge from 'deepmerge';
import { handleError, isAuthorized } from './common.js';
import { handleUIApiRequests, serveStaticFiles } from './ui-manager.js';
import { handleAPIRequests } from './api-manager.js';
import { getApiService } from './service-manager.js';
import { getProviderPoolManager } from './service-manager.js';
import { MODEL_PROVIDER } from './common.js';
import { PROMPT_LOG_FILENAME } from './config-manager.js';
import { handleOllamaRequest, handleOllamaShow } from './ollama-handler.js';

/**
 * Main request handler. It authenticates the request, determines the endpoint type,
 * and delegates to the appropriate specialized handler function.
 * @param {Object} config - The server configuration
 * @param {Object} providerPoolManager - The provider pool manager instance
 * @returns {Function} - The request handler function
 */
export function createRequestHandler(config, providerPoolManager) {
    return async function requestHandler(req, res) {
        // Deep copy the config for each request to allow dynamic modification
        const currentConfig = deepmerge({}, config);
        const requestUrl = new URL(req.url, `http://${req.headers.host}`);
        let path = requestUrl.pathname;
        const method = req.method;

        // Handle CORS preflight requests
        if (method === 'OPTIONS') {
            res.setHeader('Access-Control-Allow-Origin', '*');
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-goog-api-key, Model-Provider');
            res.writeHead(204);
            res.end();
            return;
        }

        // Serve static files for UI (除了登录页面需要认证)
        if (path.startsWith('/static/') || path === '/' || path === '/favicon.ico' || path === '/index.html' || path.startsWith('/app/') || path === '/login.html' || path === '/kiro-credits-checker.html') {
            const served = await serveStaticFiles(path, res);
            if (served) return;
        }

        const uiHandled = await handleUIApiRequests(method, path, req, res, currentConfig, providerPoolManager);
        if (uiHandled) return;

        // Ollama show endpoint with model name
        if (method === 'POST' && path === '/ollama/api/show') {
            await handleOllamaShow(req, res);
            return true;
        }

        console.log(`\n${new Date().toLocaleString()}`);
        console.log(`[Server] Received request: ${req.method} http://${req.headers.host}${req.url}`);

        // Health check endpoint
        if ((method === 'GET' || method === 'HEAD') && path === '/health') {
            const userAgent = req.headers['user-agent'] || '';
            if (userAgent.includes('UptimeRobot')) {
                console.log(`[Health Check] UptimeRobot ping received at ${new Date().toLocaleString()}`);
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                provider: currentConfig.MODEL_PROVIDER
            }));
            return true;
        }

        // Kiro credits check endpoint (no auth required)
        if (method === 'POST' && path === '/api/check-kiro-credits') {
            try {
                let body = '';
                req.on('data', chunk => {
                    body += chunk.toString();
                });
                req.on('end', async () => {
                    try {
                        const { base64Creds } = JSON.parse(body);

                        if (!base64Creds) {
                            res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
                            res.end(JSON.stringify({ error: 'base64Creds is required' }));
                            return;
                        }

                        // Decode credentials
                        const decodedStr = Buffer.from(base64Creds, 'base64').toString('utf8');
                        const creds = JSON.parse(decodedStr);

                        if (!creds.accessToken) {
                            res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
                            res.end(JSON.stringify({ error: 'Invalid credentials: missing accessToken' }));
                            return;
                        }

                        // Extract region from profileArn or use default
                        let region = creds.region;
                        if (!region && creds.profileArn) {
                            // Extract region from arn:aws:codewhisperer:us-east-1:...
                            const arnParts = creds.profileArn.split(':');
                            if (arnParts.length >= 4) {
                                region = arnParts[3];
                            }
                        }
                        region = region || 'us-east-1';

                        // Import axios dynamically
                        const axios = (await import('axios')).default;
                        const crypto = await import('crypto');
                        const os = await import('os');

                        // Get MAC address SHA256
                        const networkInterfaces = os.networkInterfaces();
                        let macAddress = '';
                        for (const interfaceName in networkInterfaces) {
                            const networkInterface = networkInterfaces[interfaceName];
                            for (const iface of networkInterface) {
                                if (!iface.internal && iface.mac && iface.mac !== '00:00:00:00:00:00') {
                                    macAddress = iface.mac;
                                    break;
                                }
                            }
                            if (macAddress) break;
                        }
                        if (!macAddress) macAddress = '00:00:00:00:00:00';
                        const macSha256 = crypto.createHash('sha256').update(macAddress).digest('hex');

                        // Call Kiro API
                        const url = `https://codewhisperer.${region}.amazonaws.com/getUserUsage`;

                        const response = await axios.post(url, {}, {
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${creds.accessToken}`,
                                'x-amz-user-agent': `aws-sdk-js/1.0.7 KiroIDE-0.1.25-${macSha256}`,
                                'user-agent': `aws-sdk-js/1.0.7 ua/2.1 os/win32#10.0.26100 lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.7 m/E KiroIDE-0.1.25-${macSha256}`,
                                'amz-sdk-request': 'attempt=1; max=1',
                                'x-amzn-kiro-agent-mode': 'vibe',
                                'Accept': 'application/json'
                            }
                        });

                        // Return usage data
                        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
                        res.end(JSON.stringify({
                            usedCredits: response.data.usedCredits || 0,
                            totalCredits: 500,
                            creditsLeft: 500 - (response.data.usedCredits || 0),
                            accountInfo: {
                                provider: creds.provider || 'Unknown',
                                region: region,
                                authMethod: creds.authMethod || 'social',
                                expiresAt: creds.expiresAt
                            }
                        }));
                    } catch (error) {
                        console.error('[Kiro Credits Check] Error:', error.message);
                        res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
                        res.end(JSON.stringify({ error: error.message }));
                    }
                });
            } catch (error) {
                console.error('[Kiro Credits Check] Error:', error.message);
                res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
                res.end(JSON.stringify({ error: error.message }));
            }
            return true;
        }

        // Ignore count_tokens requests
        if (path.includes('/count_tokens')) {
            console.log(`[Server] Ignoring count_tokens request: ${path}`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                tokens: 0,
                message: 'Token counting is not supported'
            }));
            return true;
        }

        // Handle API requests
        // Allow overriding MODEL_PROVIDER via request header
        const modelProviderHeader = req.headers['model-provider'];
        if (modelProviderHeader) {
            currentConfig.MODEL_PROVIDER = modelProviderHeader;
            console.log(`[Config] MODEL_PROVIDER overridden by header to: ${currentConfig.MODEL_PROVIDER}`);
        }

        // Check if the first path segment matches a MODEL_PROVIDER and switch if it does
        const pathSegments = path.split('/').filter(segment => segment.length > 0);
        if (pathSegments.length > 0) {
            const firstSegment = pathSegments[0];
            const isValidProvider = Object.values(MODEL_PROVIDER).includes(firstSegment);
            if (firstSegment && isValidProvider) {
                currentConfig.MODEL_PROVIDER = firstSegment;
                console.log(`[Config] MODEL_PROVIDER overridden by path segment to: ${currentConfig.MODEL_PROVIDER}`);
                pathSegments.shift();
                path = '/' + pathSegments.join('/');
                requestUrl.pathname = path;
            } else if (firstSegment && !isValidProvider) {
                console.log(`[Config] Ignoring invalid MODEL_PROVIDER in path segment: ${firstSegment}`);
            }
        }

        // 获取或选择 API Service 实例
        let apiService;
        try {
            apiService = await getApiService(currentConfig);
        } catch (error) {
            handleError(res, { statusCode: 500, message: `Failed to get API service: ${error.message}` });
            const poolManager = getProviderPoolManager();
            if (poolManager) {
                poolManager.markProviderUnhealthy(currentConfig.MODEL_PROVIDER, {
                    uuid: currentConfig.uuid
                });
            }
            return;
        }

        // Check authentication for API requests
        if (!isAuthorized(req, requestUrl, currentConfig.REQUIRED_API_KEY)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: { message: 'Unauthorized: API key is invalid or missing.' } }));
            return;
        }

        try {
            // Handle Ollama request (normalize path and route to appropriate endpoints)
            const { handled, normalizedPath } = await handleOllamaRequest(method, path, requestUrl, req, res, apiService, currentConfig, providerPoolManager);
            if (handled) return;
            path = normalizedPath;

            // Handle API requests
            const apiHandled = await handleAPIRequests(method, path, req, res, currentConfig, apiService, providerPoolManager, PROMPT_LOG_FILENAME);
            if (apiHandled) return;

            // Fallback for unmatched routes
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: { message: 'Not Found' } }));
        } catch (error) {
            handleError(res, error);
        }
    };
}