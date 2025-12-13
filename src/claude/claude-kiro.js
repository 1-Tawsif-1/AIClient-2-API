import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { promises as fs } from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';

const KIRO_CONSTANTS = {
    REFRESH_URL: 'https://prod.{{region}}.auth.desktop.kiro.dev/refreshToken',
    REFRESH_IDC_URL: 'https://oidc.{{region}}.amazonaws.com/token',
    BASE_URL: 'https://codewhisperer.{{region}}.amazonaws.com/generateAssistantResponse',
    AMAZON_Q_URL: 'https://codewhisperer.{{region}}.amazonaws.com/SendMessageStreaming',
    DEFAULT_MODEL_NAME: 'claude-sonnet-4-5',
    AXIOS_TIMEOUT: 120000, // 2 minutes timeout
    USER_AGENT: 'KiroIDE',
    CONTENT_TYPE_JSON: 'application/json',
    ACCEPT_JSON: 'application/json',
    AUTH_METHOD_SOCIAL: 'social',
    CHAT_TRIGGER_TYPE_MANUAL: 'MANUAL',
    ORIGIN_AI_EDITOR: 'AI_EDITOR',
};

const MODEL_MAPPING = {
    // Opus models
    "claude-opus-4-5": "CLAUDE_OPUS_4_5_20251101_V1_0",
    "claude-opus-4-5-20251101": "CLAUDE_OPUS_4_5_20251101_V1_0",
    "claude-opus-4-20250514": "CLAUDE_OPUS_4_20250514_V1_0",
    "claude-3-opus-20240229": "CLAUDE_3_OPUS_20240229_V1_0",
    // Sonnet models
    "claude-sonnet-4-5": "CLAUDE_SONNET_4_5_20250929_V1_0",
    "claude-sonnet-4-5-20250929": "CLAUDE_SONNET_4_5_20250929_V1_0",
    "claude-sonnet-4-20250514": "CLAUDE_SONNET_4_20250514_V1_0",
    "claude-3-7-sonnet-20250219": "CLAUDE_3_7_SONNET_20250219_V1_0",
    // Amazon Q variants
    "amazonq-claude-sonnet-4-20250514": "CLAUDE_SONNET_4_20250514_V1_0",
    "amazonq-claude-3-7-sonnet-20250219": "CLAUDE_3_7_SONNET_20250219_V1_0"
};

const KIRO_AUTH_TOKEN_FILE = "kiro-auth-token.json";

/**
 * Kiro API Service - Node.js implementation based on the Python ki2api
 * Provides OpenAI-compatible API for Claude Sonnet 4 via Kiro/CodeWhisperer
 */

async function getMacAddressSha256() {
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

    if (!macAddress) {
        console.warn("无法获取MAC地址，将使用默认值。");
        macAddress = '00:00:00:00:00:00'; // Fallback if no MAC address is found
    }

    const sha256Hash = crypto.createHash('sha256').update(macAddress).digest('hex');
    return sha256Hash;
}

// Helper functions for tool calls
function findMatchingBracket(text, startPos) {
    if (!text || startPos >= text.length || text[startPos] !== '[') {
        return -1;
    }

    let bracketCount = 1;
    let inString = false;
    let escapeNext = false;

    for (let i = startPos + 1; i < text.length; i++) {
        const char = text[i];

        if (escapeNext) {
            escapeNext = false;
            continue;
        }

        if (char === '\\' && inString) {
            escapeNext = true;
            continue;
        }

        if (char === '"' && !escapeNext) {
            inString = !inString;
            continue;
        }

        if (!inString) {
            if (char === '[') {
                bracketCount++;
            } else if (char === ']') {
                bracketCount--;
                if (bracketCount === 0) {
                    return i;
                }
            }
        }
    }
    return -1;
}

function parseSingleToolCall(toolCallText) {
    const namePattern = /\[Called\s+(\w+)\s+with\s+args:/i;
    const nameMatch = toolCallText.match(namePattern);

    if (!nameMatch) {
        return null;
    }

    const functionName = nameMatch[1].trim();
    const argsStartMarker = "with args:";
    const argsStartPos = toolCallText.toLowerCase().indexOf(argsStartMarker.toLowerCase());

    if (argsStartPos === -1) {
        return null;
    }

    const argsStart = argsStartPos + argsStartMarker.length;
    const argsEnd = toolCallText.lastIndexOf(']');

    if (argsEnd <= argsStart) {
        return null;
    }

    const jsonCandidate = toolCallText.substring(argsStart, argsEnd).trim();

    try {
        // Simple repair for common issues like trailing commas or unquoted keys
        let repairedJson = jsonCandidate;
        // Remove trailing comma before closing brace/bracket
        repairedJson = repairedJson.replace(/,\s*([}\]])/g, '$1');
        // Add quotes to unquoted keys (basic attempt)
        repairedJson = repairedJson.replace(/([{,]\s*)([a-zA-Z0-9_]+?)\s*:/g, '$1"$2":');
        // Ensure string values are properly quoted if they contain special characters and are not already quoted
        repairedJson = repairedJson.replace(/:\s*([a-zA-Z0-9_]+)(?=[,\}\]])/g, ':"$1"');


        const argumentsObj = JSON.parse(repairedJson);

        if (typeof argumentsObj !== 'object' || argumentsObj === null) {
            return null;
        }

        const toolCallId = `call_${uuidv4().replace(/-/g, '').substring(0, 8)}`;
        return {
            id: toolCallId,
            type: "function",
            function: {
                name: functionName,
                arguments: JSON.stringify(argumentsObj)
            }
        };
    } catch (e) {
        console.error(`Failed to parse tool call arguments: ${e.message}`, jsonCandidate);
        return null;
    }
}

function parseBracketToolCalls(responseText) {
    if (!responseText || !responseText.includes("[Called")) {
        return null;
    }

    const toolCalls = [];
    const callPositions = [];
    let start = 0;
    while (true) {
        const pos = responseText.indexOf("[Called", start);
        if (pos === -1) {
            break;
        }
        callPositions.push(pos);
        start = pos + 1;
    }

    for (let i = 0; i < callPositions.length; i++) {
        const startPos = callPositions[i];
        let endSearchLimit;
        if (i + 1 < callPositions.length) {
            endSearchLimit = callPositions[i + 1];
        } else {
            endSearchLimit = responseText.length;
        }

        const segment = responseText.substring(startPos, endSearchLimit);
        const bracketEnd = findMatchingBracket(segment, 0);

        let toolCallText;
        if (bracketEnd !== -1) {
            toolCallText = segment.substring(0, bracketEnd + 1);
        } else {
            // Fallback: if no matching bracket, try to find the last ']' in the segment
            const lastBracket = segment.lastIndexOf(']');
            if (lastBracket !== -1) {
                toolCallText = segment.substring(0, lastBracket + 1);
            } else {
                continue; // Skip this one if no closing bracket found
            }
        }
        
        const parsedCall = parseSingleToolCall(toolCallText);
        if (parsedCall) {
            toolCalls.push(parsedCall);
        }
    }
    return toolCalls.length > 0 ? toolCalls : null;
}

function deduplicateToolCalls(toolCalls) {
    const seen = new Set();
    const uniqueToolCalls = [];

    for (const tc of toolCalls) {
        const key = `${tc.function.name}-${tc.function.arguments}`;
        if (!seen.has(key)) {
            seen.add(key);
            uniqueToolCalls.push(tc);
        } else {
            console.log(`Skipping duplicate tool call: ${tc.function.name}`);
        }
    }
    return uniqueToolCalls;
}

export class KiroApiService {
    constructor(config = {}) {
        this.isInitialized = false;
        this.config = config;
        this.credPath = config.KIRO_OAUTH_CREDS_DIR_PATH || path.join(os.homedir(), ".aws", "sso", "cache");

        // Dynamic credential loading - supports up to 7 accounts
        this.credentialsList = []; // Array to hold all parsed credentials
        this.currentCredIndex = 0; // Track which credential is active

        // Load all available credentials dynamically
        this._loadAllCredentials(config);

        this.useSystemProxy = config?.USE_SYSTEM_PROXY_KIRO ?? false;
        console.log(`[Kiro] System proxy ${this.useSystemProxy ? 'enabled' : 'disabled'}`);
        console.log(`[Kiro] ${this.credentialsList.length} credential(s) configured for rotation`);

        // Support for file-based credentials
        if (config.KIRO_OAUTH_CREDS_FILE_PATH) {
            this.credsFilePath = config.KIRO_OAUTH_CREDS_FILE_PATH;
        }

        this.modelName = KIRO_CONSTANTS.DEFAULT_MODEL_NAME;
        this.axiosInstance = null; // Initialize later in async method
    }

    /**
     * Load all available Base64 credentials from config (supports 1-7)
     * @param {Object} config - Configuration object
     */
    _loadAllCredentials(config) {
        const credKeys = [
            'KIRO_OAUTH_CREDS_BASE64',
            'KIRO_OAUTH_CREDS_BASE64_2',
            'KIRO_OAUTH_CREDS_BASE64_3',
            'KIRO_OAUTH_CREDS_BASE64_4',
            'KIRO_OAUTH_CREDS_BASE64_5',
            'KIRO_OAUTH_CREDS_BASE64_6',
            'KIRO_OAUTH_CREDS_BASE64_7'
        ];

        for (let i = 0; i < credKeys.length; i++) {
            const base64Value = config[credKeys[i]];
            if (base64Value) {
                try {
                    const decodedCreds = Buffer.from(base64Value, 'base64').toString('utf8');
                    const parsedCreds = JSON.parse(decodedCreds);
                    this.credentialsList.push({
                        index: i + 1,
                        configKey: credKeys[i],
                        credentials: parsedCreds
                    });
                    console.info(`[Kiro] Successfully decoded Base64 credentials #${i + 1} (${credKeys[i]})`);
                } catch (error) {
                    console.error(`[Kiro] Failed to parse Base64 credentials #${i + 1} (${credKeys[i]}): ${error.message}`);
                }
            }
        }
    }

    /**
     * Get the current credential object
     * @returns {Object|null} Current credential or null if none available
     */
    _getCurrentCredential() {
        if (this.credentialsList.length === 0) {
            return null;
        }
        return this.credentialsList[this.currentCredIndex];
    }
 
    async initialize() {
        if (this.isInitialized) return;
        console.log('[Kiro] Initializing Kiro API Service...');
        await this.initializeAuth();
        const macSha256 = await getMacAddressSha256();
        const axiosConfig = {
            timeout: KIRO_CONSTANTS.AXIOS_TIMEOUT,
            headers: {
                'Content-Type': KIRO_CONSTANTS.CONTENT_TYPE_JSON,
                'x-amz-user-agent': `aws-sdk-js/1.0.7 KiroIDE-0.1.25-${macSha256}`,
                'user-agent': `aws-sdk-js/1.0.7 ua/2.1 os/win32#10.0.26100 lang/js md/nodejs#20.16.0 api/codewhispererstreaming#1.0.7 m/E KiroIDE-0.1.25-${macSha256}`,
                'amz-sdk-request': 'attempt=1; max=1',
                'x-amzn-kiro-agent-mode': 'vibe',
                'Accept': KIRO_CONSTANTS.ACCEPT_JSON,
            },
        };
        
        // 根据 useSystemProxy 配置代理设置
        if (!this.useSystemProxy) {
            axiosConfig.proxy = false;
        }
        
        this.axiosInstance = axios.create(axiosConfig);
        this.isInitialized = true;
    }

async initializeAuth(forceRefresh = false) {
    if (this.accessToken && !forceRefresh) {
        console.debug('[Kiro Auth] Access token already available and not forced refresh.');
        return;
    }

    // Helper to load credentials from a file
    const loadCredentialsFromFile = async (filePath) => {
        try {
            const fileContent = await fs.readFile(filePath, 'utf8');
            return JSON.parse(fileContent);
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.debug(`[Kiro Auth] Credential file not found: ${filePath}`);
            } else if (error instanceof SyntaxError) {
                console.warn(`[Kiro Auth] Failed to parse JSON from ${filePath}: ${error.message}`);
            } else {
                console.warn(`[Kiro Auth] Failed to read credential file ${filePath}: ${error.message}`);
            }
            return null;
        }
    };

    // Helper to save credentials to a file
    const saveCredentialsToFile = async (filePath, newData) => {
        try {
            let existingData = {};
            try {
                const fileContent = await fs.readFile(filePath, 'utf8');
                existingData = JSON.parse(fileContent);
            } catch (readError) {
                if (readError.code === 'ENOENT') {
                    console.debug(`[Kiro Auth] Token file not found, creating new one: ${filePath}`);
                } else {
                    console.warn(`[Kiro Auth] Could not read existing token file ${filePath}: ${readError.message}`);
                }
            }
            const mergedData = { ...existingData, ...newData };
            await fs.writeFile(filePath, JSON.stringify(mergedData, null, 2), 'utf8');
            console.info(`[Kiro Auth] Updated token file: ${filePath}`);
        } catch (error) {
            console.error(`[Kiro Auth] Failed to write token to file ${filePath}: ${error.message}`);
        }
    };

    try {
        let mergedCredentials = {};

        // Priority 1: Load from Base64 credentials array if available
        const currentCred = this._getCurrentCredential();
        if (currentCred && currentCred.credentials) {
            Object.assign(mergedCredentials, currentCred.credentials);
            console.info(`[Kiro Auth] Using credentials #${currentCred.index} (${currentCred.configKey})`);
        }

        // Priority 2 & 3: Load from file path or directory
        const targetFilePath = this.credsFilePath || path.join(this.credPath, KIRO_AUTH_TOKEN_FILE);
        const dirPath = path.dirname(targetFilePath);
        const targetFileName = path.basename(targetFilePath);

        console.debug(`[Kiro Auth] Attempting to load credentials from directory: ${dirPath}`);

        try {
            // First try to read the target file
            const targetCredentials = await loadCredentialsFromFile(targetFilePath);
            if (targetCredentials) {
                Object.assign(mergedCredentials, targetCredentials);
                console.info(`[Kiro Auth] Successfully loaded OAuth credentials from ${targetFilePath}`);
            }

            // Then read other JSON files in directory (excluding target file)
            const files = await fs.readdir(dirPath);
            for (const file of files) {
                if (file.endsWith('.json') && file !== targetFileName) {
                    const filePath = path.join(dirPath, file);
                    const credentials = await loadCredentialsFromFile(filePath);
                    if (credentials) {
                        // Preserve existing expiresAt
                        credentials.expiresAt = mergedCredentials.expiresAt;
                        Object.assign(mergedCredentials, credentials);
                        console.debug(`[Kiro Auth] Loaded Client credentials from ${file}`);
                    }
                }
            }
        } catch (error) {
            console.warn(`[Kiro Auth] Error loading credentials from directory ${dirPath}: ${error.message}`);
        }

        // Apply loaded credentials
        this.accessToken = this.accessToken || mergedCredentials.accessToken;
        this.refreshToken = this.refreshToken || mergedCredentials.refreshToken;
        this.clientId = this.clientId || mergedCredentials.clientId;
        this.clientSecret = this.clientSecret || mergedCredentials.clientSecret;
        this.authMethod = this.authMethod || mergedCredentials.authMethod;
        this.expiresAt = this.expiresAt || mergedCredentials.expiresAt;
        this.profileArn = this.profileArn || mergedCredentials.profileArn;
        this.region = this.region || mergedCredentials.region;

        // Ensure region is set before using it in URLs
        if (!this.region) {
            console.warn('[Kiro Auth] Region not found in credentials. Using default region us-east-1 for URLs.');
            this.region = 'us-east-1';
        }

        this.refreshUrl = KIRO_CONSTANTS.REFRESH_URL.replace("{{region}}", this.region);
        this.refreshIDCUrl = KIRO_CONSTANTS.REFRESH_IDC_URL.replace("{{region}}", this.region);
        this.baseUrl = KIRO_CONSTANTS.BASE_URL.replace("{{region}}", this.region);
        this.amazonQUrl = KIRO_CONSTANTS.AMAZON_Q_URL.replace("{{region}}", this.region);
    } catch (error) {
        console.warn(`[Kiro Auth] Error during credential loading: ${error.message}`);
    }

    // Refresh token if forced or if access token is missing but refresh token is available
    if (forceRefresh || (!this.accessToken && this.refreshToken)) {
        if (!this.refreshToken) {
            throw new Error('No refresh token available to refresh access token.');
        }
        try {
            const requestBody = {
                refreshToken: this.refreshToken,
            };

            let refreshUrl = this.refreshUrl;
            if (this.authMethod !== KIRO_CONSTANTS.AUTH_METHOD_SOCIAL) {
                refreshUrl = this.refreshIDCUrl;
                requestBody.clientId = this.clientId;
                requestBody.clientSecret = this.clientSecret;
                requestBody.grantType = 'refresh_token';
            }
            const response = await this.axiosInstance.post(refreshUrl, requestBody);
            console.log('[Kiro Auth] Token refresh response: ok');

            if (response.data && response.data.accessToken) {
                this.accessToken = response.data.accessToken;
                this.refreshToken = response.data.refreshToken;
                this.profileArn = response.data.profileArn;
                const expiresIn = response.data.expiresIn;
                const expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();
                this.expiresAt = expiresAt;
                console.info('[Kiro Auth] Access token refreshed successfully');

                // Update the token file
                const tokenFilePath = this.credsFilePath || path.join(this.credPath, KIRO_AUTH_TOKEN_FILE);
                const updatedTokenData = {
                    accessToken: this.accessToken,
                    refreshToken: this.refreshToken,
                    expiresAt: expiresAt,
                };
                if(this.profileArn){
                    updatedTokenData.profileArn = this.profileArn;
                }
                await saveCredentialsToFile(tokenFilePath, updatedTokenData);
            } else {
                throw new Error('Invalid refresh response: Missing accessToken');
            }
        } catch (error) {
            console.error('[Kiro Auth] Token refresh failed:', error.message);
            throw new Error(`Token refresh failed: ${error.message}`);
        }
    }

    if (!this.accessToken) {
        throw new Error('No access token available after initialization and refresh attempts.');
    }
}

    /**
     * Switches to the next available credential in rotation
     * @param {boolean} resetRotationTracker - If true, resets the rotation start tracker
     * @returns {boolean} True if switched successfully, false if no more credentials available or full rotation completed
     */
    switchCredentials(resetRotationTracker = false) {
        if (this.credentialsList.length <= 1) {
            console.log('[Kiro] No additional credentials available for rotation');
            return false;
        }

        // Track rotation start to prevent infinite loops
        if (resetRotationTracker || this._rotationStartIndex === undefined) {
            this._rotationStartIndex = this.currentCredIndex;
        }

        const previousIndex = this.currentCredIndex;
        const previousCred = this._getCurrentCredential();

        // Move to next credential (circular rotation)
        this.currentCredIndex = (this.currentCredIndex + 1) % this.credentialsList.length;
        
        // Check if we've completed a full rotation
        if (this.currentCredIndex === this._rotationStartIndex) {
            console.log('[Kiro] Full credential rotation completed - all credentials tried');
            this._rotationStartIndex = undefined; // Reset for next rotation cycle
            return false;
        }

        const newCred = this._getCurrentCredential();

        console.log(`[Kiro] Switching credentials: #${previousCred?.index || 'N/A'} -> #${newCred?.index || 'N/A'} (${this.currentCredIndex + 1}/${this.credentialsList.length})`);

        // Reset credentials to force reload
        this.accessToken = null;
        this.refreshToken = null;
        this.clientId = null;
        this.clientSecret = null;
        this.authMethod = null;
        this.expiresAt = null;
        this.profileArn = null;
        this.region = null;

        return true;
    }

    /**
     * Get total number of available credentials
     * @returns {number} Number of credentials configured
     */
    getCredentialsCount() {
        return this.credentialsList.length;
    }

    /**
     * Get current credential index (1-based for display)
     * @returns {number} Current credential number
     */
    getCurrentCredentialNumber() {
        const cred = this._getCurrentCredential();
        return cred ? cred.index : 0;
    }

    /**
     * Extract text content from OpenAI message format
     */
    getContentText(message) {
        if(message==null){
            return "";
        }
        if (Array.isArray(message) ) {
            return message
                .filter(part => part && part.type === 'text' && part.text)
                .map(part => part.text)
                .join('');
        } else if (typeof message.content === 'string') {
            return message.content;
        } else if (Array.isArray(message.content) ) {
            return message.content
                .filter(part => part && part.type === 'text' && part.text)
                .map(part => part.text)
                .join('');
        } 
        return String(message.content || message);
    }

    /**
     * Clean JSON schema by removing unsupported properties
     * Kiro/CodeWhisperer only supports basic JSON schema properties
     */
    _cleanJsonSchema(schema) {
        if (!schema || typeof schema !== 'object') {
            return schema;
        }

        // Only keep supported properties
        const supportedProps = ['type', 'description', 'properties', 'required', 'enum', 'items', 'default', 'minimum', 'maximum', 'minLength', 'maxLength', 'pattern'];
        const cleaned = {};

        for (const [key, value] of Object.entries(schema)) {
            if (supportedProps.includes(key)) {
                if (key === 'properties' && typeof value === 'object') {
                    // Recursively clean nested properties
                    cleaned.properties = {};
                    for (const [propName, propSchema] of Object.entries(value)) {
                        cleaned.properties[propName] = this._cleanJsonSchema(propSchema);
                    }
                } else if (key === 'items' && typeof value === 'object') {
                    // Recursively clean array items schema
                    cleaned.items = this._cleanJsonSchema(value);
                } else {
                    cleaned[key] = value;
                }
            }
        }

        return cleaned;
    }

    /**
     * Build CodeWhisperer request from OpenAI messages
     * @param {Array} messages - Array of messages
     * @param {string} model - Model name
     * @param {Array} tools - Array of tools
     * @param {string} inSystemPrompt - System prompt
     * @param {Object} thinking - Thinking configuration { type: "enabled", budget_tokens: number }
     */
    buildCodewhispererRequest(messages, model, tools = null, inSystemPrompt = null, thinking = null) {
        const conversationId = uuidv4();
        
        let systemPrompt = this.getContentText(inSystemPrompt);
        const processedMessages = messages;

        if (processedMessages.length === 0) {
            throw new Error('No user messages found');
        }

        const codewhispererModel = MODEL_MAPPING[model] || MODEL_MAPPING[this.modelName];
        
        let toolsContext = {};
        if (tools && Array.isArray(tools) && tools.length > 0) {
            // Filter out invalid tools and map valid ones
            const validTools = tools
                .filter(tool => tool && tool.name && typeof tool.name === 'string')
                .map(tool => {
                    // Clean the input schema - remove unsupported properties
                    let cleanedSchema = tool.input_schema || { type: "object", properties: {} };
                    if (cleanedSchema && typeof cleanedSchema === 'object') {
                        // Remove $schema and other unsupported top-level properties
                        const { $schema, $id, $ref, $defs, definitions, ...rest } = cleanedSchema;
                        cleanedSchema = this._cleanJsonSchema(rest);
                    }
                    return {
                        toolSpecification: {
                            name: tool.name,
                            description: tool.description || "",
                            inputSchema: { json: cleanedSchema }
                        }
                    };
                });

            // Only create toolsContext if there are valid tools
            if (validTools.length > 0) {
                toolsContext = { tools: validTools };
            }
        }

        const history = [];
        let startIndex = 0;

        // Handle system prompt
        if (systemPrompt) {
            // If the first message is a user message, prepend system prompt to it
            if (processedMessages[0].role === 'user') {
                let firstUserContent = this.getContentText(processedMessages[0]);
                history.push({
                    userInputMessage: {
                        content: `${systemPrompt}\n\n${firstUserContent}`,
                        modelId: codewhispererModel,
                        origin: KIRO_CONSTANTS.ORIGIN_AI_EDITOR,
                    }
                });
                startIndex = 1; // Start processing from the second message
            } else {
                // If the first message is not a user message, or if there's no initial user message,
                // add system prompt as a standalone user message.
                history.push({
                    userInputMessage: {
                        content: systemPrompt,
                        modelId: codewhispererModel,
                        origin: KIRO_CONSTANTS.ORIGIN_AI_EDITOR,
                    }
                });
            }
        }

        // Add remaining user/assistant messages to history
        for (let i = startIndex; i < processedMessages.length - 1; i++) {
            const message = processedMessages[i];
            if (message.role === 'user') {
                let userInputMessage = {
                    content: '',
                    modelId: codewhispererModel,
                    origin: KIRO_CONSTANTS.ORIGIN_AI_EDITOR,
                };

                if (Array.isArray(message.content)) {
                    const images = [];
                    const userInputMessageContext = {};

                    for (const part of message.content) {
                        if (!part) continue;
                        if (part.type === 'text') {
                            userInputMessage.content += part.text;
                        } else if (part.type === 'tool_result') {
                            if (!userInputMessageContext.toolResults) {
                                userInputMessageContext.toolResults = [];
                            }
                            userInputMessageContext.toolResults.push({
                                content: [{ text: this.getContentText(part.content) }],
                                status: 'success',
                                toolUseId: part.tool_use_id
                            });
                        } else if (part.type === 'image') {
                            images.push({
                                format: part.source.media_type.split('/')[1],
                                source: {
                                    bytes: part.source.data
                                }
                            });
                        }
                    }

                    // Only add images if they exist
                    if (images.length > 0) {
                        userInputMessage.images = images;
                    }

                    // Only add userInputMessageContext if it has properties
                    if (Object.keys(userInputMessageContext).length > 0) {
                        userInputMessage.userInputMessageContext = userInputMessageContext;
                    }
                } else {
                    userInputMessage.content = this.getContentText(message);
                }
                history.push({ userInputMessage });
            } else if (message.role === 'assistant') {
                let assistantResponseMessage = {
                    content: '',
                };
                const toolUses = [];

                if (Array.isArray(message.content)) {
                    for (const part of message.content) {
                        if (!part) continue;
                        if (part.type === 'text') {
                            assistantResponseMessage.content += part.text;
                        } else if (part.type === 'tool_use') {
                            toolUses.push({
                                input: part.input,
                                name: part.name,
                                toolUseId: part.id
                            });
                        }
                    }
                } else {
                    assistantResponseMessage.content = this.getContentText(message);
                }

                // Only add toolUses if they exist
                if (toolUses.length > 0) {
                    assistantResponseMessage.toolUses = toolUses;
                }

                history.push({ assistantResponseMessage });
            }
        }

        // Build current message
        const currentMessage = processedMessages[processedMessages.length - 1];
        let currentContent = '';
        let currentToolResults = [];
        let currentToolUses = [];
        let currentImages = [];

        if (Array.isArray(currentMessage.content)) {
            for (const part of currentMessage.content) {
                if (!part) continue;
                if (part.type === 'text') {
                    currentContent += part.text;
                } else if (part.type === 'tool_result') {
                    currentToolResults.push({
                        content: [{ text: this.getContentText(part.content) }],
                        status: 'success',
                        toolUseId: part.tool_use_id
                    });
                } else if (part.type === 'tool_use') {
                    currentToolUses.push({
                        input: part.input,
                        name: part.name,
                        toolUseId: part.id
                    });
                } else if (part.type === 'image') {
                    currentImages.push({
                        format: part.source.media_type.split('/')[1],
                        source: {
                            bytes: part.source.data
                        }
                    });
                }
            }
        } else {
            currentContent = this.getContentText(currentMessage);
        }

        if (!currentContent && currentToolResults.length === 0 && currentToolUses.length === 0) {
            currentContent = 'Continue';
        }

        const request = {
            conversationState: {
                chatTriggerType: KIRO_CONSTANTS.CHAT_TRIGGER_TYPE_MANUAL,
                conversationId: conversationId,
                currentMessage: {}, // Will be populated based on the last message's role
                history: history
            }
        };

        if (currentMessage.role === 'user') {
            const userInputMessage = {
                content: currentContent,
                modelId: codewhispererModel,
                origin: KIRO_CONSTANTS.ORIGIN_AI_EDITOR,
            };

            // Only add images if they exist
            if (currentImages && currentImages.length > 0) {
                userInputMessage.images = currentImages;
            }

            // Build userInputMessageContext only if there are toolResults or tools
            const userInputMessageContext = {};
            if (currentToolResults.length > 0) {
                userInputMessageContext.toolResults = currentToolResults;
            }
            if (Object.keys(toolsContext).length > 0 && toolsContext.tools) {
                userInputMessageContext.tools = toolsContext.tools;
            }

            // Only add userInputMessageContext if it has properties
            if (Object.keys(userInputMessageContext).length > 0) {
                userInputMessage.userInputMessageContext = userInputMessageContext;
            }

            request.conversationState.currentMessage.userInputMessage = userInputMessage;
        } else if (currentMessage.role === 'assistant') {
            const assistantResponseMessage = {
                content: currentContent,
            };

            // Only add toolUses if they exist
            if (currentToolUses.length > 0) {
                assistantResponseMessage.toolUses = currentToolUses;
            }

            request.conversationState.currentMessage.assistantResponseMessage = assistantResponseMessage;
        }

        if (this.authMethod === KIRO_CONSTANTS.AUTH_METHOD_SOCIAL) {
            request.profileArn = this.profileArn;
        }

        // Add extended thinking configuration if enabled
        if (thinking && thinking.type === 'enabled') {
            request.conversationState.thinkingConfig = {
                enabled: true
            };
            if (thinking.budget_tokens) {
                request.conversationState.thinkingConfig.budgetTokens = thinking.budget_tokens;
            }
            console.log(`[Kiro] Extended thinking enabled with budget: ${thinking.budget_tokens || 'default'}`);
        }
        
        return request;
    }

    parseEventStreamChunk(rawData) {
        const rawStr = Buffer.isBuffer(rawData) ? rawData.toString('utf8') : String(rawData);
        let fullContent = '';
        let thinkingContent = '';
        const toolCalls = [];
        let currentToolCallDict = null;
        // console.log(`rawStr=${rawStr}`);

        // 改进的 SSE 事件解析：匹配 :message-typeevent 后面的 JSON 数据
        // 使用更精确的正则来匹配 SSE 格式的事件
        const sseEventRegex = /:message-typeevent(\{[^]*?(?=:event-type|$))/g;
        const legacyEventRegex = /event(\{.*?(?=event\{|$))/gs;
        
        // 首先尝试使用 SSE 格式解析
        let matches = [...rawStr.matchAll(sseEventRegex)];
        
        // 如果 SSE 格式没有匹配到，回退到旧的格式
        if (matches.length === 0) {
            matches = [...rawStr.matchAll(legacyEventRegex)];
        }

        for (const match of matches) {
            const potentialJsonBlock = match[1];
            if (!potentialJsonBlock || potentialJsonBlock.trim().length === 0) {
                continue;
            }

            // 尝试找到完整的 JSON 对象
            let searchPos = 0;
            while ((searchPos = potentialJsonBlock.indexOf('}', searchPos + 1)) !== -1) {
                const jsonCandidate = potentialJsonBlock.substring(0, searchPos + 1).trim();
                try {
                    const eventData = JSON.parse(jsonCandidate);

                    // Handle thinking/reasoning content
                    if (eventData.thinking || eventData.reasoningContent || eventData.type === 'thinking') {
                        let thinkingText = eventData.thinking || eventData.reasoningContent || eventData.content || '';
                        thinkingText = thinkingText.replace(/(?<!\\)\\n/g, '\n');
                        thinkingContent += thinkingText;
                    }
                    // 优先处理结构化工具调用事件
                    else if (eventData.name && eventData.toolUseId) {
                        if (!currentToolCallDict) {
                            currentToolCallDict = {
                                id: eventData.toolUseId,
                                type: "function",
                                function: {
                                    name: eventData.name,
                                    arguments: ""
                                }
                            };
                        }
                        if (eventData.input) {
                            currentToolCallDict.function.arguments += eventData.input;
                        }
                        if (eventData.stop) {
                            try {
                                const args = JSON.parse(currentToolCallDict.function.arguments);
                                currentToolCallDict.function.arguments = JSON.stringify(args);
                            } catch (e) {
                                console.warn(`[Kiro] Tool call arguments not valid JSON: ${currentToolCallDict.function.arguments}`);
                            }
                            toolCalls.push(currentToolCallDict);
                            currentToolCallDict = null;
                        }
                    } else if (!eventData.followupPrompt && eventData.content) {
                        // 处理内容，移除转义字符
                        let decodedContent = eventData.content;
                        // 处理常见的转义序列
                        decodedContent = decodedContent.replace(/(?<!\\)\\n/g, '\n');
                        // decodedContent = decodedContent.replace(/(?<!\\)\\t/g, '\t');
                        // decodedContent = decodedContent.replace(/\\"/g, '"');
                        // decodedContent = decodedContent.replace(/\\\\/g, '\\');
                        fullContent += decodedContent;
                    }
                    break;
                } catch (e) {
                    // JSON 解析失败，继续寻找下一个可能的结束位置
                    continue;
                }
            }
        }
        
        // 如果还有未完成的工具调用，添加到列表中
        if (currentToolCallDict) {
            toolCalls.push(currentToolCallDict);
        }

        // 检查解析后文本中的 bracket 格式工具调用
        const bracketToolCalls = parseBracketToolCalls(fullContent);
        if (bracketToolCalls) {
            toolCalls.push(...bracketToolCalls);
            // 从响应文本中移除工具调用文本
            for (const tc of bracketToolCalls) {
                const funcName = tc.function.name;
                const escapedName = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const pattern = new RegExp(`\\[Called\\s+${escapedName}\\s+with\\s+args:\\s*\\{[^}]*(?:\\{[^}]*\\}[^}]*)*\\}\\]`, 'gs');
                fullContent = fullContent.replace(pattern, '');
            }
            fullContent = fullContent.replace(/\s+/g, ' ').trim();
        }

        const uniqueToolCalls = deduplicateToolCalls(toolCalls);
        return { content: fullContent || '', toolCalls: uniqueToolCalls, thinking: thinkingContent || null };
    }
 

    async callApi(method, model, body, isRetry = false, retryCount = 0) {
        if (!this.isInitialized) await this.initialize();
        const maxRetries = this.config.REQUEST_MAX_RETRIES || 3;
        const baseDelay = this.config.REQUEST_BASE_DELAY || 1000; // 1 second base delay

        // Reset rotation tracker at the start of a new request (not a retry)
        if (!isRetry && retryCount === 0) {
            this._rotationStartIndex = undefined;
        }

        const requestData = this.buildCodewhispererRequest(body.messages, model, body.tools, body.system, body.thinking);

        // Log the request for debugging
        console.log('[Kiro] Request to CodeWhisperer:', JSON.stringify(requestData, null, 2));

        try {
            const token = this.accessToken; // Use the already initialized token
            const headers = {
                'Authorization': `Bearer ${token}`,
                'amz-sdk-invocation-id': `${uuidv4()}`,
            };

            // 当 model 以 kiro-amazonq 开头时，使用 amazonQUrl，否则使用 baseUrl
            const requestUrl = model.startsWith('amazonq') ? this.amazonQUrl : this.baseUrl;
            const response = await this.axiosInstance.post(requestUrl, requestData, { headers });
            return response;
        } catch (error) {
            // Handle 401/403 with credential switching or token refresh
            if ((error.response?.status === 401 || error.response?.status === 403) && !isRetry) {
                console.log(`[Kiro] Received ${error.response.status}. Attempting credential switch or token refresh...`);

                // Try switching to fallback credential first
                if (this.switchCredentials()) {
                    try {
                        await this.initializeAuth(true); // Force refresh with new credentials
                        return this.callApi(method, model, body, true, retryCount);
                    } catch (switchError) {
                        console.error('[Kiro] Fallback credential also failed:', switchError.message);
                    }
                }

                // If no fallback or fallback failed, try refreshing current token
                try {
                    await this.initializeAuth(true); // Force refresh token
                    return this.callApi(method, model, body, true, retryCount);
                } catch (refreshError) {
                    console.error('[Kiro] Token refresh failed during auth retry:', refreshError.message);
                    throw refreshError;
                }
            }

            // Handle 429 (Too Many Requests) with credential switching or exponential backoff
            if (error.response?.status === 429 && retryCount < maxRetries) {
                console.log(`[Kiro] Received 429 (Too Many Requests / Quota Exhausted).`);

                // Try switching to fallback credential
                if (this.switchCredentials()) {
                    try {
                        console.log('[Kiro] Retrying with fallback credential...');
                        await this.initializeAuth(true);
                        return this.callApi(method, model, body, false, 0); // Reset retry count for new credential
                    } catch (switchError) {
                        console.error('[Kiro] Fallback credential also failed:', switchError.message);
                    }
                }

                // If no fallback, use exponential backoff
                const delay = baseDelay * Math.pow(2, retryCount);
                console.log(`[Kiro] Retrying in ${delay}ms... (attempt ${retryCount + 1}/${maxRetries})`);
                await new Promise(resolve => setTimeout(resolve, delay));
                return this.callApi(method, model, body, isRetry, retryCount + 1);
            }

            // Handle other retryable errors (5xx server errors)
            if (error.response?.status >= 500 && error.response?.status < 600 && retryCount < maxRetries) {
                const delay = baseDelay * Math.pow(2, retryCount);
                console.log(`[Kiro] Received ${error.response.status} server error. Retrying in ${delay}ms... (attempt ${retryCount + 1}/${maxRetries})`);
                await new Promise(resolve => setTimeout(resolve, delay));
                return this.callApi(method, model, body, isRetry, retryCount + 1);
            }

            console.error('[Kiro] API call failed:', error.message);
            throw error;
        }
    }

    _processApiResponse(response) {
        const rawResponseText = Buffer.isBuffer(response.data) ? response.data.toString('utf8') : String(response.data);
        //console.log(`[Kiro] Raw response length: ${rawResponseText.length}`);
        if (rawResponseText.includes("[Called")) {
            console.log("[Kiro] Raw response contains [Called marker.");
        }

        // 1. Parse structured events and bracket calls from parsed content
        const parsedFromEvents = this.parseEventStreamChunk(rawResponseText);
        let fullResponseText = parsedFromEvents.content;
        let allToolCalls = [...parsedFromEvents.toolCalls]; // clone
        const thinkingContent = parsedFromEvents.thinking;
        //console.log(`[Kiro] Found ${allToolCalls.length} tool calls from event stream parsing.`);

        // 2. Crucial fix from Python example: Parse bracket tool calls from the original raw response
        const rawBracketToolCalls = parseBracketToolCalls(rawResponseText);
        if (rawBracketToolCalls) {
            //console.log(`[Kiro] Found ${rawBracketToolCalls.length} bracket tool calls in raw response.`);
            allToolCalls.push(...rawBracketToolCalls);
        }

        // 3. Deduplicate all collected tool calls
        const uniqueToolCalls = deduplicateToolCalls(allToolCalls);
        //console.log(`[Kiro] Total unique tool calls after deduplication: ${uniqueToolCalls.length}`);

        // 4. Clean up response text by removing all tool call syntax from the final text.
        // The text from parseEventStreamChunk is already partially cleaned.
        // We re-clean here with all unique tool calls to be certain.
        if (uniqueToolCalls.length > 0) {
            for (const tc of uniqueToolCalls) {
                const funcName = tc.function.name;
                const escapedName = funcName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const pattern = new RegExp(`\\[Called\\s+${escapedName}\\s+with\\s+args:\\s*\\{[^}]*(?:\\{[^}]*\\}[^}]*)*\\}\\]`, 'gs');
                fullResponseText = fullResponseText.replace(pattern, '');
            }
            fullResponseText = fullResponseText.replace(/\s+/g, ' ').trim();
        }
        
        //console.log(`[Kiro] Final response text after tool call cleanup: ${fullResponseText}`);
        //console.log(`[Kiro] Final tool calls after deduplication: ${JSON.stringify(uniqueToolCalls)}`);
        if (thinkingContent) {
            console.log(`[Kiro] Thinking content received: ${thinkingContent.substring(0, 100)}...`);
        }
        return { responseText: fullResponseText, toolCalls: uniqueToolCalls, thinking: thinkingContent };
    }

    async generateContent(model, requestBody) {
        if (!this.isInitialized) await this.initialize();
        
        // 检查 token 是否即将过期,如果是则先刷新
        if (this.isExpiryDateNear()) {
            console.log('[Kiro] Token is near expiry, refreshing before generateContent request...');
            await this.initializeAuth(true);
        }
        
        const finalModel = MODEL_MAPPING[model] ? model : this.modelName;
        console.log(`[Kiro] Calling generateContent with model: ${finalModel}`);
        const response = await this.callApi('', finalModel, requestBody);

        try {
            const { responseText, toolCalls, thinking } = this._processApiResponse(response);
            return this.buildClaudeResponse(responseText, false, 'assistant', model, toolCalls, thinking);
        } catch (error) {
            console.error('[Kiro] Error in generateContent:', error);
            throw new Error(`Error processing response: ${error.message}`);
        }
    }

    //kiro提供的接口没有流式返回
    async streamApi(method, model, body, isRetry = false, retryCount = 0) {
        try {
            // 直接调用并返回Promise，最终解析为response
            return await this.callApi(method, model, body, isRetry, retryCount);
        } catch (error) {
            console.error('[Kiro] Error calling API:', error);
            throw error; // 向上抛出错误
        }
    }

    // 重构2: generateContentStream 调用新的普通async函数
    async * generateContentStream(model, requestBody) {
        if (!this.isInitialized) await this.initialize();
        
        // 检查 token 是否即将过期,如果是则先刷新
        if (this.isExpiryDateNear()) {
            console.log('[Kiro] Token is near expiry, refreshing before generateContentStream request...');
            // Try to refresh with credential rotation on failure
            let refreshSuccess = false;
            const totalCreds = this.credentialsList.length;
            let attempts = 0;
            
            while (!refreshSuccess && attempts < totalCreds) {
                try {
                    await this.initializeAuth(true);
                    refreshSuccess = true;
                } catch (refreshError) {
                    console.error(`[Kiro] Token refresh failed for credential #${this.getCurrentCredentialNumber()}: ${refreshError.message}`);
                    attempts++;
                    if (attempts < totalCreds && this.switchCredentials()) {
                        console.log(`[Kiro] Trying next credential (attempt ${attempts + 1}/${totalCreds})...`);
                    } else if (attempts >= totalCreds) {
                        throw new Error(`All ${totalCreds} credentials failed to refresh. Please update your credentials.`);
                    }
                }
            }
        }
        
        const finalModel = MODEL_MAPPING[model] ? model : this.modelName;
        console.log(`[Kiro] Calling generateContentStream with model: ${finalModel}`);
        
        try {
            const response = await this.streamApi('', finalModel, requestBody);
            const { responseText, toolCalls, thinking } = this._processApiResponse(response);

            // Pass both responseText, toolCalls and thinking to buildClaudeResponse
            // buildClaudeResponse will handle the logic of combining them into a single stream
            for (const chunkJson of this.buildClaudeResponse(responseText, true, 'assistant', model, toolCalls, thinking)) {
                yield chunkJson;
            }
        } catch (error) {
            console.error('[Kiro] Error in streaming generation:', error);
            throw new Error(`Error processing response: ${error.message}`);
            // For Claude, we yield an array of events for streaming error
            // Ensure error message is passed as content, not toolCalls
            // for (const chunkJson of this.buildClaudeResponse(`Error: ${error.message}`, true, 'assistant', model, null)) {
            //     yield chunkJson;
            // }
        }
    }

    /**
     * Build Claude compatible response object
     * @param {string} content - Text content
     * @param {boolean} isStream - Whether this is a streaming response
     * @param {string} role - Message role
     * @param {string} model - Model name
     * @param {Array} toolCalls - Array of tool calls
     * @param {string} thinking - Thinking/reasoning content for extended thinking
     */
    buildClaudeResponse(content, isStream = false, role = 'assistant', model, toolCalls = null, thinking = null) {
        const messageId = `${uuidv4()}`;
        // Helper to estimate tokens (simple heuristic)
        const estimateTokens = (text) => Math.ceil((text || '').length / 4);

        if (isStream) {
            // Kiro API is "pseudo-streaming", so we'll send a few events to simulate
            // a full Claude stream, but the content/tool_calls will be sent in one go.
            const events = [];

            // 1. message_start event
            events.push({
                type: "message_start",
                message: {
                    id: messageId,
                    type: "message",
                    role: role,
                    model: model,
                    usage: {
                        input_tokens: 0, // Kiro API doesn't provide this
                        output_tokens: 0 // Will be updated in message_delta
                    },
                    content: [] // Content will be streamed via content_block_delta
                }
            });
 
            let totalOutputTokens = 0;
            let stopReason = "end_turn";
            let currentBlockIndex = 0;

            // Add thinking content block first (if present)
            if (thinking) {
                // content_block_start for thinking
                events.push({
                    type: "content_block_start",
                    index: currentBlockIndex,
                    content_block: {
                        type: "thinking",
                        thinking: ""
                    }
                });
                // content_block_delta for thinking
                events.push({
                    type: "content_block_delta",
                    index: currentBlockIndex,
                    delta: {
                        type: "thinking_delta",
                        thinking: thinking
                    }
                });
                // content_block_stop for thinking
                events.push({
                    type: "content_block_stop",
                    index: currentBlockIndex
                });
                totalOutputTokens += estimateTokens(thinking);
                currentBlockIndex++;
            }

            if (content) {
                // Calculate content block index (after thinking and tool calls)
                const contentBlockIndex = currentBlockIndex + ((toolCalls && toolCalls.length > 0) ? toolCalls.length : 0);

                // 2. content_block_start for text
                events.push({
                    type: "content_block_start",
                    index: contentBlockIndex,
                    content_block: {
                        type: "text",
                        text: "" // Initial empty text
                    }
                });
                // 3. content_block_delta for text
                events.push({
                    type: "content_block_delta",
                    index: contentBlockIndex,
                    delta: {
                        type: "text_delta",
                        text: content
                    }
                });
                // 4. content_block_stop
                events.push({
                    type: "content_block_stop",
                    index: contentBlockIndex
                });
                totalOutputTokens += estimateTokens(content);
                // If there are tool calls, the stop reason remains "tool_use".
                // If only content, it's "end_turn".
                if (!toolCalls || toolCalls.length === 0) {
                    stopReason = "end_turn";
                }
            }

            if (toolCalls && toolCalls.length > 0) {
                toolCalls.forEach((tc, index) => {
                    let inputObject;
                    try {
                        // Arguments should be a stringified JSON object.
                        inputObject = tc.function.arguments;
                    } catch (e) {
                        console.warn(`[Kiro] Invalid JSON for tool call arguments. Wrapping in raw_arguments. Error: ${e.message}`, tc.function.arguments);
                        // If parsing fails, wrap the raw string in an object as a fallback,
                        // since Claude's `input` field expects an object.
                        inputObject = { "raw_arguments": tc.function.arguments };
                    }
                    // Adjust index to account for thinking block
                    const toolBlockIndex = currentBlockIndex + index;
                    // 2. content_block_start for each tool_use
                    events.push({
                        type: "content_block_start",
                        index: toolBlockIndex,
                        content_block: {
                            type: "tool_use",
                            id: tc.id,
                            name: tc.function.name,
                            input: {} // input is streamed via input_json_delta
                        }
                    });
                    
                    // 3. content_block_delta for each tool_use
                    // Since Kiro is not truly streaming, we send the full arguments as one delta.
                    events.push({
                        type: "content_block_delta",
                        index: toolBlockIndex,
                        delta: {
                            type: "input_json_delta",
                            partial_json: inputObject
                        }
                    });
 
                    // 4. content_block_stop for each tool_use
                    events.push({
                        type: "content_block_stop",
                        index: toolBlockIndex
                    });
                    totalOutputTokens += estimateTokens(JSON.stringify(inputObject));
                });
                stopReason = "tool_use"; // If there are tool calls, the stop reason is tool_use
            }

            // 5. message_delta with appropriate stop reason
            events.push({
                type: "message_delta",
                delta: {
                    stop_reason: stopReason,
                    stop_sequence: null,
                },
                usage: { output_tokens: totalOutputTokens }
            });

            // 6. message_stop event
            events.push({
                type: "message_stop"
            });

            return events; // Return an array of events for streaming
        } else {
            // Non-streaming response (full message object)
            const contentArray = [];
            let stopReason = "end_turn";
            let outputTokens = 0;

            // Add thinking content first (if present)
            if (thinking) {
                contentArray.push({
                    type: "thinking",
                    thinking: thinking
                });
                outputTokens += estimateTokens(thinking);
            }

            if (toolCalls && toolCalls.length > 0) {
                for (const tc of toolCalls) {
                    let inputObject;
                    try {
                        // Arguments should be a stringified JSON object.
                        inputObject = tc.function.arguments;
                    } catch (e) {
                        console.warn(`[Kiro] Invalid JSON for tool call arguments. Wrapping in raw_arguments. Error: ${e.message}`, tc.function.arguments);
                        // If parsing fails, wrap the raw string in an object as a fallback,
                        // since Claude's `input` field expects an object.
                        inputObject = { "raw_arguments": tc.function.arguments };
                    }
                    contentArray.push({
                        type: "tool_use",
                        id: tc.id,
                        name: tc.function.name,
                        input: inputObject
                    });
                    outputTokens += estimateTokens(tc.function.arguments);
                }
                stopReason = "tool_use"; // Set stop_reason to "tool_use" when toolCalls exist
            }
            
            // Add text content (can coexist with thinking and tool_use)
            if (content) {
                contentArray.push({
                    type: "text",
                    text: content
                });
                outputTokens += estimateTokens(content);
            }

            return {
                id: messageId,
                type: "message",
                role: role,
                model: model,
                stop_reason: stopReason,
                stop_sequence: null,
                usage: {
                    input_tokens: 0, // Kiro API doesn't provide this
                    output_tokens: outputTokens
                },
                content: contentArray
            };
        }
    }

    /**
     * List available models
     */
    async listModels() {
        const models = Object.keys(MODEL_MAPPING).map(id => ({
            name: id
        }));
        
        return { models: models };
    }

    /**
     * Checks if the given expiresAt timestamp is within 10 minutes from now.
     * @returns {boolean} - True if expiresAt is less than 10 minutes from now, false otherwise.
     */
    isExpiryDateNear() {
        try {
            const expirationTime = new Date(this.expiresAt);
            const currentTime = new Date();
            const cronNearMinutesInMillis = (this.config.CRON_NEAR_MINUTES || 10) * 60 * 1000;
            const thresholdTime = new Date(currentTime.getTime() + cronNearMinutesInMillis);
            console.log(`[Kiro] Expiry date: ${expirationTime.getTime()}, Current time: ${currentTime.getTime()}, ${this.config.CRON_NEAR_MINUTES || 10} minutes from now: ${thresholdTime.getTime()}`);
            return expirationTime.getTime() <= thresholdTime.getTime();
        } catch (error) {
            console.error(`[Kiro] Error checking expiry date: ${this.expiresAt}, Error: ${error.message}`);
            return false; // Treat as expired if parsing fails
        }
    }
}
