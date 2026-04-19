import {
	NodeOperationError,
	type IDataObject,
	type ICredentialDataDecryptedObject,
	type INodeExecutionData,
	type INodeProperties,
	type INodeType,
	type INodeTypeDescription,
	type ITriggerFunctions,
	type ITriggerResponse,
} from 'n8n-workflow';
import type { CloseEvent, ErrorEvent } from 'undici-types';

type AuthType = 'token' | 'cloud';
const HEARTBEAT_INTERVAL_MS = 5000;
type ParsedEventPayload =
	| IDataObject
	| string
	| number
	| boolean
	| IDataObject[]
	| string[]
	| number[]
	| boolean[]
	| null;

function parseFilterList(value: string): string[] {
	return value
		.split(',')
		.map((entry) => entry.trim())
		.filter((entry) => entry.length > 0);
}

async function buildWebSocketConfig(
	this: ITriggerFunctions,
): Promise<{
	wsUrl: string;
	accessTokenSubProtocol: string;
	allowUnauthorizedCerts: boolean;
	sourceName: string;
}> {
	const credentials = (await this.getCredentials(
		'openHABApi',
	)) as ICredentialDataDecryptedObject;

	const rawAuthType = ((credentials.authType as string | undefined) ?? 'token').toLowerCase();
	if (rawAuthType === 'basic') {
		throw new NodeOperationError(
			this.getNode(),
			'Local Basic Auth is no longer supported. Use "API Token (local openHAB)" or "myopenHAB Account".',
		);
	}

	const authType: AuthType = rawAuthType === 'cloud' ? 'cloud' : 'token';
	const useCloud = authType === 'cloud';
	const configuredLocalBaseUrl = (
		(credentials.baseUrlLocal as string | undefined) ??
		(credentials.baseUrl as string | undefined) ??
		''
	).trim();
	const baseUrl = (
		useCloud ? 'https://home.myopenhab.org' : configuredLocalBaseUrl || 'http://localhost:8080'
	).replace(/\/+$/, '');

	if (!baseUrl) {
		throw new NodeOperationError(this.getNode(), 'Base URL is missing in credentials.');
	}

	let accessToken = '';
	if (useCloud) {
		const cloudToken = ((credentials.cloudToken as string | undefined) ?? '').trim();
		if (cloudToken) {
			accessToken = cloudToken;
		} else {
			const username = (credentials.username as string | undefined) ?? '';
			const password = (credentials.password as string | undefined) ?? '';
			if (!username || !password) {
				throw new NodeOperationError(
					this.getNode(),
					'Username and password are required for myopenHAB Account.',
				);
			}
			accessToken = Buffer.from(`${username}:${password}`).toString('base64');
		}
	} else {
		const token = ((credentials.token as string | undefined) ?? '').trim();
		if (!token) {
			throw new NodeOperationError(this.getNode(), 'API token is required.');
		}
		accessToken = token;
	}

	const allowUnauthorizedCerts = Boolean(credentials.allowUnauthorizedCerts) && !useCloud;

	let parsedUrl: URL;
	try {
		parsedUrl = new URL(baseUrl);
	} catch (error) {
		throw new NodeOperationError(
			this.getNode(),
			`Invalid Base URL "${baseUrl}": ${(error as Error).message}`,
		);
	}

	parsedUrl.protocol = parsedUrl.protocol === 'https:' ? 'wss:' : 'ws:';
	parsedUrl.pathname = '/ws/events';
	parsedUrl.search = '';

	return {
		wsUrl: parsedUrl.toString(),
		accessTokenSubProtocol: Buffer.from(accessToken).toString('base64').replace(/=+$/, ''),
		allowUnauthorizedCerts,
		sourceName: `n8n:${this.getWorkflow().id}:${this.getNode().name}`,
	};
}

export class openHABTrigger implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'openHAB Trigger',
		name: 'openHABTrigger',
		icon: 'file:openhab.svg',
		group: ['trigger'],
		version: 1,
		description: 'Listen to the openHAB event WebSocket stream.',
		defaults: {
			name: 'openHAB Trigger',
		},
		inputs: [],
		outputs: ['main'],
		credentials: [
			{
				name: 'openHABApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Topic Filters',
				name: 'topicFilters',
				type: 'string',
				default: '',
				placeholder: 'openhab/items/*/statechanged,!openhab/items/MyItem/*',
				description:
					'Comma-separated WebSocket topic filters. Supports wildcards, regular expressions, and exclusions prefixed with !',
			},
			{
				displayName: 'Type Filters',
				name: 'typeFilters',
				type: 'string',
				default: '',
				placeholder: 'ItemStateEvent,ItemStateChangedEvent',
				description:
					'Comma-separated event types to subscribe to. Leave empty to receive all event types',
			},
		] as INodeProperties[],
	};

	async trigger(this: ITriggerFunctions): Promise<ITriggerResponse> {
		const topicFilters = parseFilterList(this.getNodeParameter('topicFilters') as string);
		const typeFilters = parseFilterList(this.getNodeParameter('typeFilters') as string);
		const { wsUrl, accessTokenSubProtocol, allowUnauthorizedCerts, sourceName } =
			await buildWebSocketConfig.call(this);

		let isClosing = false;
		let heartbeatTimer: NodeJS.Timeout | undefined;

		if (allowUnauthorizedCerts) {
			throw new NodeOperationError(
				this.getNode(),
				'Self-signed certificate support is not available with the built-in WebSocket client. Use HTTP instead of HTTPS for local openHAB connections, or install a trusted certificate.',
			);
		}

		const ws = new WebSocket(
			wsUrl,
			[
				'org.openhab.ws.protocol.default',
				`org.openhab.ws.accessToken.base64.${accessTokenSubProtocol}`,
			],
		);

		const sendEvent = (topic: string, payload: unknown) => {
			if (ws.readyState !== WebSocket.OPEN) {
				return;
			}
			ws.send(
				JSON.stringify({
					type: 'WebSocketEvent',
					topic,
					payload: JSON.stringify(payload),
					source: sourceName,
				}),
			);
		};

		ws.addEventListener('open', () => {
			if (topicFilters.length > 0) {
				sendEvent('openhab/websocket/filter/topic', topicFilters);
			}
			if (typeFilters.length > 0) {
				sendEvent('openhab/websocket/filter/type', typeFilters);
			}
			heartbeatTimer = setInterval(() => {
				if (ws.readyState !== WebSocket.OPEN) {
					return;
				}
				ws.send(
					JSON.stringify({
						type: 'WebSocketEvent',
						topic: 'openhab/websocket/heartbeat',
						payload: 'PING',
						source: sourceName,
					}),
				);
			}, HEARTBEAT_INTERVAL_MS);
		});

		ws.addEventListener('message', (event: MessageEvent) => {
			const messageText = event.data as string;

			let eventData: IDataObject;
			try {
				eventData = JSON.parse(messageText) as IDataObject;
			} catch {
				return;
			}

			const eventType = ((eventData.type as string | undefined) ?? '').trim();
			const eventTopic = ((eventData.topic as string | undefined) ?? '').trim();
			if (eventType === 'WebSocketEvent' && eventTopic.startsWith('openhab/websocket/')) {
				return;
			}

			const payloadRaw = eventData.payload;
			let payloadParsed = payloadRaw as ParsedEventPayload;
			if (typeof payloadRaw === 'string') {
				try {
					payloadParsed = JSON.parse(payloadRaw) as ParsedEventPayload;
				} catch {
					// Keep original string payload.
				}
			}

			const item: INodeExecutionData = {
				json: {
					...eventData,
					payloadRaw,
					payloadParsed,
					receivedAt: new Date().toISOString(),
				},
			};
			this.emit([[item]]);
		});

		ws.addEventListener('error', (event: Event) => {
			if (!isClosing) {
				const errEvent = event as unknown as ErrorEvent;
				this.emitError(new Error(errEvent.message || `WebSocket error (url: ${wsUrl}, readyState: ${ws.readyState})`));
			}
		});

		ws.addEventListener('close', (event: Event) => {
			const closeEvent = event as unknown as CloseEvent;
			if (heartbeatTimer) {
				clearInterval(heartbeatTimer);
				heartbeatTimer = undefined;
			}
			if (!isClosing) {
				const reasonText = closeEvent.reason ? `: ${closeEvent.reason}` : '';
				this.emitError(
					new NodeOperationError(
						this.getNode(),
						`openHAB event WebSocket closed with code ${closeEvent.code}${reasonText}`,
					),
				);
			}
		});

		return {
			closeFunction: async () => {
				isClosing = true;
				if (heartbeatTimer) {
					clearInterval(heartbeatTimer);
					heartbeatTimer = undefined;
				}
				if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
					ws.close();
				}
			},
		};
	}
}
