import * as crypto from 'crypto';
import * as net from 'net';
import * as tls from 'tls';

const WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export interface SimpleWebSocketOptions {
	/** When false, skips TLS certificate validation (self-signed certs). Defaults to true. */
	rejectUnauthorized?: boolean;
	/** Extra HTTP headers to include in the WebSocket upgrade request (e.g. Authorization). */
	extraHeaders?: Record<string, string>;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type SimpleEventListener = (event: any) => void;

export class SimpleWebSocket {
	static readonly CONNECTING = 0;
	static readonly OPEN = 1;
	static readonly CLOSING = 2;
	static readonly CLOSED = 3;

	readyState: number = SimpleWebSocket.CONNECTING;

	private readonly socket: net.Socket;
	private readonly listenerMap = new Map<string, SimpleEventListener[]>();
	private recvBuffer = Buffer.alloc(0);
	private handshakeDone = false;
	private closeEmitted = false;
	private readonly handshakeKey: string;
	private fragmentBuffer: Buffer | null = null;
	private fragmentOpcode = 0;

	constructor(
		private readonly url: string,
		private readonly protocols: string | string[],
		private readonly options: SimpleWebSocketOptions = {},
	) {
		this.handshakeKey = crypto.randomBytes(16).toString('base64');
		this.socket = this.createSocket();
	}

	private createSocket(): net.Socket {
		const parsedUrl = new URL(this.url);
		const isSecure = parsedUrl.protocol === 'wss:';
		const host = parsedUrl.hostname;
		const port = parsedUrl.port ? Number(parsedUrl.port) : isSecure ? 443 : 80;

		const onError = (err: Error) => {
			if (this.readyState !== SimpleWebSocket.CLOSED) {
				this.readyState = SimpleWebSocket.CLOSED;
				this.fireEvent('error', { message: err.message });
				if (!this.closeEmitted) {
					this.closeEmitted = true;
					this.fireEvent('close', { code: 1006, reason: '' });
				}
			}
		};

		const onData = (chunk: Buffer) => {
			this.recvBuffer = Buffer.concat([this.recvBuffer, chunk]);
			if (!this.handshakeDone) {
				this.processHandshake(parsedUrl);
			} else {
				this.processFrames();
			}
		};

		const onSocketClose = () => {
			if (!this.closeEmitted) {
				this.closeEmitted = true;
				this.readyState = SimpleWebSocket.CLOSED;
				this.fireEvent('close', { code: 1006, reason: '' });
			}
		};

		let socket: net.Socket;
		if (isSecure) {
			const tlsSocket = tls.connect({
				host,
				port,
				servername: host,
				rejectUnauthorized: this.options.rejectUnauthorized !== false,
			});
			tlsSocket.on('secureConnect', () => {
				this.sendHandshake(parsedUrl);
			});
			socket = tlsSocket;
		} else {
			socket = net.connect({ host, port });
			socket.on('connect', () => {
				this.sendHandshake(parsedUrl);
			});
		}

		socket.on('error', onError);
		socket.on('data', onData);
		socket.on('close', onSocketClose);

		return socket;
	}

	private sendHandshake(parsedUrl: URL): void {
		const defaultPort = parsedUrl.protocol === 'wss:' ? 443 : 80;
		const explicitPort = parsedUrl.port ? Number(parsedUrl.port) : null;
		const hostHeader =
			explicitPort !== null && explicitPort !== defaultPort
				? `${parsedUrl.hostname}:${explicitPort}`
				: parsedUrl.hostname;

		const path = (parsedUrl.pathname || '/') + (parsedUrl.search || '');

		const protocolList = Array.isArray(this.protocols)
			? this.protocols.join(', ')
			: this.protocols;

		const extraHeaderLines = Object.entries(this.options.extraHeaders ?? {})
			.map(([k, v]) => `${k}: ${v}`)
			.join('\r\n');

		const lines = [
			`GET ${path} HTTP/1.1`,
			`Host: ${hostHeader}`,
			'Upgrade: websocket',
			'Connection: Upgrade',
			`Sec-WebSocket-Key: ${this.handshakeKey}`,
			'Sec-WebSocket-Version: 13',
		];
		if (protocolList) {
			lines.push(`Sec-WebSocket-Protocol: ${protocolList}`);
		}
		if (extraHeaderLines) {
			lines.push(extraHeaderLines);
		}
		lines.push('', '');

		this.socket.write(lines.join('\r\n'));
	}

	private processHandshake(parsedUrl: URL): void {
		const str = this.recvBuffer.toString('binary');
		const headerEnd = str.indexOf('\r\n\r\n');
		if (headerEnd === -1) return;

		const headerSection = str.slice(0, headerEnd);
		const lines = headerSection.split('\r\n');
		const statusLine = lines[0] ?? '';

		if (!statusLine.includes('101')) {
			this.readyState = SimpleWebSocket.CLOSED;
			this.fireEvent('error', {
				message: `WebSocket handshake failed: ${statusLine} (url: ${parsedUrl.toString()})`,
			});
			this.socket.destroy();
			return;
		}

		const acceptLine = lines.find((l) => l.toLowerCase().startsWith('sec-websocket-accept:'));
		if (acceptLine) {
			const acceptValue = acceptLine.split(':').slice(1).join(':').trim();
			const expectedAccept = crypto
				.createHash('sha1')
				.update(this.handshakeKey + WS_MAGIC)
				.digest('base64');
			if (acceptValue !== expectedAccept) {
				this.readyState = SimpleWebSocket.CLOSED;
				this.fireEvent('error', {
					message: 'WebSocket handshake failed: invalid Sec-WebSocket-Accept',
				});
				this.socket.destroy();
				return;
			}
		}

		this.handshakeDone = true;
		this.readyState = SimpleWebSocket.OPEN;
		this.recvBuffer = this.recvBuffer.slice(headerEnd + 4);
		this.fireEvent('open', {});
		if (this.recvBuffer.length > 0) {
			this.processFrames();
		}
	}

	private processFrames(): void {
		while (this.recvBuffer.length >= 2) {
			const b0 = this.recvBuffer[0];
			const b1 = this.recvBuffer[1];

			const fin = (b0 & 0x80) !== 0;
			const opcode = b0 & 0x0f;
			const masked = (b1 & 0x80) !== 0;
			let payloadLen = b1 & 0x7f;
			let headerLen = 2;

			if (payloadLen === 126) {
				if (this.recvBuffer.length < 4) break;
				payloadLen = this.recvBuffer.readUInt16BE(2);
				headerLen = 4;
			} else if (payloadLen === 127) {
				if (this.recvBuffer.length < 10) break;
				// hi * 2^32 + lo is exact for payloads up to 2^53 bytes (safe integer limit).
				const hi = this.recvBuffer.readUInt32BE(2);
				const lo = this.recvBuffer.readUInt32BE(6);
				payloadLen = hi * 0x100000000 + lo;
				headerLen = 10;
			}

			if (masked) headerLen += 4;
			if (this.recvBuffer.length < headerLen + payloadLen) break;

			let payload = this.recvBuffer.slice(headerLen, headerLen + payloadLen);
			if (masked) {
				const maskStart = headerLen - 4;
				const mask = this.recvBuffer.slice(maskStart, maskStart + 4);
				payload = Buffer.from(payload);
				for (let i = 0; i < payload.length; i++) {
					payload[i] ^= mask[i % 4];
				}
			}

			this.recvBuffer = this.recvBuffer.slice(headerLen + payloadLen);
			this.handleFrame(fin, opcode, payload);
		}
	}

	private handleFrame(fin: boolean, opcode: number, payload: Buffer): void {
		if (opcode === 0x0) {
			// Continuation frame
			this.fragmentBuffer = this.fragmentBuffer
				? Buffer.concat([this.fragmentBuffer, payload])
				: Buffer.from(payload);
			if (fin) {
				const fullPayload = this.fragmentBuffer;
				const op = this.fragmentOpcode;
				this.fragmentBuffer = null;
				this.fragmentOpcode = 0;
				this.fireEvent('message', {
					data: op === 0x1 ? fullPayload.toString('utf8') : fullPayload,
				});
			}
			return;
		}

		switch (opcode) {
			case 0x1: // text
			case 0x2: // binary
				if (!fin) {
					// First fragment of a fragmented message
					this.fragmentBuffer = Buffer.from(payload);
					this.fragmentOpcode = opcode;
				} else {
					this.fireEvent('message', {
						data: opcode === 0x1 ? payload.toString('utf8') : payload,
					});
				}
				break;
			case 0x8: {
				// Close
				this.readyState = SimpleWebSocket.CLOSING;
				this.sendFrame(0x8, payload);
				const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1000;
				const reason = payload.length > 2 ? payload.slice(2).toString('utf8') : '';
				this.closeEmitted = true;
				this.socket.destroy();
				this.readyState = SimpleWebSocket.CLOSED;
				this.fireEvent('close', { code, reason });
				break;
			}
			case 0x9: // Ping → Pong
				this.sendFrame(0xa, payload);
				break;
			case 0xa: // Pong — no action needed
				break;
			default:
				break;
		}
	}

	send(data: string | Buffer): void {
		if (this.readyState !== SimpleWebSocket.OPEN) return;
		const payload = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
		const opcode = typeof data === 'string' ? 0x1 : 0x2;
		this.sendFrame(opcode, payload);
	}

	private sendFrame(opcode: number, payload: Buffer): void {
		if (this.socket.destroyed) return;

		const payloadLen = payload.length;
		let headerLen = 6; // 2 base + 4 mask bytes
		if (payloadLen > 65535) {
			headerLen += 8;
		} else if (payloadLen > 125) {
			headerLen += 2;
		}

		const frame = Buffer.allocUnsafe(headerLen + payloadLen);
		frame[0] = 0x80 | opcode; // FIN + opcode

		const mask = crypto.randomBytes(4);
		if (payloadLen > 65535) {
			frame[1] = 0x80 | 127;
			frame.writeUInt32BE(0, 2);
			frame.writeUInt32BE(payloadLen, 6);
			mask.copy(frame, 10);
		} else if (payloadLen > 125) {
			frame[1] = 0x80 | 126;
			frame.writeUInt16BE(payloadLen, 2);
			mask.copy(frame, 4);
		} else {
			frame[1] = 0x80 | payloadLen;
			mask.copy(frame, 2);
		}

		for (let i = 0; i < payloadLen; i++) {
			frame[headerLen + i] = payload[i] ^ mask[i % 4];
		}

		this.socket.write(frame);
	}

	close(): void {
		if (
			this.readyState === SimpleWebSocket.CLOSING ||
			this.readyState === SimpleWebSocket.CLOSED
		) {
			return;
		}
		this.readyState = SimpleWebSocket.CLOSING;
		this.sendFrame(0x8, Buffer.alloc(0));
		this.socket.destroy();
		this.readyState = SimpleWebSocket.CLOSED;
	}

	addEventListener(type: string, listener: SimpleEventListener): void {
		if (!this.listenerMap.has(type)) {
			this.listenerMap.set(type, []);
		}
		this.listenerMap.get(type)!.push(listener);
	}

	private fireEvent(type: string, event: unknown): void {
		for (const listener of this.listenerMap.get(type) ?? []) {
			listener(event);
		}
	}
}
