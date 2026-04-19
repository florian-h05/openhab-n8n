/**
 * Minimal WebSocket client built entirely on Node.js built-in modules.
 *
 * Supports:
 * - ws:// and wss:// connections (including self-signed certificates)
 * - WebSocket sub-protocol negotiation
 * - Sending text frames (client → server, always masked)
 * - Receiving text frames (server → client, never masked per RFC 6455)
 * - Proper close-frame handshake
 * - Responding to WebSocket ping frames with pong
 *
 * This intentionally does not use any external packages so the overall
 * package has zero runtime dependencies.
 */

import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import * as http from 'node:http';
import * as https from 'node:https';
import type * as stream from 'node:stream';

// RFC 6455 opcode values
const OP_CONTINUATION = 0x0;
const OP_TEXT = 0x1;
const OP_BINARY = 0x2;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;

// WebSocket magic GUID used in the handshake (RFC 6455 §1.3)
const WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export type ReadyState = 0 | 1 | 2 | 3;

export interface SimpleWebSocketOptions {
	/** When false, skips TLS certificate verification (local self-signed certs). */
	rejectUnauthorized?: boolean;
}

/**
 * Minimal WebSocket client.  The public API mirrors the subset of `ws.WebSocket`
 * that the openHAB trigger node actually uses:
 *
 * - Constructor: `new SimpleWebSocket(url, protocols, options?)`
 * - Events: `open`, `message` (payload: Buffer), `error`, `close` (code, reason Buffer)
 * - `.send(text)` — send a UTF-8 text message
 * - `.close()` — initiate a clean close
 * - `.readyState` — 0 CONNECTING, 1 OPEN, 2 CLOSING, 3 CLOSED
 * - `.CONNECTING`, `.OPEN`, `.CLOSING`, `.CLOSED` static constants
 */
export class SimpleWebSocket extends EventEmitter {
	static readonly CONNECTING = 0 as const;
	static readonly OPEN = 1 as const;
	static readonly CLOSING = 2 as const;
	static readonly CLOSED = 3 as const;

	readyState: ReadyState = SimpleWebSocket.CONNECTING;

	private socket: stream.Duplex | null = null;

	/** Accumulated bytes waiting to be parsed into frames. */
	private recvBuffer = Buffer.alloc(0);

	/** Accumulated payload for a fragmented message (opcode + chunks). */
	private fragmentOpcode = 0;
	private fragmentChunks: Buffer[] = [];

	constructor(url: string, protocols: string[], options: SimpleWebSocketOptions = {}) {
		super();
		void this.connect(url, protocols, options);
	}

	// ─── Connection ──────────────────────────────────────────────────────────────

	private connect(url: string, protocols: string[], options: SimpleWebSocketOptions): Promise<void> {
		return new Promise((resolve, reject) => {
			const parsedUrl = new URL(url);
			const isSecure = parsedUrl.protocol === 'wss:';
			const host = parsedUrl.hostname;
			const defaultPort = isSecure ? 443 : 80;
			const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : defaultPort;
			const path = (parsedUrl.pathname || '/') + (parsedUrl.search ?? '');

			// RFC 6455 §4.1: the client nonce is 16 random bytes, base64-encoded
			const wsKey = crypto.randomBytes(16).toString('base64');
			const expectedAccept = crypto
				.createHash('sha1')
				.update(wsKey + WS_MAGIC)
				.digest('base64');

			const reqOptions: https.RequestOptions = {
				hostname: host,
				port,
				path,
				method: 'GET',
				headers: {
					Host:
						(!isSecure && port === 80) || (isSecure && port === 443)
							? host
							: `${host}:${port}`,
					Upgrade: 'websocket',
					Connection: 'Upgrade',
					'Sec-WebSocket-Key': wsKey,
					'Sec-WebSocket-Version': '13',
					...(protocols.length > 0
						? { 'Sec-WebSocket-Protocol': protocols.join(', ') }
						: {}),
				},
				// https-only option; ignored by http.request
				rejectUnauthorized: options.rejectUnauthorized !== false,
			};

			const requester = isSecure ? https : http;
			const req = requester.request(reqOptions);

			req.on('upgrade', (res: http.IncomingMessage, socket: stream.Duplex) => {
				// Validate the handshake response
				if (res.statusCode !== 101) {
					const err = new Error(`WebSocket upgrade rejected: HTTP ${res.statusCode}`);
					socket.destroy(err);
					this.readyState = SimpleWebSocket.CLOSED;
					this.emit('error', err);
					reject(err);
					return;
				}

				const acceptHeader = res.headers['sec-websocket-accept'];
				if (acceptHeader !== expectedAccept) {
					const err = new Error('Invalid Sec-WebSocket-Accept header');
					socket.destroy(err);
					this.readyState = SimpleWebSocket.CLOSED;
					this.emit('error', err);
					reject(err);
					return;
				}

				this.socket = socket;
				this.readyState = SimpleWebSocket.OPEN;
				resolve();

				socket.on('data', (chunk: Buffer) => this.onData(chunk));

				socket.on('error', (err: Error) => {
					this.emit('error', err);
				});

				socket.on('close', () => {
					if (this.readyState !== SimpleWebSocket.CLOSED) {
						this.readyState = SimpleWebSocket.CLOSED;
						// Abnormal closure
						this.emit('close', 1006, Buffer.alloc(0));
					}
				});

				this.emit('open');
			});

			req.on('response', (res: http.IncomingMessage) => {
				// A non-101 response: not a WebSocket upgrade
				res.resume();
				const err = new Error(`WebSocket upgrade failed: HTTP ${res.statusCode}`);
				this.readyState = SimpleWebSocket.CLOSED;
				this.emit('error', err);
				reject(err);
			});

			req.on('error', (err: Error) => {
				this.readyState = SimpleWebSocket.CLOSED;
				this.emit('error', err);
				reject(err);
			});

			req.end();
		});
	}

	// ─── Receiving ───────────────────────────────────────────────────────────────

	private onData(chunk: Buffer): void {
		this.recvBuffer = Buffer.concat([this.recvBuffer, chunk]);
		this.parseFrames();
	}

	private parseFrames(): void {
		while (this.recvBuffer.length >= 2) {
			const firstByte = this.recvBuffer[0];
			const secondByte = this.recvBuffer[1];

			const fin = (firstByte & 0x80) !== 0;
			const opcode = firstByte & 0x0f;
			const masked = (secondByte & 0x80) !== 0;

			// Payload length, possibly extended
			let payloadLen = secondByte & 0x7f;
			let headerLen = 2 + (masked ? 4 : 0);

			if (payloadLen === 126) {
				if (this.recvBuffer.length < 4) return; // wait for more
				payloadLen = this.recvBuffer.readUInt16BE(2);
				headerLen += 2;
			} else if (payloadLen === 127) {
				if (this.recvBuffer.length < 10) return; // wait for more
				// The high 32-bit word must be 0 for any sane message size
				const hi = this.recvBuffer.readUInt32BE(2);
				const lo = this.recvBuffer.readUInt32BE(6);
				payloadLen = hi * 0x100000000 + lo;
				headerLen += 8;
			}

			if (this.recvBuffer.length < headerLen + payloadLen) return; // wait for more

			// Unmask if needed (server → client frames should never be masked, but handle it)
			let payload: Buffer;
			if (masked) {
				const maskOffset = headerLen - 4;
				payload = Buffer.allocUnsafe(payloadLen);
				for (let i = 0; i < payloadLen; i++) {
					payload[i] =
						this.recvBuffer[headerLen + i] ^ this.recvBuffer[maskOffset + (i % 4)];
				}
			} else {
				// Safe to slice; we'll consume from recvBuffer below
				payload = Buffer.from(
					this.recvBuffer.buffer,
					this.recvBuffer.byteOffset + headerLen,
					payloadLen,
				);
			}

			this.recvBuffer = this.recvBuffer.slice(headerLen + payloadLen);

			this.handleFrame(fin, opcode, payload);
		}
	}

	private handleFrame(fin: boolean, opcode: number, payload: Buffer): void {
		switch (opcode) {
			case OP_TEXT:
			case OP_BINARY: {
				if (fin && this.fragmentChunks.length === 0) {
					// Simple, non-fragmented message
					this.emit('message', Buffer.from(payload));
				} else {
					// Start of a fragmented message
					this.fragmentOpcode = opcode;
					this.fragmentChunks = [Buffer.from(payload)];
					if (fin) this.deliverFragment();
				}
				break;
			}
			case OP_CONTINUATION: {
				this.fragmentChunks.push(Buffer.from(payload));
				if (fin) this.deliverFragment();
				break;
			}
			case OP_CLOSE: {
				const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1005;
				const reason = payload.length > 2 ? payload.slice(2) : Buffer.alloc(0);
				// Acknowledge with a close frame if we haven't already
				if (this.readyState === SimpleWebSocket.OPEN) {
					this.sendFrame(OP_CLOSE, payload);
					this.readyState = SimpleWebSocket.CLOSING;
				}
				this.socket?.end();
				this.readyState = SimpleWebSocket.CLOSED;
				this.emit('close', code, reason);
				break;
			}
			case OP_PING: {
				this.sendFrame(OP_PONG, payload);
				break;
			}
			case OP_PONG: {
				// Unsolicited pong — no action required
				break;
			}
			default:
				break;
		}
	}

	private deliverFragment(): void {
		const data = Buffer.concat(this.fragmentChunks);
		this.fragmentChunks = [];
		this.fragmentOpcode = 0;
		this.emit('message', data);
	}

	// ─── Sending ─────────────────────────────────────────────────────────────────

	/** Send a UTF-8 text message. */
	send(data: string): void {
		this.sendFrame(OP_TEXT, Buffer.from(data, 'utf8'));
	}

	/** Close the connection with an optional code and reason. */
	close(code = 1000, reason = ''): void {
		if (this.readyState !== SimpleWebSocket.OPEN) return;
		this.readyState = SimpleWebSocket.CLOSING;
		const reasonBuf = Buffer.from(reason, 'utf8');
		const payload = Buffer.allocUnsafe(2 + reasonBuf.length);
		payload.writeUInt16BE(code, 0);
		reasonBuf.copy(payload, 2);
		this.sendFrame(OP_CLOSE, payload);
		this.socket?.end();
	}

	/**
	 * Write a single WebSocket frame onto the socket.
	 * Client → server frames must always be masked (RFC 6455 §5.3).
	 */
	private sendFrame(opcode: number, payload: Buffer): void {
		if (!this.socket) return;

		const payloadLen = payload.length;
		const maskKey = crypto.randomBytes(4);

		// Frame header size: 2 base bytes + extended length + 4 mask bytes
		let headerLen = 6; // 2 + 4
		if (payloadLen > 65535) headerLen += 8;
		else if (payloadLen > 125) headerLen += 2;

		const frame = Buffer.allocUnsafe(headerLen + payloadLen);

		frame[0] = 0x80 | opcode; // FIN=1 + opcode

		if (payloadLen > 65535) {
			frame[1] = 0x80 | 127; // MASK=1 + 127
			frame.writeUInt32BE(0, 2); // high 32 bits (always 0 here)
			frame.writeUInt32BE(payloadLen, 6);
			maskKey.copy(frame, 10);
		} else if (payloadLen > 125) {
			frame[1] = 0x80 | 126; // MASK=1 + 126
			frame.writeUInt16BE(payloadLen, 2);
			maskKey.copy(frame, 4);
		} else {
			frame[1] = 0x80 | payloadLen; // MASK=1 + 7-bit length
			maskKey.copy(frame, 2);
		}

		// Apply masking
		for (let i = 0; i < payloadLen; i++) {
			frame[headerLen + i] = payload[i] ^ maskKey[i % 4];
		}

		this.socket.write(frame);
	}
}
