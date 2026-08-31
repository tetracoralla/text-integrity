import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import { executeOperation } from "../core/operations.js";
import { TextIntegrityError, errorPayload } from "../core/errors.js";
import { LIMITS } from "../core/limits.js";

const UI_DIRECTORY = fileURLToPath(new URL("./public/", import.meta.url));
const STATIC_FILES = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/app.js", ["app.js", "text/javascript; charset=utf-8"]],
  ["/styles.css", ["styles.css", "text/css; charset=utf-8"]]
]);
const MAX_BODY_BYTES = LIMITS.maxCliInputBytes;

function sendJson(response, statusCode, value) {
  const body = JSON.stringify(value);
  response.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store"
  });
  response.end(body);
}

async function readJsonBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAX_BODY_BYTES) {
      throw new TextIntegrityError("REQUEST_TOO_LARGE", `Request body exceeds ${MAX_BODY_BYTES} bytes.`);
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new TextIntegrityError("INVALID_INPUT", "Request body must be valid JSON.");
  }
}

export function createUiServer() {
  return http.createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://localhost");
    if (request.method === "POST" && url.pathname === "/api/run") {
      try {
        const body = await readJsonBody(request);
        if (body === null || typeof body !== "object" || Array.isArray(body)) {
          throw new TextIntegrityError("INVALID_INPUT", "Request must be an object.");
        }
        const keys = Object.keys(body);
        if (keys.length !== 2 || !keys.includes("operation") || !keys.includes("arguments")) {
          throw new TextIntegrityError("INVALID_INPUT", "Request must contain only operation and arguments.");
        }
        sendJson(response, 200, executeOperation(body.operation, body.arguments));
      } catch (error) {
        sendJson(response, 400, errorPayload(error));
      }
      return;
    }

    const staticFile = request.method === "GET" ? STATIC_FILES.get(url.pathname) : undefined;
    if (staticFile) {
      const [filename, contentType] = staticFile;
      try {
        const content = await readFile(path.join(UI_DIRECTORY, filename));
        response.writeHead(200, {
          "content-type": contentType,
          "content-length": content.length,
          "x-content-type-options": "nosniff"
        });
        response.end(content);
      } catch {
        response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
        response.end("Static file unavailable\n");
      }
      return;
    }

    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("Not found\n");
  });
}

export function startUiServer(port = Number(process.env.PORT ?? 4173), host = process.env.HOST ?? "127.0.0.1") {
  const server = createUiServer();
  server.listen(port, host, () => {
    const address = server.address();
    const resolvedPort = typeof address === "object" && address ? address.port : port;
    process.stdout.write(`${JSON.stringify({ status: "listening", url: `http://${host}:${resolvedPort}` })}\n`);
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startUiServer();
}
