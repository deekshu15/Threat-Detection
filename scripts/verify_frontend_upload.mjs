const endpoint = "http://127.0.0.1:9222";
async function getPage() {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const pages = await fetch(`${endpoint}/json`).then((response) => response.json());
      const page = pages.find(
        (candidate) =>
          candidate.type === "page" &&
          !candidate.url.startsWith("chrome-extension://") &&
          candidate.webSocketDebuggerUrl,
      );
      if (page) {
        return page;
      }
    } catch {
      // Chrome is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error("Chrome DevTools endpoint did not become ready");
}

const page = await getPage();
const socket = new WebSocket(page.webSocketDebuggerUrl);
const pending = new Map();
const consoleMessages = [];
let uploadRequest;
let uploadResponse;
let uploadFailure;
let nextId = 1;

const send = (method, params = {}) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });

await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});

socket.addEventListener("message", (event) => {
  const message = JSON.parse(event.data);
  if (message.id) {
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    if (message.error) request.reject(new Error(message.error.message));
    else request.resolve(message.result);
    return;
  }

  if (message.method === "Runtime.consoleAPICalled") {
    consoleMessages.push(
      message.params.args.map((arg) => arg.value ?? arg.description).join(" "),
    );
  }

  if (
    message.method === "Network.requestWillBeSent" &&
    message.params.request.method === "POST" &&
    message.params.request.url.endsWith("/api/upload")
  ) {
    uploadRequest = {
      method: message.params.request.method,
      url: message.params.request.url,
      requestId: message.params.requestId,
    };
  }

  if (
    message.method === "Network.responseReceived" &&
    uploadRequest?.requestId === message.params.requestId
  ) {
    uploadResponse = {
      status: message.params.response.status,
      url: message.params.response.url,
    };
  }

  if (
    message.method === "Network.loadingFailed" &&
    uploadRequest?.requestId === message.params.requestId
  ) {
    uploadFailure = {
      errorText: message.params.errorText,
      corsErrorStatus: message.params.corsErrorStatus,
    };
  }
});

await Promise.all([
  send("Runtime.enable"),
  send("Page.enable"),
  send("Network.enable"),
]);
await send("Page.navigate", { url: "http://localhost:5173" });
await new Promise((resolve) => setTimeout(resolve, 1_500));

const evaluation = await send("Runtime.evaluate", {
  awaitPromise: true,
  returnByValue: true,
  expression: `(async () => {
    const React = await import('/node_modules/.vite/deps/react.js');
    const ReactDOM = await import('/node_modules/.vite/deps/react-dom_client.js');
    const pageModule = await import('/src/modules/ingestion/DataIngestionPage.tsx');
    const createElement = React.createElement || React.default.createElement;
    const createRoot = ReactDOM.createRoot || ReactDOM.default.createRoot;
    document.body.innerHTML = '<div id="upload-verification-root"></div>';
    createRoot(document.getElementById('upload-verification-root')).render(
      createElement(pageModule.default)
    );
    await new Promise((resolve) => setTimeout(resolve, 500));
    const input = document.querySelector('input[type="file"]');
    if (!input) throw new Error('File input was not rendered');
    const transfer = new DataTransfer();
    transfer.items.add(new File([
      'Label,Source IP,Destination IP,Protocol\\nBENIGN,1.1.1.1,2.2.2.2,TCP\\n'
    ], 'codex_frontend_upload_verification.csv', { type: 'text/csv' }));
    Object.defineProperty(input, 'files', { value: transfer.files, configurable: true });
    input.dispatchEvent(new Event('change', { bubbles: true }));
    return { inputExists: true, onChangeDispatched: true };
  })()`,
});

const uploadDeadline = Date.now() + 15_000;
while (!uploadResponse && Date.now() < uploadDeadline) {
  await new Promise((resolve) => setTimeout(resolve, 200));
}

const result = {
  evaluation: evaluation.result?.value,
  exception: evaluation.exceptionDetails?.text,
  uploadRequest,
  uploadResponse,
  uploadFailure,
  consoleMessages,
};

console.log(JSON.stringify(result, null, 2));
socket.close();

if (!uploadRequest || uploadResponse?.status !== 200) {
  process.exitCode = 1;
}
