// Challenge-page bootstrap.
//
// Loaded as an external ES module because the CSP (script-src 'self',
// see middleware/headers.rs) forbids inline scripts. The logic that
// used to live in an inline <script type="module"> tag now lives here.
//
// The dynamic import means a failure to fetch the wasm-bindgen glue
// is caught and shown on the page instead of failing silently.
//
// The nonce / nonce-sig / destination are read from the #challenge-data
// data attributes by solve() inside the WASM module — the server embeds
// them in the HTML so no extra network request is needed.

async function start() {
    if (typeof WebAssembly === 'undefined') {
        // No WASM support — show the dedicated error and stop.
        const status = document.getElementById('status');
        const error = document.getElementById('error');
        if (status) status.style.display = 'none';
        if (error) error.style.display = 'block';
        return;
    }

    // wasm-bindgen "web" target glue: the default export is init(),
    // and the Rust #[wasm_bindgen] exports (solve) ride along as
    // named exports. Pass the wasm path explicitly — the deployed
    // file is renamed from pow_challenge_bg.wasm to pow_challenge.wasm.
    const glue = await import('/static/pow_challenge.js');
    await glue.default('/static/pow_challenge.wasm');
    await glue.solve();
}

start().catch((err) => {
    const status = document.getElementById('status');
    if (status) {
        status.textContent =
            'Verification failed. Please refresh the page.';
    }
    console.error('WASM error:', err);
});
