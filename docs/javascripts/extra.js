function replaceAppNameEverywhere(appName) {
    console.log("[REPLACE] Using appName:", appName);

    document.querySelectorAll("*").forEach(el => {
        // Replace in text nodes
        el.childNodes.forEach(node => {
            if (node.nodeType === Node.TEXT_NODE && node.nodeValue.includes("@APP_NAME")) {
                node.nodeValue = node.nodeValue.replace(/@APP_NAME/g, appName);
            }
        });

        // Replace in attributes (like href, src, etc.)
        Array.from(el.attributes || []).forEach(attr => {
            if (attr.value.includes("@APP_NAME")) {
                attr.value = attr.value.replace(/@APP_NAME/g, appName);
            }
        });
    });
}

function initAppName() {
    const appName = localStorage.getItem("appName");

    if (appName) {
        console.log("[INIT] Loaded appName:", appName);
        replaceAppNameEverywhere(appName);
    } else {
        console.log("[INIT] No appName in localStorage");
    }

    // Handle dropdown selection (if on index page)
    const select = document.getElementById("appName");
    if (select) {
        console.log("[FORM] Select found");
        if (appName) select.value = appName;

        select.addEventListener("change", () => {
            const newApp = select.value;
            if (newApp) {
                console.log("[FORM] New app selected:", newApp);
                localStorage.setItem("appName", newApp);
                location.reload(); // force reload to re-render @APP_NAME
            }
        });
    } else {
        console.log("[FORM] No select found");
    }
}

// Run on page load
document.addEventListener("DOMContentLoaded", () => {
    console.log("[EVENT] DOMContentLoaded");
    initAppName();
});

// Support mkdocs with instant navigation
document.addEventListener("navigation:end", () => {
    console.log("[EVENT] navigation:end");
    initAppName();
});


function displayResult(message) {
    const resultDiv = document.getElementById("http-method-result");
    if (resultDiv) {
        resultDiv.innerText = message;
    }
}

function getAppUrl() {
    const appName = localStorage.getItem("appName") || "@APP_NAME";
    return `https://${appName}/login.php`;
}

function sendHeadRequestToLogin() {
    fetch(getAppUrl(), {
        method: "HEAD",
        mode: "no-cors"
    })
    .then(() => {
        alert("HEAD request sent.");
    })
    .catch(error => {
        alert("Request failed: " + error);
    });
}

function sendRequestWithHeadlessUserAgent() {
    fetch(getAppUrl(), {
        method: "GET",
        mode: "no-cors",
        headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/114.0.5735.133 Safari/537.36"
        }
    })
    .then(() => {
        alert("Headless bot request sent.");
    })
    .catch(error => {
        alert("Request failed: " + error);
    });
}
