const textSection = document.getElementById("text-section");
const imageSection = document.getElementById("image-section");

const textInput = document.getElementById("text-input");
const imageInput = document.getElementById("image-input");
const fileName = document.getElementById("file-name");

const analyzeTextButton = document.getElementById("analyze-text");
const analyzeImageButton = document.getElementById("analyze-image");

const loading = document.getElementById("loading");
const errorBox = document.getElementById("error");
const result = document.getElementById("result");

const riskLevel = document.getElementById("risk-level");
const scamType = document.getElementById("scam-type");
const signals = document.getElementById("signals");
const explanation = document.getElementById("explanation");
const recommendations = document.getElementById("recommendations");

document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
        document.querySelectorAll(".tab").forEach((item) => {
            item.classList.remove("active");
        });

        tab.classList.add("active");

        if (tab.dataset.mode === "text") {
            textSection.classList.remove("hidden");
            imageSection.classList.add("hidden");
        } else {
            textSection.classList.add("hidden");
            imageSection.classList.remove("hidden");
        }

        clearError();
    });
});

imageInput.addEventListener("change", () => {
    const file = imageInput.files[0];

    fileName.textContent = file
        ? `Selected: ${file.name}`
        : "";
});

analyzeTextButton.addEventListener("click", async () => {
    const text = textInput.value.trim();

    if (!text) {
        showError("Please enter a message or URL to analyze.");
        return;
    }

    await analyze("/analyze/text", {
        text: text,
    });
});

analyzeImageButton.addEventListener("click", async () => {
    const file = imageInput.files[0];

    if (!file) {
        showError("Please choose an image first.");
        return;
    }

    try {
        setLoading(true);
        clearError();

        const base64 = await fileToBase64(file);

        const response = await fetch("/analyze/image", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                image_base64: base64,
                mime_type: file.type,
            }),
        });

        await handleResponse(response);
    } catch (error) {
        showError(error.message);
    } finally {
        setLoading(false);
    }
});

async function analyze(endpoint, body) {
    try {
        setLoading(true);
        clearError();

        const response = await fetch(endpoint, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(body),
        });

        await handleResponse(response);
    } catch (error) {
        showError(error.message);
    } finally {
        setLoading(false);
    }
}

async function handleResponse(response) {
    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.detail || "Analysis failed.");
    }

    displayResult(data);
}

function displayResult(data) {
    riskLevel.textContent = data.risk_level;
    scamType.textContent = data.scam_type;
    explanation.textContent = data.explanation;

    renderList(signals, data.signals);
    renderList(recommendations, data.recommended_actions);

    result.classList.remove("hidden");

    result.scrollIntoView({
        behavior: "smooth",
        block: "start",
    });
}

function renderList(element, items) {
    element.innerHTML = "";

    items.forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        element.appendChild(li);
    });
}

function fileToBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = () => {
            const result = reader.result;
            const base64 = result.split(",")[1];
            resolve(base64);
        };

        reader.onerror = () => {
            reject(new Error("Unable to read the selected image."));
        };

        reader.readAsDataURL(file);
    });
}

function setLoading(isLoading) {
    loading.classList.toggle("hidden", !isLoading);

    analyzeTextButton.disabled = isLoading;
    analyzeImageButton.disabled = isLoading;
}

function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
}

function clearError() {
    errorBox.classList.add("hidden");
    errorBox.textContent = "";
}