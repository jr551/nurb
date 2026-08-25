import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

// userAgentData is Chromium-only and absent from some TS DOM libs.
type NavWithUaData = Navigator & { userAgentData?: { platform?: string } };
const platform =
  (navigator as NavWithUaData).userAgentData?.platform ?? navigator.platform;
if (platform === "Linux") {
  document.documentElement.classList.add("platform-linux");
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
