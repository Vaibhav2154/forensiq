'use client';
import { marked } from "marked";

export const exportMarkdownToPdf = async (markdownContent) => {
  // Dynamically import html2pdf (only runs in browser)
  const html2pdf = (await import("html2pdf.js")).default;

  const container = document.createElement("div");
  container.style.padding = "20px";
  container.style.background = "white";
  container.style.color = "black";
  container.style.fontFamily = "system-ui, sans-serif";

  container.innerHTML = marked.parse(markdownContent);

  const style = document.createElement("style");
  style.innerHTML = `
    h1 { font-size: 24px; font-weight: bold; margin-bottom: 10px; }
    h2 { font-size: 20px; font-weight: bold; margin-bottom: 8px; }
    h3 { font-size: 18px; font-weight: bold; margin-bottom: 6px; }
    p { margin-bottom: 6px; line-height: 1.5; }
    li { margin-bottom: 4px; }
    code { font-family: monospace; background: #f6f8fa; padding: 2px 4px; border-radius: 4px; font-size: 0.9em; }
    pre { background: #f6f8fa; padding: 10px; border-radius: 6px; overflow-x: auto; }
    blockquote { border-left: 4px solid #ddd; padding-left: 10px; color: #555; margin: 6px 0; }
  `;
  container.appendChild(style);

  const options = {
    margin: 0.5,
    filename: "markdown.pdf",
    image: { type: "jpeg", quality: 0.98 },
    html2canvas: { scale: 2 },
    jsPDF: { unit: "in", format: "a4", orientation: "portrait" },
  };

  html2pdf()
    .set(options)
    .from(container)
    .save();
};
