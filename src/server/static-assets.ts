import path from "node:path";

function decodeRequestPath(requestPathname: string): string | null {
  try {
    return decodeURIComponent(requestPathname || "/");
  } catch {
    return null;
  }
}

export function resolveStaticAssetPath(webDistDir: string, requestPathname: string): string | null {
  const decodedPath = decodeRequestPath(requestPathname);
  if (decodedPath == null) return null;
  const relativePath = decodedPath === "/" ? "index.html" : decodedPath.replace(/^\/+/, "");
  const normalizedPath = path.normalize(relativePath);

  if (!normalizedPath || normalizedPath === ".") {
    return path.join(webDistDir, "index.html");
  }

  if (normalizedPath.startsWith("..") || path.isAbsolute(normalizedPath)) {
    return null;
  }

  return path.join(webDistDir, normalizedPath);
}

export function shouldServeSpaFallback(requestPathname: string): boolean {
  const decodedPath = decodeRequestPath(requestPathname);
  if (!decodedPath) return false;

  if (decodedPath === "/" || decodedPath === "") return true;
  if (decodedPath === "/api" || decodedPath.startsWith("/api/")) return false;

  const trimmedPath = decodedPath.replace(/\/+$/, "");
  const lastSegment = trimmedPath.split("/").pop() || "";
  return !lastSegment.includes(".");
}
