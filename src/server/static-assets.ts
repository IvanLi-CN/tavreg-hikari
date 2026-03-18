import path from "node:path";

export function resolveStaticAssetPath(webDistDir: string, requestPathname: string): string | null {
  const decodedPath = decodeURIComponent(requestPathname || "/");
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
