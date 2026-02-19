export interface ProxyNode {
  name: string;
  type?: string;
}

export interface ProxyGroup {
  name: string;
  now?: string;
  all?: string[];
}

export interface ProxyController {
  apiBaseUrl: string;
  proxyServer: string;
  groupName: string;
  listGroupNodes(): Promise<ProxyNode[]>;
  getGroupSelection(): Promise<string | null>;
  setGroupProxy(name: string): Promise<void>;
  testDelay(name: string, url: string, timeoutMs: number): Promise<number | null>;
  stop(): Promise<void>;
}
