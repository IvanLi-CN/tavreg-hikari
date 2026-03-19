import { createServer } from "node:net";

export interface PortLease {
  port: number;
  releaseListener: () => Promise<void>;
  release: () => Promise<void>;
}

const RESERVED_LOCAL_PORTS = new Set<number>();

async function reserveLocalPortLease(): Promise<PortLease> {
  return await new Promise<PortLease>((resolve, reject) => {
    const server = createServer();
    const fail = (error: Error) => {
      server.close(() => {});
      reject(error);
    };

    server.once("error", fail);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      if (!port || port <= 0) {
        fail(new Error("failed to reserve local port"));
        return;
      }

      server.removeListener("error", fail);
      let listenerReleased = false;
      resolve({
        port,
        releaseListener: async () => {
          if (listenerReleased) return;
          listenerReleased = true;
          await new Promise<void>((resolveClose, rejectClose) => {
            server.close((error) => {
              if (error) {
                rejectClose(error);
                return;
              }
              resolveClose();
            });
          });
        },
        release: async () => {
          if (!listenerReleased) {
            await new Promise<void>((resolveClose, rejectClose) => {
              server.close((error) => {
                if (error) {
                  rejectClose(error);
                  return;
                }
                listenerReleased = true;
                resolveClose();
              });
            });
          }
        },
      });
    });
  });
}

export async function reserveUniqueLocalPortLease(): Promise<PortLease> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const lease = await reserveLocalPortLease();
    if (RESERVED_LOCAL_PORTS.has(lease.port)) {
      await lease.release().catch(() => {});
      continue;
    }

    RESERVED_LOCAL_PORTS.add(lease.port);
    let released = false;
    return {
      port: lease.port,
      releaseListener: async () => {
        await lease.releaseListener().catch(() => {});
      },
      release: async () => {
        if (released) return;
        released = true;
        RESERVED_LOCAL_PORTS.delete(lease.port);
        await lease.release().catch(() => {});
      },
    };
  }

  throw new Error("failed to reserve a unique local port");
}

export async function reserveMihomoPortLeases(): Promise<{ apiPort: PortLease; mixedPort: PortLease }> {
  const apiPort = await reserveUniqueLocalPortLease();
  let mixedPort = await reserveUniqueLocalPortLease();
  while (mixedPort.port === apiPort.port) {
    await mixedPort.release();
    mixedPort = await reserveUniqueLocalPortLease();
  }
  return { apiPort, mixedPort };
}

export function isPortLeaseReserved(port: number): boolean {
  return RESERVED_LOCAL_PORTS.has(port);
}
