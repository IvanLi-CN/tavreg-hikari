import { expect, test } from "bun:test";
import { connect } from "node:net";
import { isPortLeaseReserved, reserveMihomoPortLeases } from "../src/server/port-lease.ts";

function canConnect(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host: "127.0.0.1", port });
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

test("reserveMihomoPortLeases keeps ports bound until release", async () => {
  const leases = await reserveMihomoPortLeases();
  expect(leases.apiPort.port).not.toBe(leases.mixedPort.port);
  expect(isPortLeaseReserved(leases.apiPort.port)).toBe(true);
  expect(isPortLeaseReserved(leases.mixedPort.port)).toBe(true);
  expect(await canConnect(leases.apiPort.port)).toBe(true);
  expect(await canConnect(leases.mixedPort.port)).toBe(true);

  await leases.apiPort.releaseListener();
  await leases.mixedPort.releaseListener();

  expect(isPortLeaseReserved(leases.apiPort.port)).toBe(true);
  expect(isPortLeaseReserved(leases.mixedPort.port)).toBe(true);
  expect(await canConnect(leases.apiPort.port)).toBe(false);
  expect(await canConnect(leases.mixedPort.port)).toBe(false);

  await leases.apiPort.release();
  await leases.mixedPort.release();

  expect(isPortLeaseReserved(leases.apiPort.port)).toBe(false);
  expect(isPortLeaseReserved(leases.mixedPort.port)).toBe(false);
});
