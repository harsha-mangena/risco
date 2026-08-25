import { getOrder } from "./gen/client";

export async function handle(id: string) {
  return getOrder(id);
}
