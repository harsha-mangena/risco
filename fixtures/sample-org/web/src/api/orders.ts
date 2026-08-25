const ORDERS_BASE = process.env.ORDERS_SERVICE_URL;

export async function loadOrder(id: string): Promise<unknown> {
  const res = await fetch(`${ORDERS_BASE}/v2/orders/${id}`, { method: "GET" });
  if (!res.ok) throw new Error(`orders ${res.status}`);
  return res.json();
}

export async function submitRefund(orderId: string, amount: number) {
  const res = await fetch(`${ORDERS_BASE}/v2/refunds`, {
    method: "POST",
    body: JSON.stringify({ order_id: orderId, amount }),
  });
  return res.json();
}
