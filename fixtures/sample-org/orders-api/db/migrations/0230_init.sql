CREATE TABLE IF NOT EXISTS orders (
  id text PRIMARY KEY,
  total numeric NOT NULL,
  created timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS refunds (
  id text PRIMARY KEY,
  order_id text REFERENCES orders(id),
  amount numeric NOT NULL,
  created timestamptz NOT NULL DEFAULT now()
);
