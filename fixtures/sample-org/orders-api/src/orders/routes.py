from fastapi import APIRouter

router = APIRouter()


@router.get("/v2/orders/{order_id}")
async def get_order(order_id: str):
    row = db_fetch_order(order_id)
    return {
        "id": row.id,
        "total": row.total,
        "fulfillment_eta": row.fulfillment_eta,
    }
