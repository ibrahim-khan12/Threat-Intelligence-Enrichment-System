from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.realtime import event_manager

router = APIRouter(tags=["realtime"])


@router.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket):
    await event_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        event_manager.disconnect(websocket)
    except Exception:
        event_manager.disconnect(websocket)
