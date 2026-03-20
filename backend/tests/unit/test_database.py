import pytest
from unittest.mock import AsyncMock, patch

from app.models.database import init_db, get_db

@pytest.mark.asyncio
async def test_init_db():
    with patch("app.models.database.engine") as mock_engine:
        mock_conn = AsyncMock()
        mock_engine.begin.return_value.__aenter__.return_value = mock_conn
        
        await init_db()
        
        mock_conn.run_sync.assert_called_once()

@pytest.mark.asyncio
async def test_get_db_success():
    with patch("app.models.database.AsyncSessionLocal") as mock_session_local:
        mock_session = AsyncMock()
        mock_session_local.return_value.__aenter__.return_value = mock_session
        
        gen = get_db()
        
        # Step 1: get the yielded session
        session = await gen.__anext__()
        assert session is mock_session
        
        # Step 2: finish the generator
        try:
            await gen.__anext__()
        except StopAsyncIteration:
            pass
            
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()

@pytest.mark.asyncio
async def test_get_db_exception():
    with patch("app.models.database.AsyncSessionLocal") as mock_session_local:
        mock_session = AsyncMock()
        mock_session_local.return_value.__aenter__.return_value = mock_session
        
        gen = get_db()
        session = await gen.__anext__()
        
        with pytest.raises(ValueError):
            await gen.athrow(ValueError("Test error"))
            
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()
